package server

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"net/http"

	"gsignver/internal/cryptox"
	"gsignver/internal/store"
	"gsignver/internal/ulid"
	"gsignver/internal/wire"
)

const (
	maxDeviceDescLen     = 4096
	maxDeviceDescDecoded = 2048
	maxDeviceIDAttempts  = 8
)

// shouldCountAsFailure 决定哪些错误计入限流桶。
func shouldCountAsFailure(code int) bool {
	switch code {
	case wire.CodeBadParam, wire.CodeTimestampStale, wire.CodeNonceReplay,
		wire.CodeActivationBad, wire.CodeAppNotFound:
		return true
	}
	return false
}

func (s *Server) fail(w http.ResponseWriter, e *wire.Error, buckets ...string) {
	if shouldCountAsFailure(e.Code) {
		for _, b := range buckets {
			_ = s.recordFailure([]string{b})
		}
	}
	writeBare(w, e)
}

func (s *Server) newDeviceID(t *store.Tx) (string, error) {
	for i := 0; i < maxDeviceIDAttempts; i++ {
		id := "srv_" + ulid.New()
		_, ok, err := t.GetDevice(id)
		if err != nil {
			return "", err
		}
		if !ok {
			return id, nil
		}
	}
	return "", errors.New("server: 无法分配唯一 device_id")
}

func validateDeviceDesc(s string) error {
	if s == "" {
		return wire.Err(wire.CodeBadParam, "device_desc 不能为空")
	}
	if len(s) > maxDeviceDescLen {
		return wire.Err(wire.CodeBadParam, "device_desc 超过 4096 字符")
	}
	raw, err := wire.UnB64(s)
	if err != nil {
		return wire.Err(wire.CodeBadParam, "device_desc 不是合法标准 Base64")
	}
	if len(raw) > maxDeviceDescDecoded {
		return wire.Err(wire.CodeBadParam, "device_desc 解码后超过 2048 字节")
	}
	return nil
}

func licenseToWire(l *store.License) *wire.License {
	return &wire.License{
		LicenseID: l.LicenseID,
		AppID:     l.AppID,
		Edition:   l.Edition,
		Features:  l.Features,
		DeviceID:  l.DeviceID,
		NotBefore: l.NotBefore,
		ExpiresAt: l.ExpiresAt,
	}
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	env, ok := s.readEnvelope(w, r)
	if !ok {
		return
	}
	if env.DeviceID != wire.DeviceAnonymous {
		writeBare(w, wire.Err(wire.CodeBadParam, "未注册请求的 device_id 必须是 anonymous"))
		return
	}
	ipBuckets := []string{"ip:" + clientIP(r), "app:" + env.AppID}
	if !s.gate(w, ipBuckets) {
		return
	}

	raw, err := wire.UnB64(env.Data)
	if err != nil {
		s.fail(w, wire.Err(wire.CodeBadParam, "data 不是合法标准 Base64"), ipBuckets...)
		return
	}
	var req wire.ActivateRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		s.fail(w, wire.Err(wire.CodeBadParam, "data 不是合法 JSON"), ipBuckets...)
		return
	}
	if req.Action != wire.ActionActivate {
		s.fail(w, wire.Err(wire.CodeBadParam, "action 必须是 activate"), ipBuckets...)
		return
	}
	if req.ActivationCode == "" || req.DeviceEncPub == "" || req.Nonce == "" {
		s.fail(w, wire.Err(wire.CodeBadParam, "缺少 activation_code/device_enc_pub/nonce"), ipBuckets...)
		return
	}
	now := s.now().Unix()
	if !withinWindow(req.TS, now, s.TSWindow) {
		s.fail(w, wire.Err(wire.CodeTimestampStale, "时间戳超出窗口"), ipBuckets...)
		return
	}
	if err := validateDeviceDesc(req.DeviceDesc); err != nil {
		s.fail(w, wire.AsError(err), ipBuckets...)
		return
	}
	encPub, err := wire.UnB64(req.DeviceEncPub)
	if err != nil || len(encPub) != 32 {
		s.fail(w, wire.Err(wire.CodeBadParam, "device_enc_pub 必须是 32 字节标准 Base64"), ipBuckets...)
		return
	}
	if _, err := ecdh.X25519().NewPublicKey(encPub); err != nil {
		s.fail(w, wire.Err(wire.CodeBadParam, "device_enc_pub 不是合法 X25519 公钥"), ipBuckets...)
		return
	}

	codeHash := s.kms.CodeHash(env.AppID, req.ActivationCode)
	codeBuckets := []string{"code:" + codeHash}
	if !s.gate(w, codeBuckets) {
		return
	}

	var out wire.Envelope
	err = s.repo.Update(func(t *store.Tx) error {
		app, ok, err := t.GetApp(env.AppID)
		if err != nil {
			return err
		}
		if !ok {
			return wire.Err(wire.CodeAppNotFound, "app_id 不存在")
		}
		code, ok, err := t.GetCode(codeHash)
		if err != nil {
			return err
		}
		if !ok || code.Status != store.StatusActive || code.AppID != env.AppID {
			return wire.Err(wire.CodeActivationBad, "激活码无效")
		}
		if code.ExpiresAt > 0 && now > code.ExpiresAt {
			return wire.Err(wire.CodeActivationBad, "激活码无效")
		}
		claimed, err := t.ClaimNonce(env.AppID, req.Nonce, now, s.NonceTTL)
		if err != nil {
			return err
		}
		if !claimed {
			return wire.Err(wire.CodeNonceReplay, "nonce 重放")
		}

		maxDev := code.MaxDevices
		if maxDev <= 0 {
			maxDev = app.MaxDevicesDefault
		}
		cnt, err := t.CountActiveDevices(codeHash)
		if err != nil {
			return err
		}
		if cnt > maxDev {
			return wire.Err(wire.CodeDeviceOverLimit, "设备数异常超过上限")
		}
		if cnt >= maxDev {
			return wire.Err(wire.CodeDeviceLimit, "设备数已达上限，请调用紧急踢出接口")
		}

		sk, _, ok, err := t.GetActiveSigningKey(env.AppID)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("服务端未配置应用签名密钥")
		}

		deviceID, err := s.newDeviceID(t)
		if err != nil {
			return err
		}
		key, err := cryptox.Random(cryptox.KeyLen)
		if err != nil {
			return err
		}
		encKeyBlob, err := cryptox.Seal(encPub, key)
		if err != nil {
			return err
		}
		storedKeyBlob, err := s.kms.Seal(key)
		if err != nil {
			return err
		}

		lic := &store.License{
			LicenseID:          "lic_" + ulid.New(),
			AppID:              env.AppID,
			ActivationCodeHash: codeHash,
			Edition:            code.Edition,
			Features:           code.Features,
			DeviceID:           deviceID,
			KeyID:              sk.KeyID,
			IssuedAt:           now,
			NotBefore:          now,
			ExpiresAt:          now + app.LicenseTTLSeconds,
			Status:             store.StatusActive,
		}
		if err := t.PutLicense(lic); err != nil {
			return err
		}
		dev := &store.Device{
			DeviceID:           deviceID,
			AppID:              env.AppID,
			ActivationCodeHash: codeHash,
			LicenseID:          lic.LicenseID,
			DeviceEncPub:       req.DeviceEncPub,
			DeviceDesc:         req.DeviceDesc,
			RegisteredAt:       now,
			LastSeenAt:         now,
			Status:             store.StatusActive,
		}
		if err := t.PutDevice(dev); err != nil {
			return err
		}
		t.LinkDeviceToCode(codeHash, deviceID)
		if err := t.PutSharedKey(&store.SharedKey{
			AppID: env.AppID, DeviceID: deviceID, CreatedAt: now, Status: store.StatusActive,
		}, storedKeyBlob); err != nil {
			return err
		}

		body, err := json.Marshal(wire.ActivateResponse{
			Code: wire.CodeOK, Message: "ok", Nonce: req.Nonce, TS: now,
			DeviceID: deviceID, EncKey: wire.B64(encKeyBlob), License: licenseToWire(lic),
		})
		if err != nil {
			return err
		}
		dataStr := wire.B64(body)
		sig, err := s.signData(t, env.AppID, dataStr)
		if err != nil {
			return err
		}
		out = wire.Envelope{AppID: env.AppID, DeviceID: deviceID, Data: dataStr, Sig: sig}
		return nil
	})
	if err != nil {
		s.fail(w, wire.AsError(err), append(ipBuckets, codeBuckets...)...)
		return
	}
	s.clearFailures(ipBuckets)
	s.clearFailures(codeBuckets)
	writeEnvelope(w, out)
}
