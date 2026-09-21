package server

import (
	"encoding/json"
	"net/http"

	"gsignver/internal/cryptox"
	"gsignver/internal/store"
	"gsignver/internal/wire"
)

func bizError(code int, msg, nonce string, now int64) wire.BizResponse {
	return wire.BizResponse{Code: code, Message: msg, Nonce: nonce, TS: now}
}

// handleBiz 处理 /v1/biz。解密前的失败一律形态 B，解密后的失败走形态 A。
func (s *Server) handleBiz(w http.ResponseWriter, r *http.Request) {
	env, ok := s.readEnvelope(w, r)
	if !ok {
		return
	}
	if env.DeviceID == wire.DeviceAnonymous {
		writeBare(w, wire.Err(wire.CodeBadParam, "业务请求必须携带真实 device_id"))
		return
	}

	var keyBlob []byte
	var app *store.Application
	err := s.repo.View(func(t *store.Tx) error {
		a, ok, err := t.GetApp(env.AppID)
		if err != nil {
			return err
		}
		if !ok {
			return wire.Err(wire.CodeAppNotFound, "app_id 不存在")
		}
		app = a
		sk, blob, ok, err := t.GetSharedKey(env.AppID, env.DeviceID)
		if err != nil {
			return err
		}
		if !ok || sk.Status != store.StatusActive {
			return wire.Err(wire.CodeCrypto, "密钥不存在或已销毁")
		}
		keyBlob = blob
		return nil
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	key, err := s.kms.Open(keyBlob)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cipherBytes, err := wire.UnB64(env.Data)
	if err != nil {
		writeBare(w, wire.Err(wire.CodeCrypto, "data 不是合法标准 Base64"))
		return
	}
	plain, err := cryptox.AEADOpen(key, cipherBytes)
	if err != nil {
		writeBare(w, wire.Err(wire.CodeCrypto, "密文校验失败"))
		return
	}
	var req wire.BizRequest
	if err := json.Unmarshal(plain, &req); err != nil {
		writeBare(w, wire.Err(wire.CodeCrypto, "内层不是合法 JSON"))
		return
	}

	now := s.now().Unix()
	var resp wire.BizResponse
	err = s.repo.Update(func(t *store.Tx) error {
		claimed, err := t.ClaimNonce(env.AppID, req.Nonce, now, s.NonceTTL)
		if err != nil {
			return err
		}
		if !claimed {
			resp = bizError(wire.CodeNonceReplay, "nonce 重放", req.Nonce, now)
			return nil
		}
		if !withinWindow(req.TS, now, s.TSWindow) {
			resp = bizError(wire.CodeTimestampStale, "时间戳超出窗口", req.Nonce, now)
			return nil
		}
		dev, ok, err := t.GetDevice(env.DeviceID)
		if err != nil {
			return err
		}
		if !ok {
			resp = bizError(wire.CodeDeviceMismatch, "设备不存在", req.Nonce, now)
			return nil
		}
		if dev.Status != store.StatusActive {
			resp = bizError(wire.CodeDeviceRemoved, "设备已被移除", req.Nonce, now)
			return nil
		}
		lic, ok, err := t.GetLicense(req.LicenseID)
		if err != nil {
			return err
		}
		if !ok {
			resp = bizError(wire.CodeLicenseNotFound, "license 不存在", req.Nonce, now)
			return nil
		}
		if lic.DeviceID != env.DeviceID || lic.AppID != env.AppID {
			resp = bizError(wire.CodeDeviceMismatch, "设备不属于该 license", req.Nonce, now)
			return nil
		}
		if lic.Status == store.StatusRevoked {
			resp = bizError(wire.CodeLicenseRevoked, "许可证已被吊销", req.Nonce, now)
			return nil
		}
		if req.Action != wire.ActionRefresh && lic.ExpiresAt > 0 && now > lic.ExpiresAt {
			resp = bizError(wire.CodeLicenseExpired, "许可证已过期", req.Nonce, now)
			return nil
		}

		resp = wire.BizResponse{Code: wire.CodeOK, Message: "ok", Nonce: req.Nonce, TS: now}
		if err := s.dispatchBiz(t, app, dev, lic, &req, now, &resp); err != nil {
			return err
		}
		dev.LastSeenAt = now
		return t.PutDevice(dev)
	})
	if err != nil {
		s.writeErr(w, err)
		return
	}

	body, err := json.Marshal(resp)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cipherOut, err := cryptox.AEADSeal(key, body)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	dataStr := wire.B64(cipherOut)
	var sig string
	if err := s.repo.View(func(t *store.Tx) error {
		v, e := s.signData(t, env.AppID, dataStr)
		if e != nil {
			return e
		}
		sig = v
		return nil
	}); err != nil {
		s.writeErr(w, err)
		return
	}
	writeEnvelope(w, wire.Envelope{AppID: env.AppID, DeviceID: env.DeviceID, Data: dataStr, Sig: sig})
}

// dispatchBiz 执行具体业务动作。
func (s *Server) dispatchBiz(t *store.Tx, app *store.Application, dev *store.Device, lic *store.License, req *wire.BizRequest, now int64, resp *wire.BizResponse) error {
	switch req.Action {
	case wire.ActionListDevices:
		code, ok, err := t.GetCode(dev.ActivationCodeHash)
		if err != nil {
			return err
		}
		maxDev := app.MaxDevicesDefault
		if ok && code.MaxDevices > 0 {
			maxDev = code.MaxDevices
		}
		devices, err := t.ActiveDevicesOfCode(dev.ActivationCodeHash)
		if err != nil {
			return err
		}
		infos := make([]wire.DeviceInfo, 0, len(devices))
		for _, d := range devices {
			infos = append(infos, wire.DeviceInfo{
				DeviceID: d.DeviceID, DeviceDesc: d.DeviceDesc,
				RegisteredAt: d.RegisteredAt, LastSeenAt: d.LastSeenAt,
			})
		}
		resp.MaxDevices = maxDev
		resp.Devices = infos

	case wire.ActionRemoveDevice:
		target := req.TargetDeviceID
		if target == "" {
			*resp = bizError(wire.CodeBadParam, "缺少 target_device_id", req.Nonce, now)
			return nil
		}
		td, ok, err := t.GetDevice(target)
		if err != nil {
			return err
		}
		if !ok || td.ActivationCodeHash != dev.ActivationCodeHash {
			*resp = bizError(wire.CodeDeviceMismatch, "目标设备不属于该激活码", req.Nonce, now)
			return nil
		}
		if td.Status != store.StatusActive {
			resp.RemovedID = td.DeviceID
			return nil
		}
		if err := t.RetireDevice(td); err != nil {
			return err
		}
		resp.RemovedID = td.DeviceID

	case wire.ActionRefresh:
		code, ok, err := t.GetCode(dev.ActivationCodeHash)
		if err != nil {
			return err
		}
		if ok {
			lic.Edition = code.Edition
			lic.Features = code.Features
		}
		lic.ExpiresAt = now + app.LicenseTTLSeconds
		lic.Status = store.StatusActive
		if err := t.PutLicense(lic); err != nil {
			return err
		}
		resp.License = licenseToWire(lic)

	case wire.ActionFetchData:
		if req.Key == "" {
			*resp = bizError(wire.CodeBadParam, "缺少 key", req.Nonce, now)
			return nil
		}
		payload, ok := t.GetData(app.AppID, req.Key)
		if !ok {
			*resp = bizError(wire.CodeBadParam, "数据不存在", req.Nonce, now)
			return nil
		}
		resp.Payload = json.RawMessage(payload)

	default:
		*resp = bizError(wire.CodeBadParam, "未知 action", req.Nonce, now)
	}
	return nil
}
