package server

import (
	"encoding/json"
	"net/http"

	"gsignver/internal/store"
	"gsignver/internal/wire"
)

// handleKickout 处理 /v1/emergency/kickout：未激活客户端凭激活码踢出最早注册的设备。
func (s *Server) handleKickout(w http.ResponseWriter, r *http.Request) {
	env, ok := s.readEnvelope(w, r)
	if !ok {
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
	var req wire.EmergencyKickoutRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		s.fail(w, wire.Err(wire.CodeBadParam, "data 不是合法 JSON"), ipBuckets...)
		return
	}
	if req.Action != wire.ActionEmergencyKickout {
		s.fail(w, wire.Err(wire.CodeBadParam, "action 必须是 emergency_kickout"), ipBuckets...)
		return
	}
	if req.ActivationCode == "" || req.Nonce == "" {
		s.fail(w, wire.Err(wire.CodeBadParam, "缺少 activation_code/nonce"), ipBuckets...)
		return
	}
	now := s.now().Unix()
	if !withinWindow(req.TS, now, s.TSWindow) {
		s.fail(w, wire.Err(wire.CodeTimestampStale, "时间戳超出窗口"), ipBuckets...)
		return
	}
	codeHash := s.kms.CodeHash(env.AppID, req.ActivationCode)
	codeBuckets := []string{"code:" + codeHash}
	if !s.gate(w, codeBuckets) {
		return
	}

	var out wire.Envelope
	err = s.repo.Update(func(t *store.Tx) error {
		if _, ok, err := t.GetApp(env.AppID); err != nil {
			return err
		} else if !ok {
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
		victim, ok, err := t.EarliestActiveDevice(codeHash)
		if err != nil {
			return err
		}
		if !ok {
			return wire.Err(wire.CodeNoDeviceToKick, "没有可踢出的设备")
		}
		if err := t.RetireDevice(victim); err != nil {
			return err
		}
		body, err := json.Marshal(wire.KickoutResponse{
			Code: wire.CodeOK, Message: "ok", Nonce: req.Nonce, TS: now,
			KickedDeviceID: victim.DeviceID,
		})
		if err != nil {
			return err
		}
		dataStr := wire.B64(body)
		sig, err := s.signData(t, env.AppID, dataStr)
		if err != nil {
			return err
		}
		out = wire.Envelope{AppID: env.AppID, DeviceID: env.DeviceID, Data: dataStr, Sig: sig}
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
