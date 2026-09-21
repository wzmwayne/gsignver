// Package client 是协议的参考客户端实现，同时充当虚拟验证客户端。
package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"gsignver/internal/cryptox"
	"gsignver/internal/wire"
)

// 客户端本地错误。
var (
	ErrBadResponseSig = errors.New("client: 响应签名校验失败")
	ErrNonceMismatch  = errors.New("client: 响应 nonce 与请求不一致")
	ErrNotActivated   = errors.New("client: 尚未激活")
)

// Client 是持有本地设备状态的协议客户端。
type Client struct {
	BaseURL string
	AppID   string
	AppPub  ed25519.PublicKey
	HTTP    *http.Client
	Now     func() time.Time

	DeviceID  string
	Key       []byte
	License   *wire.License
	DeviceEnc *ecdh.PrivateKey
}

// New 构造客户端。
func New(baseURL, appID string, appPub ed25519.PublicKey) *Client {
	return &Client{
		BaseURL: baseURL,
		AppID:   appID,
		AppPub:  appPub,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
		Now:     time.Now,
	}
}

// AppPubFromB64 解码内置应用公钥。
func AppPubFromB64(s string) (ed25519.PublicKey, error) {
	raw, err := wire.UnB64(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("client: 公钥长度 %d，期望 %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func (c *Client) newNonce() (string, error) {
	b, err := cryptox.Random(16)
	if err != nil {
		return "", err
	}
	return wire.B64URL(b), nil
}

func (c *Client) post(path string, env wire.Envelope) (int, []byte, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, out, nil
}

// verify 校验形态 A 响应并返回 data 字符串。
func (c *Client) verify(status int, body []byte) (string, error) {
	if status != http.StatusOK {
		var be wire.BareError
		if err := json.Unmarshal(body, &be); err == nil && be.Code != 0 {
			return "", wire.Err(be.Code, be.Message)
		}
		return "", fmt.Errorf("client: 服务端返回 HTTP %d", status)
	}
	var env wire.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return "", err
	}
	if env.AppID != c.AppID {
		return "", fmt.Errorf("client: 响应 app_id = %q，期望 %q", env.AppID, c.AppID)
	}
	if !wire.VerifyData(c.AppPub, env.Data, env.Sig) {
		return "", ErrBadResponseSig
	}
	return env.Data, nil
}

// Activate 走完激活流程，成功后在本地保存 device_id 与 K。
func (c *Client) Activate(activationCode, deviceDescRaw string) (*wire.ActivateResponse, error) {
	priv, err := cryptox.X25519Generate()
	if err != nil {
		return nil, err
	}
	c.DeviceEnc = priv
	nonce, err := c.newNonce()
	if err != nil {
		return nil, err
	}
	desc := wire.B64([]byte(deviceDescRaw))
	req := wire.ActivateRequest{
		Action:         wire.ActionActivate,
		ActivationCode: activationCode,
		DeviceDesc:     desc,
		DeviceEncPub:   wire.B64(priv.PublicKey().Bytes()),
		Nonce:          nonce,
		TS:             c.Now().Unix(),
	}
	inner, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	status, body, err := c.post("/v1/activate", wire.Envelope{
		AppID: c.AppID, DeviceID: wire.DeviceAnonymous, Data: wire.B64(inner),
	})
	if err != nil {
		return nil, err
	}
	dataStr, err := c.verify(status, body)
	if err != nil {
		return nil, err
	}
	raw, err := wire.UnB64(dataStr)
	if err != nil {
		return nil, err
	}
	var resp wire.ActivateResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if resp.Nonce != nonce {
		return nil, ErrNonceMismatch
	}
	if resp.Code != wire.CodeOK {
		return nil, wire.Err(resp.Code, resp.Message)
	}
	encKey, err := wire.UnB64(resp.EncKey)
	if err != nil {
		return nil, err
	}
	key, err := cryptox.Unseal(priv, encKey)
	if err != nil {
		return nil, fmt.Errorf("client: 解封 K 失败: %w", err)
	}
	if resp.License == nil || resp.License.DeviceID != resp.DeviceID {
		return nil, errors.New("client: license.device_id 与下发的 device_id 不一致")
	}
	c.DeviceID = resp.DeviceID
	c.Key = key
	c.License = resp.License
	return &resp, nil
}

// Biz 发送一个业务请求并解出响应。
func (c *Client) Biz(req wire.BizRequest) (*wire.BizResponse, error) {
	if c.Key == nil || c.DeviceID == "" {
		return nil, ErrNotActivated
	}
	nonce, err := c.newNonce()
	if err != nil {
		return nil, err
	}
	req.Nonce = nonce
	req.TS = c.Now().Unix()
	if req.LicenseID == "" && c.License != nil {
		req.LicenseID = c.License.LicenseID
	}
	inner, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ct, err := cryptox.AEADSeal(c.Key, inner)
	if err != nil {
		return nil, err
	}
	status, body, err := c.post("/v1/biz", wire.Envelope{
		AppID: c.AppID, DeviceID: c.DeviceID, Data: wire.B64(ct),
	})
	if err != nil {
		return nil, err
	}
	dataStr, err := c.verify(status, body)
	if err != nil {
		return nil, err
	}
	sealed, err := wire.UnB64(dataStr)
	if err != nil {
		return nil, err
	}
	plain, err := cryptox.AEADOpen(c.Key, sealed)
	if err != nil {
		return nil, fmt.Errorf("client: 解密业务响应失败: %w", err)
	}
	var resp wire.BizResponse
	if err := json.Unmarshal(plain, &resp); err != nil {
		return nil, err
	}
	if resp.Nonce != nonce {
		return nil, ErrNonceMismatch
	}
	return &resp, nil
}

// Kickout 调用紧急踢出接口（未激活状态即可使用）。
func (c *Client) Kickout(activationCode string) (*wire.KickoutResponse, error) {
	nonce, err := c.newNonce()
	if err != nil {
		return nil, err
	}
	inner, err := json.Marshal(wire.EmergencyKickoutRequest{
		Action: wire.ActionEmergencyKickout, ActivationCode: activationCode,
		Nonce: nonce, TS: c.Now().Unix(),
	})
	if err != nil {
		return nil, err
	}
	status, body, err := c.post("/v1/emergency/kickout", wire.Envelope{
		AppID: c.AppID, DeviceID: wire.DeviceAnonymous, Data: wire.B64(inner),
	})
	if err != nil {
		return nil, err
	}
	dataStr, err := c.verify(status, body)
	if err != nil {
		return nil, err
	}
	raw, err := wire.UnB64(dataStr)
	if err != nil {
		return nil, err
	}
	var resp wire.KickoutResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if resp.Nonce != nonce {
		return nil, ErrNonceMismatch
	}
	if resp.Code != wire.CodeOK {
		return nil, wire.Err(resp.Code, resp.Message)
	}
	return &resp, nil
}
