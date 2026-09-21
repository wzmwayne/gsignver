// Package wire 定义信封、状态码与各方共用的载荷结构。
package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// DeviceAnonymous 是未注册请求在 device_id 字段使用的保留字面量。
const DeviceAnonymous = "anonymous"

// 动作名。
const (
	ActionActivate         = "activate"
	ActionEmergencyKickout = "emergency_kickout"
	ActionListDevices      = "list_devices"
	ActionRemoveDevice     = "remove_device"
	ActionRefresh          = "refresh"
	ActionFetchData        = "fetch_data"
)

// Envelope 是 SPEC 3.1 规定的外层信封。
type Envelope struct {
	AppID    string `json:"app_id"`
	DeviceID string `json:"device_id"`
	Data     string `json:"data"`
	Sig      string `json:"sig,omitempty"`
}

// 状态码。
const (
	CodeOK              = 0
	CodeBadParam        = 1001
	CodeBadSig          = 1002
	CodeTimestampStale  = 1003
	CodeNonceReplay     = 1004
	CodeAppNotFound     = 1006
	CodeBodyTooLarge    = 1007
	CodeCrypto          = 1010
	CodeActivationBad   = 2001
	CodeActivationUsed  = 2002
	CodeDeviceLimit     = 2003
	CodeProductMismatch = 2004
	CodeDeviceRemoved   = 2005
	CodeDeviceMismatch  = 2006
	CodeDeviceOverLimit = 2007
	CodeNoDeviceToKick  = 2009
	CodeLicenseExpired  = 3001
	CodeLicenseRevoked  = 3002
	CodeLicenseNotFound = 3003
	CodeRateLimited     = 429
	CodeInternal        = 5000
)

// Error 是带状态码的业务错误。
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%d: %s", e.Code, e.Message) }

// Err 构造一个业务错误。
func Err(code int, msg string) *Error { return &Error{Code: code, Message: msg} }

// Errf 构造一个带格式化消息的业务错误。
func Errf(code int, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// HTTPStatus 把业务码映射为 HTTP 状态码。
func HTTPStatus(code int) int {
	switch code {
	case CodeRateLimited:
		return 429
	case CodeInternal:
		return 500
	default:
		return 400
	}
}

// AsError 把任意 error 归一为 *Error。
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Err(CodeInternal, err.Error())
}

// B64 是标准 Base64（含等号填充），用于 data 与各类二进制字段。
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// UnB64 严格解码标准 Base64。
func UnB64(s string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(s)
}

// B64URL 是 Base64URL 无填充，用于 sig 与 nonce。
func B64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64URL 严格解码 Base64URL 无填充。
func UnB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// SignData 对 data 字符串的 UTF-8 字节签名，返回 Base64URL 无填充。
func SignData(priv ed25519.PrivateKey, data string) string {
	return B64URL(ed25519.Sign(priv, []byte(data)))
}

// VerifyData 校验 data 字符串上的签名。
func VerifyData(pub ed25519.PublicKey, data, sig string) bool {
	b, err := UnB64URL(sig)
	if err != nil || len(b) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(data), b)
}

// NormalizeCode 按 SPEC 2.5 归一化明文激活码。
func NormalizeCode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

// License 是下发给客户端的许可证。
type License struct {
	LicenseID string   `json:"license_id"`
	AppID     string   `json:"app_id"`
	Edition   string   `json:"edition"`
	Features  []string `json:"features"`
	DeviceID  string   `json:"device_id"`
	NotBefore int64    `json:"not_before"`
	ExpiresAt int64    `json:"expires_at"`
}

// ActivateRequest 是 /v1/activate 的明文载荷。
type ActivateRequest struct {
	Action         string `json:"action"`
	ActivationCode string `json:"activation_code"`
	DeviceDesc     string `json:"device_desc"`
	DeviceEncPub   string `json:"device_enc_pub"`
	Nonce          string `json:"nonce"`
	TS             int64  `json:"ts"`
}

// ActivateResponse 是 /v1/activate 成功响应的明文载荷。
type ActivateResponse struct {
	Code     int      `json:"code"`
	Message  string   `json:"message"`
	Nonce    string   `json:"nonce"`
	TS       int64    `json:"ts"`
	DeviceID string   `json:"device_id"`
	EncKey   string   `json:"enc_key"`
	License  *License `json:"license"`
}

// EmergencyKickoutRequest 是 /v1/emergency/kickout 的明文载荷。
type EmergencyKickoutRequest struct {
	Action         string `json:"action"`
	ActivationCode string `json:"activation_code"`
	Nonce          string `json:"nonce"`
	TS             int64  `json:"ts"`
}

// KickoutResponse 是 /v1/emergency/kickout 的明文响应载荷。
type KickoutResponse struct {
	Code           int    `json:"code"`
	Message        string `json:"message"`
	Nonce          string `json:"nonce"`
	TS             int64  `json:"ts"`
	KickedDeviceID string `json:"kicked_device_id,omitempty"`
}

// BizRequest 是 /v1/biz 的内层请求载荷（整体经 K 加密）。
type BizRequest struct {
	Action         string `json:"action"`
	LicenseID      string `json:"license_id"`
	Nonce          string `json:"nonce"`
	TS             int64  `json:"ts"`
	TargetDeviceID string `json:"target_device_id,omitempty"`
	Key            string `json:"key,omitempty"`
}

// DeviceInfo 是设备列表条目。
type DeviceInfo struct {
	DeviceID     string `json:"device_id"`
	DeviceDesc   string `json:"device_desc"`
	RegisteredAt int64  `json:"registered_at"`
	LastSeenAt   int64  `json:"last_seen_at"`
}

// BizResponse 是 /v1/biz 的内层响应载荷（整体经 K 加密）。
type BizResponse struct {
	Code       int          `json:"code"`
	Message    string       `json:"message"`
	Nonce      string       `json:"nonce,omitempty"`
	TS         int64        `json:"ts"`
	MaxDevices int          `json:"max_devices,omitempty"`
	Devices    []DeviceInfo `json:"devices,omitempty"`
	RemovedID  string       `json:"removed_device_id,omitempty"`
	License    *License     `json:"license,omitempty"`
	Payload    any          `json:"payload,omitempty"`
}

// BareError 是形态 B（裸错误）的响应体。
type BareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
