// Package store 在 kv 之上实现领域仓储：应用、签名密钥、激活码、许可证、设备、共享密钥、
// nonce 去重与限流。所有写操作都必须经由 Repo.Update 的事务回调，以保证读-改-写原子。
package store

import (
	"encoding/json"
	"errors"
	"time"

	"gsignver/internal/kv"
)

// 记录状态常量。
const (
	StatusActive    = "active"
	StatusRevoked   = "revoked"
	StatusRemoved   = "removed"
	StatusDestroyed = "destroyed"
)

// Application 是应用配置。
type Application struct {
	AppID             string `json:"app_id"`
	Name              string `json:"name"`
	MaxDevicesDefault int    `json:"max_devices_default"`
	LicenseTTLSeconds int64  `json:"license_ttl_seconds"`
	CreatedAt         int64  `json:"created_at"`
}

// SigningKey 是应用签名密钥的公开元数据；私钥单独以封装形式存放。
type SigningKey struct {
	KeyID     string `json:"key_id"`
	AppID     string `json:"app_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

// ActivationCode 是激活码记录（只存摘要）。
type ActivationCode struct {
	CodeHash   string   `json:"code_hash"`
	AppID      string   `json:"app_id"`
	Edition    string   `json:"edition"`
	Features   []string `json:"features"`
	MaxDevices int      `json:"max_devices"`
	Status     string   `json:"status"`
	ExpiresAt  int64    `json:"expires_at"`
	CreatedAt  int64    `json:"created_at"`
}

// License 是每设备一张的许可证。
type License struct {
	LicenseID          string   `json:"license_id"`
	AppID              string   `json:"app_id"`
	ActivationCodeHash string   `json:"activation_code_hash"`
	Edition            string   `json:"edition"`
	Features           []string `json:"features"`
	DeviceID           string   `json:"device_id"`
	KeyID              string   `json:"key_id"`
	IssuedAt           int64    `json:"issued_at"`
	NotBefore          int64    `json:"not_before"`
	ExpiresAt          int64    `json:"expires_at"`
	Status             string   `json:"status"`
}

// Device 是一次注册产生的身份。
type Device struct {
	DeviceID           string `json:"device_id"`
	AppID              string `json:"app_id"`
	ActivationCodeHash string `json:"activation_code_hash"`
	LicenseID          string `json:"license_id"`
	DeviceEncPub       string `json:"device_enc_pub"`
	DeviceDesc         string `json:"device_desc"`
	RegisteredAt       int64  `json:"registered_at"`
	LastSeenAt         int64  `json:"last_seen_at"`
	Status             string `json:"status"`
}

// SharedKey 是某设备对称密钥的封装记录。
type SharedKey struct {
	AppID     string `json:"app_id"`
	DeviceID  string `json:"device_id"`
	CreatedAt int64  `json:"created_at"`
	Status    string `json:"status"`
}

// RateLimit 是限流桶。
type RateLimit struct {
	Failures    int   `json:"failures"`
	WindowStart int64 `json:"window_start"`
	LockedUntil int64 `json:"locked_until"`
}

// Repo 是仓储入口。
type Repo struct {
	db *kv.DB
}

// New 构造仓储。
func New(db *kv.DB) *Repo { return &Repo{db: db} }

// Close 关闭底层存储。
func (r *Repo) Close() error { return r.db.Close() }

// Update 在写事务内执行回调。
func (r *Repo) Update(fn func(*Tx) error) error {
	return r.db.Update(func(kt *kv.Tx) error { return fn(&Tx{kt: kt}) })
}

// View 在只读事务内执行回调。
func (r *Repo) View(fn func(*Tx) error) error {
	return r.db.View(func(kt *kv.Tx) error { return fn(&Tx{kt: kt}) })
}

// Tx 是一次事务内的仓储视图。
type Tx struct {
	kt *kv.Tx
}

func appKey(appID string) string                 { return "app:" + appID }
func signingKey(appID, keyID string) string      { return "sk:" + appID + ":" + keyID }
func activeKeyID(appID string) string            { return "ska:" + appID }
func codeKey(h string) string                    { return "code:" + h }
func deviceKey(id string) string                 { return "dev:" + id }
func licenseKey(id string) string                { return "lic:" + id }
func sharedKeyKey(appID, deviceID string) string { return "key:" + appID + ":" + deviceID }
func deviceToLicense(deviceID string) string     { return "idx:dev2lic:" + deviceID }
func codeToDevicePrefix(h string) string         { return "idx:code2dev:" + h + ":" }
func codeToDeviceKey(h, deviceID string) string  { return codeToDevicePrefix(h) + deviceID }
func nonceKey(appID, nonce string) string        { return "nonce:" + appID + ":" + nonce }
func rateLimitKey(bucket string) string          { return "rl:" + bucket }
func dataKey(appID, k string) string             { return "dat:" + appID + ":" + k }

func putJSON(t *kv.Tx, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	t.Put(key, b)
	return nil
}

func getJSON[T any](t *kv.Tx, key string) (*T, bool, error) {
	b, ok := t.Get(key)
	if !ok {
		return nil, false, nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, false, err
	}
	return &v, true, nil
}

// --- 应用 ---

func (t *Tx) GetApp(appID string) (*Application, bool, error) {
	return getJSON[Application](t.kt, appKey(appID))
}

func (t *Tx) PutApp(a *Application) error { return putJSON(t.kt, appKey(a.AppID), a) }

func (t *Tx) ListApps() ([]*Application, error) {
	out := []*Application{}
	for _, k := range t.kt.Scan("app:") {
		a, ok, err := getJSON[Application](t.kt, k)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// --- 签名密钥 ---

func (t *Tx) PutSigningKey(k *SigningKey, sealedPriv []byte, setActive bool) error {
	if err := putJSON(t.kt, signingKey(k.AppID, k.KeyID), k); err != nil {
		return err
	}
	t.kt.Put(signingKey(k.AppID, k.KeyID)+":priv", sealedPriv)
	if setActive {
		t.kt.Put(activeKeyID(k.AppID), []byte(k.KeyID))
	}
	return nil
}

// GetActiveSigningKey 返回当前 active 的应用签名密钥及其封装私钥。
func (t *Tx) GetActiveSigningKey(appID string) (*SigningKey, []byte, bool, error) {
	kid, ok := t.kt.Get(activeKeyID(appID))
	if !ok {
		return nil, nil, false, nil
	}
	k, ok, err := getJSON[SigningKey](t.kt, signingKey(appID, string(kid)))
	if err != nil || !ok {
		return nil, nil, false, err
	}
	priv, ok := t.kt.Get(signingKey(appID, k.KeyID) + ":priv")
	if !ok {
		return nil, nil, false, errors.New("store: active signing key has no sealed private key")
	}
	return k, priv, true, nil
}

// --- 激活码 ---

func (t *Tx) GetCode(codeHash string) (*ActivationCode, bool, error) {
	return getJSON[ActivationCode](t.kt, codeKey(codeHash))
}

func (t *Tx) PutCode(c *ActivationCode) error { return putJSON(t.kt, codeKey(c.CodeHash), c) }

// --- 设备 ---

func (t *Tx) GetDevice(deviceID string) (*Device, bool, error) {
	return getJSON[Device](t.kt, deviceKey(deviceID))
}

// CountAllDevices 返回库中全部设备记录数（含 removed），用于测试与巡检。
func (t *Tx) CountAllDevices() int { return t.kt.Count("dev:") }

// LinkDeviceToCode 维护「激活码 -> 设备」次级索引。
func (t *Tx) LinkDeviceToCode(codeHash, deviceID string) {
	t.kt.Put(codeToDeviceKey(codeHash, deviceID), []byte{})
}

func (t *Tx) PutDevice(d *Device) error { return putJSON(t.kt, deviceKey(d.DeviceID), d) }

// ActiveDevicesOfCode 返回某激活码下全部 active 设备，按 registered_at 升序。
func (t *Tx) ActiveDevicesOfCode(codeHash string) ([]*Device, error) {
	keys := t.kt.Scan(codeToDevicePrefix(codeHash))
	out := make([]*Device, 0, len(keys))
	for _, k := range keys {
		id := k[len(codeToDevicePrefix(codeHash)):]
		d, ok, err := t.GetDevice(id)
		if err != nil {
			return nil, err
		}
		if ok && d.Status == StatusActive {
			out = append(out, d)
		}
	}
	// 稳定排序：registered_at 升序，同刻按 device_id 升序。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.RegisteredAt > b.RegisteredAt || (a.RegisteredAt == b.RegisteredAt && a.DeviceID > b.DeviceID) {
				out[j-1], out[j] = out[j], out[j-1]
				continue
			}
			break
		}
	}
	return out, nil
}

// CountActiveDevices 返回某激活码下 active 设备数。
func (t *Tx) CountActiveDevices(codeHash string) (int, error) {
	ds, err := t.ActiveDevicesOfCode(codeHash)
	if err != nil {
		return 0, err
	}
	return len(ds), nil
}

// EarliestActiveDevice 返回某激活码下最早注册的 active 设备。
func (t *Tx) EarliestActiveDevice(codeHash string) (*Device, bool, error) {
	ds, err := t.ActiveDevicesOfCode(codeHash)
	if err != nil {
		return nil, false, err
	}
	if len(ds) == 0 {
		return nil, false, nil
	}
	return ds[0], true, nil
}

// --- 许可证 ---

func (t *Tx) GetLicense(licenseID string) (*License, bool, error) {
	return getJSON[License](t.kt, licenseKey(licenseID))
}

func (t *Tx) PutLicense(l *License) error {
	if err := putJSON(t.kt, licenseKey(l.LicenseID), l); err != nil {
		return err
	}
	t.kt.Put(deviceToLicense(l.DeviceID), []byte(l.LicenseID))
	return nil
}

// LicenseOfDevice 按 device_id 取许可证。
func (t *Tx) LicenseOfDevice(deviceID string) (*License, bool, error) {
	id, ok := t.kt.Get(deviceToLicense(deviceID))
	if !ok {
		return nil, false, nil
	}
	return t.GetLicense(string(id))
}

// --- 共享密钥 ---

func (t *Tx) PutSharedKey(k *SharedKey, sealed []byte) error {
	if err := putJSON(t.kt, sharedKeyKey(k.AppID, k.DeviceID), k); err != nil {
		return err
	}
	t.kt.Put(sharedKeyKey(k.AppID, k.DeviceID)+":blob", sealed)
	return nil
}

// GetSharedKey 返回共享密钥元数据与封装后的密钥材料。
func (t *Tx) GetSharedKey(appID, deviceID string) (*SharedKey, []byte, bool, error) {
	k, ok, err := getJSON[SharedKey](t.kt, sharedKeyKey(appID, deviceID))
	if err != nil || !ok {
		return nil, nil, false, err
	}
	blob, ok := t.kt.Get(sharedKeyKey(appID, deviceID) + ":blob")
	if !ok {
		return nil, nil, false, nil
	}
	return k, blob, true, nil
}

// DestroySharedKey 标记销毁并清除密文。
func (t *Tx) DestroySharedKey(appID, deviceID string) error {
	k, _, ok, err := t.GetSharedKey(appID, deviceID)
	if err != nil || !ok {
		return err
	}
	k.Status = StatusDestroyed
	if err := putJSON(t.kt, sharedKeyKey(appID, deviceID), k); err != nil {
		return err
	}
	t.kt.Delete(sharedKeyKey(appID, deviceID) + ":blob")
	return nil
}

// --- 设备下线（remove_device 与紧急踢出共用） ---

// RetireDevice 把一个设备下线：设备置 removed、许可证置 revoked、对称密钥销毁。
func (t *Tx) RetireDevice(d *Device) error {
	d.Status = StatusRemoved
	if err := t.PutDevice(d); err != nil {
		return err
	}
	lic, ok, err := t.GetLicense(d.LicenseID)
	if err != nil {
		return err
	}
	if ok {
		lic.Status = StatusRevoked
		if err := t.PutLicense(lic); err != nil {
			return err
		}
	}
	return t.DestroySharedKey(d.AppID, d.DeviceID)
}

// --- nonce ---

// ClaimNonce 尝试认领 nonce；已被认领且未过期时返回 false。
func (t *Tx) ClaimNonce(appID, nonce string, now int64, ttl time.Duration) (bool, error) {
	k := nonceKey(appID, nonce)
	if b, ok := t.kt.Get(k); ok {
		var exp int64
		if err := json.Unmarshal(b, &exp); err == nil && exp > now {
			return false, nil
		}
	}
	b, err := json.Marshal(now + int64(ttl/time.Second))
	if err != nil {
		return false, err
	}
	t.kt.Put(k, b)
	return true, nil
}

// PruneNonces 清理已过期 nonce。
func (t *Tx) PruneNonces(now int64) error {
	for _, k := range t.kt.Scan("nonce:") {
		b, ok := t.kt.Get(k)
		if !ok {
			continue
		}
		var exp int64
		if err := json.Unmarshal(b, &exp); err != nil || exp <= now {
			t.kt.Delete(k)
		}
	}
	return nil
}

// --- 限流 ---

func (t *Tx) GetRateLimit(bucket string) (*RateLimit, bool, error) {
	return getJSON[RateLimit](t.kt, rateLimitKey(bucket))
}

func (t *Tx) PutRateLimit(bucket string, rl *RateLimit) error {
	return putJSON(t.kt, rateLimitKey(bucket), rl)
}

func (t *Tx) DeleteRateLimit(bucket string) { t.kt.Delete(rateLimitKey(bucket)) }

// --- 业务数据（fetch_data 用） ---

func (t *Tx) PutData(appID, key string, payload []byte) error {
	t.kt.Put(dataKey(appID, key), payload)
	return nil
}

func (t *Tx) GetData(appID, key string) ([]byte, bool) {
	return t.kt.Get(dataKey(appID, key))
}

// PruneExpired 清理过期 nonce（供定时任务调用）。
func (r *Repo) PruneExpired(now int64) error {
	return r.Update(func(t *Tx) error { return t.PruneNonces(now) })
}
