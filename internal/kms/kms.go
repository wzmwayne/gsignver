// Package kms 是自建密钥管理：master key 与 pepper 由文件或环境变量持有，
// 库中一切私密材料（K、应用签名私钥）都以 master key 的 AES-256-GCM 封装后存放；
// 同时为其它模块派生独立的子密钥（如 KV 的落盘加密密钥）。
package kms

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gsignver/internal/cryptox"
	"gsignver/internal/wire"
)

const (
	masterKeyFile = "master.key"
	pepperFile    = "pepper.key"

	// EnvMasterKey 允许从环境注入 master key（hex / 标准 Base64 / Base64URL，32 字节）。
	// 生产部署应使用它，使数据文件与其解密密钥分开存放。
	EnvMasterKey = "GSIGNVER_MASTER_KEY"
	// EnvPepper 允许从环境注入激活码 pepper（32 字节，格式同上）。
	EnvPepper = "GSIGNVER_PEPPER"
)

// KMS 持有 master key 与 pepper。
type KMS struct {
	master []byte
	pepper []byte
}

// Open 加载或首次生成 dir 下的 master key 与 pepper。
func Open(dir string) (*KMS, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	master, err := loadOrCreateEnv(filepath.Join(dir, masterKeyFile), EnvMasterKey)
	if err != nil {
		return nil, err
	}
	pepper, err := loadOrCreateEnv(filepath.Join(dir, pepperFile), EnvPepper)
	if err != nil {
		return nil, err
	}
	return &KMS{master: master, pepper: pepper}, nil
}

func loadOrCreateEnv(path, env string) ([]byte, error) {
	if v := os.Getenv(env); v != "" {
		k, err := decodeKey(v)
		if err != nil {
			return nil, fmt.Errorf("kms: 环境变量 %s 非法: %w", env, err)
		}
		return k, nil
	}
	return loadOrCreate(path)
}

func decodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == cryptox.KeyLen {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == cryptox.KeyLen {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == cryptox.KeyLen {
		return b, nil
	}
	return nil, fmt.Errorf("需要 %d 字节的 hex 或 Base64", cryptox.KeyLen)
}

func loadOrCreate(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != cryptox.KeyLen {
			return nil, fmt.Errorf("kms: %s 长度为 %d，期望 %d", path, len(b), cryptox.KeyLen)
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := cryptox.Random(cryptox.KeyLen)
	if err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}

// MasterKey 返回 master key 的副本。
func (k *KMS) MasterKey() []byte {
	out := make([]byte, len(k.master))
	copy(out, k.master)
	return out
}

// DeriveKey 用 HKDF-SHA256 从 master key 派生子密钥，info 用于隔离用途。
func (k *KMS) DeriveKey(info string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, k.master, nil, info, n)
}

// Seal 用 master key 封装私密材料。
func (k *KMS) Seal(plain []byte) ([]byte, error) {
	return cryptox.AEADSeal(k.master, plain)
}

// Open 解开由 Seal 封装的材料。
func (k *KMS) Open(blob []byte) ([]byte, error) {
	return cryptox.AEADOpen(k.master, blob)
}

// CodeHash 按 SPEC 2.5 计算激活码摘要：
// hex(HMAC_SHA256(pepper, app_id + ":" + 归一化码))。
// pepper 的用途是让数据库泄露时无法离线穷举激活码，因此必须参与运算。
func (k *KMS) CodeHash(appID, code string) string {
	mac := hmac.New(sha256.New, k.pepper)
	mac.Write([]byte(appID))
	mac.Write([]byte(":"))
	mac.Write([]byte(wire.NormalizeCode(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

// PublicKeyB64 是应用公钥对外使用的标准 Base64 形式。
func PublicKeyB64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
