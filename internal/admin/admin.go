// Package admin 提供服务端运维操作：创建应用、签发激活码、列出应用。
package admin

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gsignver/internal/cryptox"
	"gsignver/internal/kms"
	"gsignver/internal/store"
	"gsignver/internal/ulid"
)

// codeAlphabetLen 是明文激活码的字符数（5 组，每组 5 字符，共 25 个 Crockford 字符 ≈ 123 位熵）。
const codeGroups = 5
const codeGroupLen = 5

// CreateApp 创建或更新应用，并确保存在一把 active 的应用签名密钥。
// 返回内置到客户端使用的应用公钥（标准 Base64）。
func CreateApp(repo *store.Repo, k *kms.KMS, appID, name string, maxDevices int, ttlSeconds int64) (string, error) {
	if appID == "" {
		return "", errors.New("admin: app_id 不能为空")
	}
	if maxDevices <= 0 {
		maxDevices = 1
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 30 * 24 * 3600
	}
	now := time.Now().Unix()
	pubB64 := ""
	err := repo.Update(func(t *store.Tx) error {
		app := &store.Application{
			AppID: appID, Name: name,
			MaxDevicesDefault: maxDevices, LicenseTTLSeconds: ttlSeconds, CreatedAt: now,
		}
		if old, ok, err := t.GetApp(appID); err != nil {
			return err
		} else if ok {
			app.CreatedAt = old.CreatedAt
		}
		if sk, _, ok, err := t.GetActiveSigningKey(appID); err != nil {
			return err
		} else if ok {
			// 已存在 active 密钥：不轮换（SPEC B8），仅更新应用元数据。
			pubB64 = sk.PublicKey
			return t.PutApp(app)
		}
		pub, priv, err := cryptox.Ed25519Generate()
		if err != nil {
			return err
		}
		sealed, err := k.Seal(priv.Seed())
		if err != nil {
			return err
		}
		keyID := "ed25519-" + time.Unix(now, 0).UTC().Format("20060102")
		sk := &store.SigningKey{
			KeyID: keyID, AppID: appID, Algorithm: "Ed25519",
			PublicKey: kms.PublicKeyB64(pub), Status: store.StatusActive, CreatedAt: now,
		}
		if err := t.PutSigningKey(sk, sealed, true); err != nil {
			return err
		}
		pubB64 = sk.PublicKey
		return t.PutApp(app)
	})
	return pubB64, err
}

// IssueCode 签发一枚激活码，返回仅此一次可见的明文码。
func IssueCode(repo *store.Repo, k *kms.KMS, appID, edition string, features []string, maxDevices int, codeTTLSeconds int64) (string, error) {
	if appID == "" {
		return "", errors.New("admin: app_id 不能为空")
	}
	plain, err := GenerateCode()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	var expires int64
	if codeTTLSeconds > 0 {
		expires = now + codeTTLSeconds
	}
	code := &store.ActivationCode{
		CodeHash:   k.CodeHash(appID, plain),
		AppID:      appID,
		Edition:    edition,
		Features:   features,
		MaxDevices: maxDevices,
		Status:     store.StatusActive,
		ExpiresAt:  expires,
		CreatedAt:  now,
	}
	err = repo.Update(func(t *store.Tx) error {
		if _, ok, err := t.GetApp(appID); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("admin: app_id %s 不存在", appID)
		}
		return t.PutCode(code)
	})
	if err != nil {
		return "", err
	}
	return plain, nil
}

// ListApps 列出所有应用及其 active 应用公钥。
func ListApps(repo *store.Repo) ([]string, error) {
	var out []string
	err := repo.View(func(t *store.Tx) error {
		apps, err := t.ListApps()
		if err != nil {
			return err
		}
		for _, a := range apps {
			sk, _, ok, err := t.GetActiveSigningKey(a.AppID)
			if err != nil {
				return err
			}
			pub := "(无签名密钥)"
			if ok {
				pub = sk.PublicKey
			}
			out = append(out, fmt.Sprintf("%s\t%s\tmax_devices=%d\tttl=%ds\tpub=%s",
				a.AppID, a.Name, a.MaxDevicesDefault, a.LicenseTTLSeconds, pub))
		}
		return nil
	})
	return out, err
}

// GenerateCode 生成形如 XXXXX-XXXXX-XXXXX-XXXXX-XXXXX 的明文激活码。
func GenerateCode() (string, error) {
	raw, err := cryptox.Random(16)
	if err != nil {
		return "", err
	}
	var b [16]byte
	copy(b[:], raw)
	body := ulid.Encode(b)
	need := codeGroups * codeGroupLen
	if len(body) < need {
		return "", errors.New("admin: 随机源长度不足")
	}
	body = body[:need]
	groups := make([]string, 0, codeGroups)
	for i := 0; i < need; i += codeGroupLen {
		groups = append(groups, body[i:i+codeGroupLen])
	}
	return strings.Join(groups, "-"), nil
}
