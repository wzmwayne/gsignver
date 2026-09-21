// Package cryptox 提供信封无关的密码学原语。
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	KEMInfo = "gsignver/kem/v1"
	KeyLen  = 32
	IVLen   = 12
	TagLen  = 16
	// SealedLen = eph_pub(32) + iv(12) + ct(32) + tag(16)
	SealedLen = 32 + IVLen + KeyLen + TagLen
)

var ErrSealedFormat = errors.New("cryptox: sealed blob format invalid")

// Random 返回 n 字节密码学随机数。
func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// X25519Generate 生成 X25519 密钥对。
func X25519Generate() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// X25519FromBytes 由 32 字节私钥构造。
func X25519FromBytes(b []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b)
}

// Seal 按 SPEC 2.4 封装 msg32。
func Seal(recipientPub, msg []byte) ([]byte, error) {
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	kek, err := hkdf.Key(sha256.New, shared, nil, KEMInfo, KeyLen)
	if err != nil {
		return nil, err
	}
	body, err := AEADSeal(kek, msg)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, SealedLen)
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, body...)
	return out, nil
}

// Unseal 按 SPEC 2.4 解封装。
func Unseal(recipientPriv *ecdh.PrivateKey, blob []byte) ([]byte, error) {
	if len(blob) != SealedLen {
		return nil, ErrSealedFormat
	}
	curve := ecdh.X25519()
	ephPub, err := curve.NewPublicKey(blob[:32])
	if err != nil {
		return nil, err
	}
	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	kek, err := hkdf.Key(sha256.New, shared, nil, KEMInfo, KeyLen)
	if err != nil {
		return nil, err
	}
	return AEADOpen(kek, blob[32:])
}

// AEADSeal 输出 IV(12) + ciphertext + tag(16)。
func AEADSeal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	iv, err := Random(IVLen)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, IVLen+len(plaintext)+TagLen)
	out = append(out, iv...)
	return gcm.Seal(out, iv, plaintext, nil), nil
}

// AEADOpen 接受 IV(12) + ciphertext + tag(16)。
func AEADOpen(key, blob []byte) ([]byte, error) {
	if len(blob) < IVLen+TagLen {
		return nil, ErrSealedFormat
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, blob[:IVLen], blob[IVLen:], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Ed25519Generate 生成应用签名密钥对。
func Ed25519Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Ed25519FromSeed 由 32 字节种子恢复私钥。
func Ed25519FromSeed(seed []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(seed)
}
