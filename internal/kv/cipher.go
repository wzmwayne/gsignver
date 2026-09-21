package kv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// aesGCMCipher 是基于 AES-256-GCM 的 Cipher 实现，密文格式为 nonce(12) + ciphertext + tag(16)。
type aesGCMCipher struct{ aead cipher.AEAD }

// NewAESGCMCipher 由 16/24/32 字节密钥构造 Cipher。
func NewAESGCMCipher(key []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aesGCMCipher{aead: aead}, nil
}

func (c *aesGCMCipher) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plain, nil), nil
}

func (c *aesGCMCipher) Decrypt(blob []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(blob) < ns+c.aead.Overhead() {
		return nil, errors.New("kv: 密文长度不足")
	}
	return c.aead.Open(nil, blob[:ns], blob[ns:], nil)
}
