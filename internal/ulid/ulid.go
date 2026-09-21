// Package ulid 生成按字典序单调递增的 26 字符 Crockford Base32 标识。
package ulid

import (
	"crypto/rand"
	"time"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New 返回 26 字符的 ULID（48 位毫秒时间戳 + 80 位随机数）。
func New() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	return Encode(b)
}

// Encode 把 16 字节编码为 26 字符（130 位视图，最高 2 位恒为 0）。
func Encode(b [16]byte) string {
	out := make([]byte, 26)
	bitPos := -2
	for i := 0; i < 26; i++ {
		v := 0
		for j := 0; j < 5; j++ {
			v <<= 1
			if bitPos >= 0 {
				idx := bitPos / 8
				if idx < 16 {
					shift := uint(7 - bitPos%8)
					if (b[idx]>>shift)&1 == 1 {
						v |= 1
					}
				}
			}
			bitPos++
		}
		out[i] = alphabet[v]
	}
	return string(out)
}
