// Package kv 是纯 Go 实现的嵌入式键值存储：内存索引 + 追加日志 + 快照压缩。
// 单进程独占（排他文件锁）；所有读写经由一把互斥锁串行化，因此 Update 回调内的读-改-写天然原子。
// 落盘数据可通过 Cipher 接口做可插拔的静态加密。
package kv

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	opPut    byte = 1
	opDelete byte = 2
)

// 落盘载荷的明文/密文标记，使同一份文件在开启或关闭加密时都能自描述。
const (
	markerPlain byte = 0
	markerEnc   byte = 1
)

// DefaultCompactThreshold 是触发日志压缩的日志字节数阈值。
const DefaultCompactThreshold = 4 << 20

var (
	// ErrClosed 表示库已关闭。
	ErrClosed = errors.New("kv: closed")
	// ErrEncryptedNeedsCipher 表示文件是加密的，但打开时未提供 Cipher。
	ErrEncryptedNeedsCipher = errors.New("kv: 数据已加密，打开时必须提供相同的 Cipher")
)

// Cipher 是可插拔的静态加密后端。实现者可换成任何 AEAD 或外置 KMS 包装。
type Cipher interface {
	Encrypt(plain []byte) ([]byte, error)
	Decrypt(blob []byte) ([]byte, error)
}

// Option 配置 DB。
type Option func(*DB)

// WithCipher 启用落盘加密。
func WithCipher(c Cipher) Option { return func(db *DB) { db.cipher = c } }

// WithCompactThreshold 设置日志压缩阈值。
func WithCompactThreshold(n int64) Option {
	return func(db *DB) {
		if n > 0 {
			db.threshold = n
		}
	}
}

// DB 是一个嵌入式键值库。
type DB struct {
	mu        sync.Mutex
	dir       string
	snapPath  string
	logPath   string
	data      map[string][]byte
	log       *os.File
	lock      *os.File
	cipher    Cipher
	logSize   int64
	threshold int64
	closed    bool
}

// Open 打开（必要时创建）dir 下的键值库。
func Open(dir string, opts ...Option) (*DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db := &DB{
		dir:       dir,
		snapPath:  filepath.Join(dir, "kv.snapshot"),
		logPath:   filepath.Join(dir, "kv.log"),
		data:      make(map[string][]byte),
		threshold: DefaultCompactThreshold,
	}
	for _, o := range opts {
		o(db)
	}
	if err := db.loadSnapshot(); err != nil {
		return nil, err
	}
	if err := db.replayLog(); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, "kv.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(lf); err != nil {
		lf.Close()
		return nil, fmt.Errorf("kv: 数据目录 %s 已被其它进程占用（服务端运行期间请改用管理接口 /admin/v1/* 签发激活码；多实例请各自使用独立 data-dir）: %w", dir, err)
	}
	db.lock = lf

	f, err := os.OpenFile(db.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		lf.Close()
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		lf.Close()
		return nil, err
	}
	db.log = f
	db.logSize = st.Size()
	return db, nil
}

// SetCompactThreshold 设置日志压缩阈值（仅供测试与调优）。
func (db *DB) SetCompactThreshold(n int64) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if n > 0 {
		db.threshold = n
	}
}

// HasCipher 报告落盘是否启用加密。
func (db *DB) HasCipher() bool { return db.cipher != nil }

// Close 落盘并关闭。
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return nil
	}
	db.closed = true
	err := db.compactLocked()
	if cerr := db.log.Close(); err == nil {
		err = cerr
	}
	if db.lock != nil {
		db.lock.Close()
		db.lock = nil
	}
	return err
}

// sealPayload 落盘前加密（或无 cipher 时仅加明文标记）。
func (db *DB) sealPayload(plain []byte) ([]byte, error) {
	if db.cipher == nil {
		out := make([]byte, 0, len(plain)+1)
		out = append(out, markerPlain)
		return append(out, plain...), nil
	}
	ct, err := db.cipher.Encrypt(plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(ct)+1)
	out = append(out, markerEnc)
	return append(out, ct...), nil
}

// openPayload 读盘后解密。为兼容未加标记的旧文件，首字节不是标记时按明文整体处理。
func (db *DB) openPayload(stored []byte) ([]byte, error) {
	if len(stored) == 0 {
		return nil, errors.New("kv: 空载荷")
	}
	switch stored[0] {
	case markerPlain:
		return stored[1:], nil
	case markerEnc:
		if db.cipher == nil {
			return nil, ErrEncryptedNeedsCipher
		}
		return db.cipher.Decrypt(stored[1:])
	default:
		return stored, nil
	}
}

func (db *DB) loadSnapshot() error {
	b, err := os.ReadFile(db.snapPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	plain, err := db.openPayload(b)
	if err != nil {
		return fmt.Errorf("kv: 读取快照失败: %w", err)
	}
	m := make(map[string][]byte)
	if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&m); err != nil {
		return err
	}
	db.data = m
	return nil
}

// replayLog 重放追加日志，遇到截断或校验和不符的尾部记录即停止并截断文件。
func (db *DB) replayLog() error {
	b, err := os.ReadFile(db.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	off := 0
	for {
		if off+4 > len(b) {
			break
		}
		n := int(binary.BigEndian.Uint32(b[off:]))
		if n < 1 || off+4+n+4 > len(b) {
			break
		}
		stored := b[off+4 : off+4+n]
		want := binary.BigEndian.Uint32(b[off+4+n:])
		if crc32.ChecksumIEEE(stored) != want {
			break
		}
		body, err := db.openPayload(stored)
		if err != nil {
			return fmt.Errorf("kv: 重放日志失败，请确认打开时提供了相同的 Cipher: %w", err)
		}
		ok, err := applyBody(body, db.data)
		if err != nil {
			break
		}
		if !ok {
			break
		}
		off += 4 + n + 4
	}
	if off < len(b) {
		if err := os.Truncate(db.logPath, int64(off)); err != nil {
			return err
		}
	}
	return nil
}

// applyBody 解析一条记录体并应用到内存。返回 false 表示记录体非法。
func applyBody(body []byte, data map[string][]byte) (bool, error) {
	if len(body) < 9 {
		return false, nil
	}
	op := body[0]
	kl := int(binary.BigEndian.Uint32(body[1:]))
	vl := int(binary.BigEndian.Uint32(body[5:]))
	if 9+kl+vl != len(body) {
		return false, nil
	}
	key := string(body[9 : 9+kl])
	switch op {
	case opPut:
		val := make([]byte, vl)
		copy(val, body[9+kl:])
		data[key] = val
	case opDelete:
		delete(data, key)
	default:
		return false, nil
	}
	return true, nil
}

func encodeBody(op byte, key string, val []byte) []byte {
	body := make([]byte, 0, 9+len(key)+len(val))
	body = append(body, op)
	body = binary.BigEndian.AppendUint32(body, uint32(len(key)))
	body = binary.BigEndian.AppendUint32(body, uint32(len(val)))
	body = append(body, key...)
	body = append(body, val...)
	return body
}

func (db *DB) encodeRecord(op byte, key string, val []byte) ([]byte, error) {
	stored, err := db.sealPayload(encodeBody(op, key, val))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(stored)+4)
	out = binary.BigEndian.AppendUint32(out, uint32(len(stored)))
	out = append(out, stored...)
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(stored))
	return out, nil
}

func (db *DB) compactLocked() error {
	var raw bytes.Buffer
	if err := gob.NewEncoder(&raw).Encode(db.data); err != nil {
		return err
	}
	stored, err := db.sealPayload(raw.Bytes())
	if err != nil {
		return err
	}
	tmp := db.snapPath + ".tmp"
	if err := os.WriteFile(tmp, stored, 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0o600)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if err := os.Rename(tmp, db.snapPath); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := db.log.Truncate(0); err != nil {
		return err
	}
	if _, err := db.log.Seek(0, 0); err != nil {
		return err
	}
	db.logSize = 0
	syncDir(db.dir)
	return nil
}

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	d.Sync()
	d.Close()
}

// Get 读取一个键。
func (db *DB) Get(key string) ([]byte, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	v, ok := db.data[key]
	return v, ok
}

// View 在一致性视图内执行只读回调。
func (db *DB) View(fn func(tx *Tx) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return ErrClosed
	}
	return fn(&Tx{db: db, puts: map[string][]byte{}, dels: map[string]struct{}{}})
}

// Update 在一致性视图内执行读写回调；回调返回 nil 才把写集落盘。
func (db *DB) Update(fn func(tx *Tx) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return ErrClosed
	}
	tx := &Tx{db: db, puts: map[string][]byte{}, dels: map[string]struct{}{}}
	if err := fn(tx); err != nil {
		return err
	}
	if len(tx.puts) == 0 && len(tx.dels) == 0 {
		return nil
	}

	var buf []byte
	for _, k := range sortedKeys(tx.dels) {
		rec, err := db.encodeRecord(opDelete, k, nil)
		if err != nil {
			return err
		}
		buf = append(buf, rec...)
	}
	for _, k := range sortedKeys(tx.puts) {
		rec, err := db.encodeRecord(opPut, k, tx.puts[k])
		if err != nil {
			return err
		}
		buf = append(buf, rec...)
	}

	if _, err := db.log.Write(buf); err != nil {
		return err
	}
	if err := db.log.Sync(); err != nil {
		return err
	}
	db.logSize += int64(len(buf))

	for k := range tx.dels {
		delete(db.data, k)
	}
	for k, v := range tx.puts {
		db.data[k] = v
	}

	if db.logSize > db.threshold {
		if err := db.compactLocked(); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Tx 是一次事务内的键值视图。
type Tx struct {
	db   *DB
	puts map[string][]byte
	dels map[string]struct{}
}

// Get 读取键（含本事务内尚未提交的写）。
func (tx *Tx) Get(key string) ([]byte, bool) {
	if _, del := tx.dels[key]; del {
		return nil, false
	}
	if v, ok := tx.puts[key]; ok {
		return v, true
	}
	v, ok := tx.db.data[key]
	return v, ok
}

// Has 判断键是否存在。
func (tx *Tx) Has(key string) bool {
	_, ok := tx.Get(key)
	return ok
}

// Put 写入键值。
func (tx *Tx) Put(key string, val []byte) {
	delete(tx.dels, key)
	tx.puts[key] = val
}

// Delete 删除键。
func (tx *Tx) Delete(key string) {
	delete(tx.puts, key)
	tx.dels[key] = struct{}{}
}

// Scan 返回前缀匹配的全部键，按字典序排序。
func (tx *Tx) Scan(prefix string) []string {
	set := make(map[string]struct{})
	for k := range tx.db.data {
		if strings.HasPrefix(k, prefix) {
			if _, del := tx.dels[k]; del {
				continue
			}
			set[k] = struct{}{}
		}
	}
	for k := range tx.puts {
		if strings.HasPrefix(k, prefix) {
			set[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Count 返回前缀匹配的键数量。
func (tx *Tx) Count(prefix string) int { return len(tx.Scan(prefix)) }
