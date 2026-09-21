package kv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func put(t *testing.T, db *DB, k, v string) {
	t.Helper()
	if err := db.Update(func(tx *Tx) error { tx.Put(k, []byte(v)); return nil }); err != nil {
		t.Fatalf("put %s: %v", k, err)
	}
}

func mustGet(t *testing.T, db *DB, k, want string) {
	t.Helper()
	got, ok := db.Get(k)
	if !ok || string(got) != want {
		t.Fatalf("Get(%s) = %q,%v want %q", k, got, ok, want)
	}
}

// record 以明文标记构造一条合法日志记录。
func record(op byte, key string, val []byte) []byte {
	stored := append([]byte{markerPlain}, encodeBody(op, key, val)...)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(stored)))
	out = append(out, stored...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(stored))
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	put(t, db, "a", "1")
	put(t, db, "b", "2")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	mustGet(t, db2, "a", "1")
	mustGet(t, db2, "b", "2")
}

func TestTruncatedTailIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var log []byte
	log = append(log, record(opPut, "k1", []byte("v1"))...)
	log = append(log, record(opPut, "k2", []byte("v2"))...)
	// 模拟崩溃：尾部半条记录
	log = append(log, 0, 0, 0, 50, 1, 2, 3)
	logPath := filepath.Join(dir, "kv.log")
	if err := os.WriteFile(logPath, log, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(logPath)

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	defer db.Close()
	mustGet(t, db, "k1", "v1")
	mustGet(t, db, "k2", "v2")
	after, _ := os.Stat(logPath)
	if after.Size() >= before.Size() {
		t.Fatalf("尾部残记录未被截断: before=%d after=%d", before.Size(), after.Size())
	}
}

func TestCompactionKeepsAllKeys(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.SetCompactThreshold(256)
	for i := 0; i < 100; i++ {
		put(t, db, fmt.Sprintf("key%03d", i), fmt.Sprintf("val%03d", i))
	}
	if _, err := os.Stat(filepath.Join(dir, "kv.snapshot")); err != nil {
		t.Fatalf("未生成快照: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	for i := 0; i < 100; i++ {
		mustGet(t, db2, fmt.Sprintf("key%03d", i), fmt.Sprintf("val%03d", i))
	}
}

func TestTransactionRollback(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	put(t, db, "keep", "yes")
	sentinel := fmt.Errorf("boom")
	if err := db.Update(func(tx *Tx) error {
		tx.Put("drop", []byte("no"))
		return sentinel
	}); err != sentinel {
		t.Fatalf("got %v want sentinel", err)
	}
	if _, ok := db.Get("drop"); ok {
		t.Fatal("回滚的写入泄漏了")
	}
	mustGet(t, db, "keep", "yes")
}

func TestExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Open(dir); err == nil {
		t.Fatal("第二个实例不应能打开同一数据目录")
	}
}

func TestScanPrefixAndDelete(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, k := range []string{"idx:a:1", "idx:a:2", "idx:b:1"} {
		put(t, db, k, "x")
	}
	if err := db.Update(func(tx *Tx) error { tx.Delete("idx:a:1"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *Tx) error {
		got := tx.Scan("idx:a:")
		if len(got) != 1 || got[0] != "idx:a:2" {
			t.Fatalf("Scan = %v", got)
		}
		if tx.Count("idx:") != 2 {
			t.Fatalf("Count = %d want 2", tx.Count("idx:"))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func testCipher(t *testing.T) Cipher {
	t.Helper()
	c, err := NewAESGCMCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	c := testCipher(t)
	db, err := Open(dir, WithCipher(c))
	if err != nil {
		t.Fatal(err)
	}
	if !db.HasCipher() {
		t.Fatal("HasCipher 应为 true")
	}
	put(t, db, "secret", "TOP-SECRET-VALUE")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// 落盘内容不得出现明文
	for _, name := range []string{"kv.log", "kv.snapshot"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte("TOP-SECRET-VALUE")) {
			t.Fatalf("%s 中出现明文", name)
		}
	}

	// 带正确 cipher 可读回
	db2, err := Open(dir, WithCipher(testCipher(t)))
	if err != nil {
		t.Fatal(err)
	}
	mustGet(t, db2, "secret", "TOP-SECRET-VALUE")
	db2.Close()

	// 不带 cipher 打开应报错
	if _, err := Open(dir); err == nil {
		t.Fatal("未提供 Cipher 时应拒绝打开加密数据")
	}

	// 错误密钥应报错
	bad, err := NewAESGCMCipher(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, WithCipher(bad)); err == nil {
		t.Fatal("错误密钥不应能打开")
	}
}
