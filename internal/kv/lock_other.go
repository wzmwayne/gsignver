//go:build !unix

package kv

import "os"

// lockFile 在非 unix 平台上退化为空操作。
func lockFile(f *os.File) error { return nil }
