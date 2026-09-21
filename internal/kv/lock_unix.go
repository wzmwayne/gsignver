//go:build unix

package kv

import (
	"os"
	"syscall"
)

// lockFile 取得排他非阻塞文件锁，失败说明已有其它进程占用数据目录。
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
