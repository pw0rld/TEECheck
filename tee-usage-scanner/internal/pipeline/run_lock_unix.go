//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Kernel locks disappear after a crash, unlike persistent lock directories.
func lockRunDirectory(runDir string, _ bool) (func(), error) {
	f, err := os.OpenFile(filepath.Join(runDir, ".active.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("run directory is already in use: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
