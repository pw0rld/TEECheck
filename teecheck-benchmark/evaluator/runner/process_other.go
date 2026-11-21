//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import (
	"os"
	"os/exec"
)

// CommandContext retains its platform-default cancellation outside Unix.
// WaitDelay still bounds pipes; process-tree containment is not claimed here.
func configureScannerProcess(cmd *exec.Cmd) {}

func cleanupScannerProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}
