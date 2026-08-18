//go:build unix

package executor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// configureProcessCancellation makes context cancellation terminate the
// command and every descendant in its process group. Killing only a shell can
// leave a child holding stdout/stderr pipes open, which makes Cmd.Wait block
// until that child exits even though the timeout already fired.
func configureProcessCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 250 * time.Millisecond
}
