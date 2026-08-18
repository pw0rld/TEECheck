//go:build !unix

package executor

import (
	"os/exec"
	"time"
)

func configureProcessCancellation(cmd *exec.Cmd) {
	cmd.WaitDelay = 250 * time.Millisecond
}
