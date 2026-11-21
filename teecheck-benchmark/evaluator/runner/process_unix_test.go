//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestScannerProcessHelper(t *testing.T) {
	if os.Getenv("TEECHECK_PROCESS_GROUP_HELPER") != "1" {
		return
	}
	args := os.Args
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	if i+2 >= len(args) {
		os.Exit(2)
	}
	role, dir := args[i+1], args[i+2]
	if role == "spawn" {
		child := exec.Command(os.Args[0], "-test.run=^TestScannerProcessHelper$", "--", "child", dir)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		_ = child.Wait()
		os.Exit(0)
	}
	if role != "child" {
		os.Exit(4)
	}
	pgid, err := syscall.Getpgid(0)
	if err != nil {
		os.Exit(5)
	}
	body, _ := json.Marshal(map[string]int{"pid": os.Getpid(), "pgid": pgid})
	if err := os.WriteFile(filepath.Join(dir, "child.json"), body, 0600); err != nil {
		os.Exit(6)
	}
	for {
		f, err := os.OpenFile(filepath.Join(dir, "heartbeat"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(7)
		}
		_, _ = f.WriteString("x")
		_ = f.Close()
		fmt.Fprintln(os.Stdout, "child alive") // Holds an inherited stdout pipe.
		time.Sleep(15 * time.Millisecond)
	}
}

func childRecord(t *testing.T, dir string) map[string]int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(filepath.Join(dir, "child.json"))
		if err == nil {
			var record map[string]int
			if json.Unmarshal(body, &record) == nil {
				return record
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scanner helper child did not start")
	return nil
}

func assertHeartbeatStopped(t *testing.T, dir string) {
	t.Helper()
	first, err := os.ReadFile(filepath.Join(dir, "heartbeat"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	second, err := os.ReadFile(filepath.Join(dir, "heartbeat"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatal("descendant continues running after scanner cancellation")
	}
}

func TestScannerCancellationKillsGroupAndInheritedPipes(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestScannerProcessHelper$", "--", "spawn", dir)
	cmd.Env = append(os.Environ(), "TEECHECK_PROCESS_GROUP_HELPER=1")
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	configureScannerProcess(cmd)
	cmd.WaitDelay = 500 * time.Millisecond
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cleanupScannerProcess(cmd)
	child := childRecord(t, dir)
	defer syscall.Kill(child["pid"], syscall.SIGKILL)
	if child["pgid"] != cmd.Process.Pid {
		t.Fatalf("child pgid=%d want %d", child["pgid"], cmd.Process.Pid)
	}
	start := time.Now()
	cancel()
	err := cmd.Wait()
	if err == nil {
		t.Fatal("cancelled scanner unexpectedly succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("cancellation did not close inherited pipes promptly: %v", time.Since(start))
	}
	assertHeartbeatStopped(t, dir)
	if err := cleanupScannerProcess(&exec.Cmd{}); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("unstarted cleanup: %v", err)
	}
}

func TestRunScannerAttemptTimeoutKillsDescendants(t *testing.T) {
	dir := t.TempDir()
	output := t.TempDir()
	t.Setenv("TEECHECK_PROCESS_GROUP_HELPER", "1")
	command := shellQuote(os.Args[0]) + " -test.run='^TestScannerProcessHelper$' -- spawn " + shellQuote(dir)
	c := loadedCase{Dir: t.TempDir()}
	c.Case.ID = "process-timeout"
	if err := runScannerAttempt(c, "fixed", output, command, time.Second); err != nil {
		t.Fatal(err)
	}
	child := childRecord(t, dir)
	defer syscall.Kill(child["pid"], syscall.SIGKILL)
	assertHeartbeatStopped(t, dir)
	var latest latestAttempt
	if err := readJSON(filepath.Join(output, "latest.json"), &latest); err != nil {
		t.Fatal(err)
	}
	var record attemptRecord
	if err := readJSON(filepath.Join(output, "attempts", latest.AttemptID, "attempt.json"), &record); err != nil {
		t.Fatal(err)
	}
	if record.Status != "timeout" {
		t.Fatalf("attempt status=%s want timeout", record.Status)
	}
}
