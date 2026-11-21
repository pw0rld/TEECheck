//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package codedb

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheLockChild(t *testing.T) {
	path := os.Getenv("TEECHECK_TEST_LOCK_PATH")
	if path == "" {
		return
	}
	unlock, err := lockCache(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err = os.WriteFile(path+".ready", []byte("locked"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The parent deliberately kills this process to verify OS lock release.
	for {
		time.Sleep(time.Hour)
	}
}

func TestSharedCacheLockCoordinatesProcessesAndReleasesOnDeath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry.lock")
	child := exec.Command(os.Args[0], "-test.run=^TestCacheLockChild$")
	child.Env = append(os.Environ(), "TEECHECK_TEST_LOCK_PATH="+path)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(path + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not acquire lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if _, err := lockCache(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		cancel()
		t.Fatalf("second process obtained busy lock: %v", err)
	}
	cancel()
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := lockCache(ctx, path)
	if err != nil {
		t.Fatalf("dead process retained lock: %v", err)
	}
	unlock()
}
