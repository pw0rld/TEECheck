package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/runbundle"
)

type attemptRecord struct {
	Schema     string            `json:"schema"`
	AttemptID  string            `json:"attempt_id"`
	CaseID     string            `json:"case_id"`
	Variant    string            `json:"variant"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at,omitempty"`
	Status     string            `json:"status"`
	ExitCode   int               `json:"exit_code"`
	Error      string            `json:"error,omitempty"`
	BundlePath string            `json:"bundle_path,omitempty"`
	Validation *runbundle.Report `json:"validation,omitempty"`
}

type latestAttempt struct {
	AttemptID string `json:"attempt_id"`
}

// Every invocation owns a new directory. Publish its pointer before starting
// the command, so a crash cannot cause the scorer to reuse an earlier result.
func runScannerAttempt(c loadedCase, variant, variantDir, template string, timeout time.Duration) error {
	parent := filepath.Join(variantDir, "attempts")
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(parent, "attempt-")
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	record := attemptRecord{Schema: "teecheck.benchmark.attempt.v1", AttemptID: filepath.Base(dir), CaseID: c.Case.ID, Variant: variant, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "running", ExitCode: -1}
	if err := writeJSONAtomic(filepath.Join(dir, "attempt.json"), record); err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(variantDir, "latest.json"), latestAttempt{record.AttemptID}); err != nil {
		return err
	}
	input, err := filepath.Abs(filepath.Join(c.Dir, variant))
	if err != nil {
		return err
	}
	values := commandValues(c, variant, input, dir)
	values["attempt_id"] = record.AttemptID
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, "sh", "-c", expandCommand(template, values))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	fmt.Printf("RUN %s/%s attempt=%s\n", c.Case.ID, variant, record.AttemptID)
	runErr := cmd.Run()
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	cancel()
	record.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if cmd.ProcessState != nil {
		record.ExitCode = cmd.ProcessState.ExitCode()
	}
	switch {
	case timedOut:
		record.Status = "timeout"
		record.Error = "scanner timeout"
	case runErr != nil:
		record.Status = "failed"
		record.Error = runErr.Error()
	default:
		record.Status = "completed"
		root, findErr := findRunBundle(dir)
		if findErr != nil {
			record.Status = "invalid"
			record.Error = findErr.Error()
			break
		}
		record.BundlePath, _ = filepath.Rel(dir, root)
		validation := runbundle.Validate(root)
		record.Validation = &validation
		if !validation.Valid {
			record.Status = "invalid"
			record.Error = "validate-run rejected scanner output"
			break
		}
		if err := checkAttemptIdentity(c, variant, validation); err != nil {
			record.Status = "invalid"
			record.Error = err.Error()
		}
		if err := checkAttemptFreshness(record, validation); err != nil {
			record.Status = "invalid"
			record.Error = err.Error()
		}
	}
	if record.Status != "completed" {
		fmt.Printf("WARN %s/%s %s: %s\n", c.Case.ID, variant, record.Status, record.Error)
	}
	return writeJSONAtomic(filepath.Join(dir, "attempt.json"), record)
}

func checkAttemptIdentity(c loadedCase, variant string, validation runbundle.Report) error {
	if c.Case.Repository != "" && c.Case.Repository != validation.Repository {
		return fmt.Errorf("scanner repository %q differs from requested %q", validation.Repository, c.Case.Repository)
	}
	want := c.Case.VulnerableRevision
	if variant == "fixed" {
		want = c.Oracle.FixedRevision
	}
	if want != "" && want != validation.Commit {
		return fmt.Errorf("scanner revision %q differs from requested %q", validation.Commit, want)
	}
	return nil
}

// A normal invocation has one shallow run directory. Nested example bundles
// inside a source checkout are not outputs of this attempt.
func findRunBundle(root string) (string, error) {
	var candidates []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		if entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if _, err := os.Stat(filepath.Join(path, "00_manifest.json")); err == nil {
			if _, err := os.Stat(filepath.Join(path, "07_arbiter", "findings.json")); err == nil {
				candidates = append(candidates, path)
			}
			// A run is an atomic output boundary. Its source checkout may contain
			// example bundles, which are never alternative results for this attempt.
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", errors.New("no completed scanner bundle in this attempt")
	}
	depth := func(p string) int {
		rel, _ := filepath.Rel(root, p)
		return strings.Count(rel, string(filepath.Separator))
	}
	sort.Slice(candidates, func(i, j int) bool { return depth(candidates[i]) < depth(candidates[j]) })
	if len(candidates) > 1 && depth(candidates[0]) == depth(candidates[1]) {
		return "", errors.New("multiple scanner bundles at the attempt output level")
	}
	return candidates[0], nil
}

func selectedAttempt(c loadedCase, variant, variantDir string) (attemptRecord, string, runbundle.Report, error) {
	var pointer latestAttempt
	if err := readJSON(filepath.Join(variantDir, "latest.json"), &pointer); err != nil {
		return attemptRecord{}, "", runbundle.Report{}, errors.New("no current attempt record; legacy results are unvalidated")
	}
	if pointer.AttemptID == "" || filepath.Base(pointer.AttemptID) != pointer.AttemptID || strings.ContainsAny(pointer.AttemptID, "/\\") {
		return attemptRecord{}, "", runbundle.Report{}, errors.New("invalid attempt identifier")
	}
	dir := filepath.Join(variantDir, "attempts", pointer.AttemptID)
	var record attemptRecord
	if err := readJSON(filepath.Join(dir, "attempt.json"), &record); err != nil {
		return record, "", runbundle.Report{}, err
	}
	if record.Schema != "teecheck.benchmark.attempt.v1" || record.AttemptID != pointer.AttemptID || record.CaseID != c.Case.ID || record.Variant != variant {
		return record, "", runbundle.Report{}, errors.New("attempt identity mismatch")
	}
	if record.Status != "completed" || record.ExitCode != 0 || record.FinishedAt == "" {
		return record, "", runbundle.Report{}, fmt.Errorf("scanner attempt is %s (exit %d): %s", record.Status, record.ExitCode, record.Error)
	}
	if record.Validation == nil || !record.Validation.Valid {
		return record, "", runbundle.Report{}, errors.New("attempt has no successful validate-run gate")
	}
	if record.BundlePath == "" {
		return record, "", runbundle.Report{}, errors.New("attempt has no bundle path")
	}
	root := filepath.Join(dir, record.BundlePath)
	rel, err := filepath.Rel(dir, root)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return record, "", runbundle.Report{}, errors.New("bundle path escapes attempt")
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return record, "", runbundle.Report{}, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return record, "", runbundle.Report{}, err
	}
	realRel, err := filepath.Rel(resolvedDir, resolvedRoot)
	if err != nil || realRel == ".." || strings.HasPrefix(realRel, ".."+string(filepath.Separator)) {
		return record, "", runbundle.Report{}, errors.New("bundle symlink escapes attempt")
	}
	validation := runbundle.Validate(root)
	if !validation.Valid {
		return record, root, validation, errors.New("current scanner bundle failed validate-run")
	}
	if err := checkAttemptIdentity(c, variant, validation); err != nil {
		return record, root, validation, err
	}
	if err := checkAttemptFreshness(record, validation); err != nil {
		return record, root, validation, err
	}
	return record, root, validation, nil
}

func checkAttemptFreshness(record attemptRecord, validation runbundle.Report) error {
	start, err := time.Parse(time.RFC3339Nano, record.StartedAt)
	if err != nil {
		return errors.New("attempt has no valid start timestamp")
	}
	end, err := time.Parse(time.RFC3339Nano, record.FinishedAt)
	if err != nil || end.Before(start) {
		return errors.New("attempt has no valid completion timestamp")
	}
	created, err := time.Parse(time.RFC3339Nano, validation.CreatedAt)
	if err != nil {
		return errors.New("scanner manifest has no valid creation timestamp")
	}
	// The manifest currently serializes whole seconds, while attempts use ns.
	if created.Before(start.Add(-2*time.Second)) || created.After(end.Add(2*time.Second)) {
		return errors.New("scanner manifest was created outside this attempt; stale result rejected")
	}
	return nil
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
