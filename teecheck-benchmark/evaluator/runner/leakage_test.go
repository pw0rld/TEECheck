package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// holdoutFunctionRevision is the commit whose parent still had
// primary_function populated in every oracle.yaml. c3e3e28 trimmed that
// field from all 44 datasets, so we recover the pre-trim value straight
// from git history at test time rather than ever writing it to disk.
const holdoutFunctionRevision = "c3e3e28^"

// recoverHoldoutFunctions shells out to git to read each holdout case's
// primary_function as it existed before c3e3e28 stripped the field. The
// values are kept only in memory for the duration of the test — persisting
// them to a committed file would leak the holdout answers to playbook
// authors, defeating the point of the guard.
func recoverHoldoutFunctions(t *testing.T, repoRoot string, holdout []string) map[string]string {
	t.Helper()
	recovered := map[string]string{} // case id -> primary_function
	for _, id := range holdout {
		path := "teecheck-benchmark/datasets/" + id + "/oracle.yaml"
		cmd := exec.Command("git", "show", holdoutFunctionRevision+":"+path)
		cmd.Dir = repoRoot
		out, err := cmd.Output()
		if err != nil {
			// Missing at that revision (or git failed for this one path) —
			// skip this case's function name but keep going with the rest.
			continue
		}
		var o struct {
			PrimaryFunction string `json:"primary_function"`
		}
		if err := json.Unmarshal(out, &o); err != nil {
			continue
		}
		if o.PrimaryFunction != "" {
			recovered[id] = o.PrimaryFunction
		}
	}
	return recovered
}

// scanFileForLeaks reads a single knowledge file and reports (via t.Errorf)
// every forbidden term it contains, attributing each hit to the holdout case
// it identifies. It returns true if the file was read successfully, so
// callers can distinguish "checked, found nothing" from "couldn't read it".
func scanFileForLeaks(t *testing.T, path, displayName string, forbidden map[string]string) bool {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", displayName, err)
	}
	text := string(body)
	for term, fromCase := range forbidden {
		if term == "" {
			continue
		}
		if strings.Contains(text, term) {
			t.Errorf("%s mentions %q, which identifies holdout case %s — knowledge files must state generalizable obligations, not memorized instances", displayName, term, fromCase)
		}
	}
	return true
}

// A knowledge file (playbook or catalog entry) that names a holdout case's
// file, function, or CVE id has memorized the answer instead of stating a
// generalizable obligation. That would make the holdout measurement
// meaningless, so it fails the build.
func TestKnowledgeDoesNotLeakHoldoutCases(t *testing.T) {
	var split struct {
		Holdout []string `json:"holdout"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "datasets", "split.v1.json"))
	if err != nil {
		t.Fatalf("read split: %v", err)
	}
	if err := json.Unmarshal(raw, &split); err != nil {
		t.Fatalf("parse split: %v", err)
	}
	if len(split.Holdout) == 0 {
		t.Fatal("split.v1.json lists no holdout cases")
	}

	// Build the forbidden vocabulary: each holdout case's id, its oracle's
	// primary_file (and that file's base name), and its primary_function.
	forbidden := map[string]string{} // term -> which case it came from
	for _, id := range split.Holdout {
		forbidden[id] = id
		oraclePath := filepath.Join("..", "..", "datasets", id, "oracle.yaml")
		data, err := os.ReadFile(oraclePath)
		if err != nil {
			continue // a case without an oracle cannot leak through it
		}
		var o struct {
			PrimaryFile     string `json:"primary_file"`
			PrimaryFunction string `json:"primary_function"`
		}
		if err := json.Unmarshal(data, &o); err != nil {
			continue
		}
		if o.PrimaryFile != "" {
			forbidden[o.PrimaryFile] = id
			if base := filepath.Base(o.PrimaryFile); base != o.PrimaryFile {
				forbidden[base] = id
			}
		}
		if o.PrimaryFunction != "" {
			forbidden[o.PrimaryFunction] = id
		}
	}

	// No oracle on disk carries primary_function today (c3e3e28 trimmed it
	// from all 44 datasets), so the loop above never populates it. Recover
	// each holdout case's pre-trim primary_function from git history and
	// add it to the forbidden vocabulary — without ever writing it to a
	// committed file.
	repoRootOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git unavailable, cannot recover holdout primary_function values: %v", err)
	}
	repoRoot := strings.TrimSpace(string(repoRootOut))
	recoveredFunctions := recoverHoldoutFunctions(t, repoRoot, split.Holdout)
	if len(recoveredFunctions) == 0 {
		t.Fatalf("recovered zero holdout primary_function values from %s; the function-name half of the leak guard would silently check nothing", holdoutFunctionRevision)
	}
	for id, fn := range recoveredFunctions {
		forbidden[fn] = id
	}

	playbookDir := filepath.Join("..", "..", "..", "tee-usage-scanner", "knowledge", "twe", "playbooks")
	entries, err := os.ReadDir(playbookDir)
	if err != nil {
		t.Fatalf("read playbook dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		if scanFileForLeaks(t, filepath.Join(playbookDir, e.Name()), e.Name(), forbidden) {
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no playbooks were checked; the path to the playbook directory is wrong")
	}

	catalogPath := filepath.Join("..", "..", "..", "tee-usage-scanner", "knowledge", "twe", "definitions", "catalog.yml")
	scanFileForLeaks(t, catalogPath, "catalog.yml", forbidden)
}
