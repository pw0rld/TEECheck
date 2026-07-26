package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A playbook that names a holdout case's file, function, or CVE id has
// memorized the answer instead of stating a generalizable obligation. That
// would make the holdout measurement meaningless, so it fails the build.
func TestPlaybooksDoNotLeakHoldoutCases(t *testing.T) {
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
		body, err := os.ReadFile(filepath.Join(playbookDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		checked++
		text := string(body)
		for term, fromCase := range forbidden {
			if term == "" {
				continue
			}
			if strings.Contains(text, term) {
				t.Errorf("%s mentions %q, which identifies holdout case %s — playbooks must state generalizable obligations, not memorized instances", e.Name(), term, fromCase)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no playbooks were checked; the path to the playbook directory is wrong")
	}
}
