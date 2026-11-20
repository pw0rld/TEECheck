package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixturePatchRejectsReversedSources(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"vulnerable", "fixed", "patches"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	patch := "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1,3 +1,3 @@\n int check(void) {\n- return 1;\n+ return 0;\n }\n-- \n2.43.5\n"
	_ = os.WriteFile(filepath.Join(dir, "patches", "fix.patch"), []byte(patch), 0644)
	old := []byte("int check(void) {\n return 1;\n}\n")
	fixed := []byte("int check(void) {\n return 0;\n}\n")
	_ = os.WriteFile(filepath.Join(dir, "vulnerable", "a.c"), fixed, 0644)
	_ = os.WriteFile(filepath.Join(dir, "fixed", "a.c"), old, 0644)
	oracle := oracleSpec{Files: []fileSpec{{Path: "a.c"}}}
	if err := validateFixturePatch(dir, oracle); err == nil {
		t.Fatal("hash-correct but reversed fixture must be rejected")
	}
	_ = os.WriteFile(filepath.Join(dir, "vulnerable", "a.c"), old, 0644)
	_ = os.WriteFile(filepath.Join(dir, "fixed", "a.c"), fixed, 0644)
	if err := validateFixturePatch(dir, oracle); err != nil {
		t.Fatalf("forward patch with mail footer: %v", err)
	}
}
