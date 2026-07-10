package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRepositoryCases(t *testing.T) {
	casesDir := filepath.Clean(filepath.Join("..", "cases"))
	entries, err := os.ReadDir(casesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no benchmark cases")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			if err := validateCase(filepath.Join(casesDir, entry.Name())); err != nil {
				t.Fatal(err)
			}
		})
	}
}
