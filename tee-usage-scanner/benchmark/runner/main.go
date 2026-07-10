package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fileSpec struct {
	Path       string `json:"path"`
	Vulnerable string `json:"vulnerable_sha256"`
	Fixed      string `json:"fixed_sha256"`
}

type caseSpec struct {
	Schema             int        `json:"schema"`
	ID                 string     `json:"id"`
	Platform           string     `json:"platform"`
	Repository         string     `json:"repository"`
	VulnerableRevision string     `json:"vulnerable_revision"`
	FixedRevision      string     `json:"fixed_revision"`
	DetectionSurface   string     `json:"detection_surface"`
	Language           string     `json:"language"`
	ScanPaths          []string   `json:"scan_paths"`
	Files              []fileSpec `json:"files"`
}

type oracleSpec struct {
	Schema           int      `json:"schema"`
	ID               string   `json:"id"`
	Expected         string   `json:"expected"`
	Weakness         string   `json:"weakness"`
	TWE              []string `json:"twe"`
	PrimaryFile      string   `json:"primary_file"`
	PrimaryFunction  string   `json:"primary_function"`
	RequiredEvidence []string `json:"required_evidence"`
	FixedEvidence    []string `json:"fixed_evidence"`
}

func main() {
	casesDir := flag.String("cases", "benchmark/cases", "benchmark cases directory")
	list := flag.Bool("list", false, "list valid case identifiers")
	flag.Parse()

	entries, err := os.ReadDir(*casesDir)
	if err != nil {
		fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		fatal(errors.New("no benchmark cases found"))
	}

	failed := false
	for _, name := range names {
		dir := filepath.Join(*casesDir, name)
		if err := validateCase(dir); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", name, err)
			failed = true
			continue
		}
		if *list {
			fmt.Println(name)
		} else {
			fmt.Printf("PASS %s\n", name)
		}
	}
	if failed {
		os.Exit(1)
	}
}

func validateCase(dir string) error {
	var c caseSpec
	if err := readJSON(filepath.Join(dir, "case.yaml"), &c); err != nil {
		return err
	}
	var o oracleSpec
	if err := readJSON(filepath.Join(dir, "oracle.yaml"), &o); err != nil {
		return err
	}
	if c.Schema != 1 || o.Schema != 1 {
		return errors.New("unsupported schema")
	}
	if c.ID == "" || c.ID != o.ID || c.ID != filepath.Base(dir) {
		return errors.New("case, oracle, and directory identifiers differ")
	}
	if c.Repository == "" || c.VulnerableRevision == "" || c.FixedRevision == "" {
		return errors.New("repository revisions are incomplete")
	}
	if len(c.Files) == 0 || len(c.ScanPaths) == 0 {
		return errors.New("no fixture files or scan paths")
	}
	if o.Expected != "vulnerable_only" || o.Weakness == "" || o.PrimaryFile == "" || o.PrimaryFunction == "" {
		return errors.New("oracle ground truth is incomplete")
	}
	if len(o.RequiredEvidence) == 0 || len(o.FixedEvidence) == 0 {
		return errors.New("oracle evidence is incomplete")
	}
	if _, err := os.Stat(filepath.Join(dir, "patches", "fix.patch")); err != nil {
		return fmt.Errorf("fix patch: %w", err)
	}

	seen := map[string]bool{}
	changed := 0
	for _, f := range c.Files {
		if f.Path == "" || filepath.IsAbs(f.Path) || strings.Contains(f.Path, "..") {
			return fmt.Errorf("unsafe fixture path %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("duplicate fixture path %q", f.Path)
		}
		seen[f.Path] = true
		vuln := filepath.Join(dir, "vulnerable", filepath.FromSlash(f.Path))
		fixed := filepath.Join(dir, "fixed", filepath.FromSlash(f.Path))
		if err := verifyHash(vuln, f.Vulnerable); err != nil {
			return err
		}
		if err := verifyHash(fixed, f.Fixed); err != nil {
			return err
		}
		if f.Vulnerable != f.Fixed {
			changed++
		}
	}
	if changed == 0 {
		return errors.New("vulnerable and fixed fixtures are identical")
	}
	if !seen[o.PrimaryFile] {
		return fmt.Errorf("oracle primary file %q is absent from fixture", o.PrimaryFile)
	}
	return nil
}

func readJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func verifyHash(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash %s: %w", path, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("hash mismatch for %s: got %s want %s", path, got, want)
	}
	return nil
}

func fatal(err error) {
	if !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(os.Stderr, err)
	} else {
		fmt.Fprintf(os.Stderr, "benchmark path does not exist: %v\n", err)
	}
	os.Exit(1)
}
