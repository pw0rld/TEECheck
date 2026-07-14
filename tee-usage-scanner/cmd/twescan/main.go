// Command twescan runs the deterministic TWE pipeline against one source tree
// and writes a benchmark-shaped findings.json. It is the entry point the
// benchmark runner invokes as its scanner-command for the TWE path.
//
// The TrustIR candidate is currently hand-wired per fixture family (the expert
// LLM front that would locate the roles is not automated yet), so only the
// Binding family is supported. Unsupported cases exit non-zero with a clear
// message rather than emitting an empty result.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/solver"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twepipeline"
)

func main() {
	input := flag.String("input", "", "variant source dir to scan (e.g. .../TWE-BIND-0001/vulnerable)")
	runDir := flag.String("run-dir", "", "output run directory; findings.json is written under 07_arbiter/")
	fixture := flag.String("fixture", "", "fixture dir with the codeql/ harness and case.yaml (default: parent of input)")
	knowledge := flag.String("knowledge", "knowledge/twe", "TWE catalog directory")
	bundle := flag.String("bundle", "", "CodeQL bundle dir (contains the codeql binary and qlpacks)")
	cargo := flag.String("cargo", "", "dir containing cargo, prepended to PATH for the DB build")
	flag.Parse()

	if err := run(*input, *runDir, *fixture, *knowledge, *bundle, *cargo); err != nil {
		fmt.Fprintln(os.Stderr, "twescan:", err)
		os.Exit(1)
	}
}

func run(input, runDir, fixture, knowledge, bundle, cargo string) error {
	if input == "" || runDir == "" || bundle == "" {
		return fmt.Errorf("--input, --run-dir, and --bundle are required")
	}
	if fixture == "" {
		fixture = filepath.Dir(input)
	}
	scanPaths, err := readScanPaths(filepath.Join(fixture, "case.yaml"))
	if err != nil {
		return err
	}
	catalog, err := twe.Load(knowledge)
	if err != nil {
		return err
	}
	cand, err := candidateFor(catalog, input, scanPaths)
	if err != nil {
		return err
	}

	engine := codeql.NewWithBin(filepath.Join(bundle, "codeql"))
	if !engine.Available() {
		return fmt.Errorf("codeql not available under %s", bundle)
	}
	libs, err := codeql.RustLibrariesPath(bundle)
	if err != nil {
		return err
	}

	work, err := os.MkdirTemp("", "twescan-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	crate := filepath.Join(work, "crate")
	if err := codeql.AssembleFixtureCrate(filepath.Join(fixture, "codeql"), input, scanPaths, crate); err != nil {
		return err
	}
	db := filepath.Join(work, "db")
	if err := engine.CreateDatabase(context.Background(), codeql.CreateDBOptions{
		Language: "rust", SourceRoot: crate, DBPath: db, Overwrite: true, ExtraPATH: cargo,
	}); err != nil {
		return err
	}

	res, err := twepipeline.ScanSite(context.Background(), engine, catalog, cand, db, libs, filepath.Join(work, "ql"))
	if err != nil {
		return err
	}

	doc := solver.BuildFindings(filepath.Base(runDir), []solver.Result{res})
	out := filepath.Join(runDir, "07_arbiter", "findings.json")
	if err := runfs.WriteJSON(out, doc); err != nil {
		return err
	}
	fmt.Printf("twescan: %s → %s (%s)\n", cand.SiteID, res.Status, out)
	return nil
}

// candidateFor builds the TrustIR candidate for a fixture. This is the piece
// the expert LLM will eventually produce; for now it is wired for the Binding
// family by locating the attestation call and the authority point in source.
func candidateFor(catalog *twe.Catalog, input string, scanPaths []string) (twe.TrustIRCandidate, error) {
	var entry twe.Entry
	for _, e := range catalog.All() {
		if e.Family == twe.FamilyBinding {
			entry = e
			break
		}
	}
	if entry.ID == "" {
		return twe.TrustIRCandidate{}, fmt.Errorf("no Binding TWE in catalog")
	}
	// Locate roles in the first scan file (the fixture's patched file).
	scan := scanPaths[0]
	data, err := os.ReadFile(filepath.Join(input, filepath.FromSlash(scan)))
	if err != nil {
		return twe.TrustIRCandidate{}, err
	}
	claimLine := lineOf(string(data), "verify_quote")
	authLine := lineOf(string(data), ".push(")
	if claimLine == 0 || authLine == 0 {
		return twe.TrustIRCandidate{}, fmt.Errorf("could not locate Binding roles in %s (this fixture is not wired for twescan)", scan)
	}
	return twe.TrustIRCandidate{
		TWEID:  entry.ID,
		SiteID: filepath.Base(filepath.Dir(input)) + "-" + strings.TrimSuffix(filepath.Base(scan), filepath.Ext(scan)),
		Roles: map[string]twe.RoleCandidate{
			"claim_field":       {Enum: "attested_public_key", Loc: twe.Loc{Path: scan, Line: claimLine, Symbol: "report.pubkey"}},
			"authority_subject": {Enum: "registered_worker", Loc: twe.Loc{Path: scan, Line: authLine, Symbol: "pubkey"}},
		},
	}, nil
}

func lineOf(content, needle string) int {
	for i, line := range strings.Split(content, "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	return 0
}

func readScanPaths(caseYaml string) ([]string, error) {
	data, err := os.ReadFile(caseYaml)
	if err != nil {
		return nil, fmt.Errorf("read case.yaml: %w", err)
	}
	var c struct {
		ScanPaths []string `json:"scan_paths"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse case.yaml: %w", err)
	}
	if len(c.ScanPaths) == 0 {
		return nil, fmt.Errorf("case.yaml has no scan_paths")
	}
	return c.ScanPaths, nil
}
