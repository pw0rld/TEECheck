package twepipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/solver"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

// TestScanSiteEndToEnd exercises the whole deterministic tail on the real
// TWE-BIND-0001 fixture: build a Rust DB from the fixture harness, then run
// ScanSite (generate query → analyze → solve) for a TrustIR candidate. The
// vulnerable variant must solve to confirmed, the fixed variant to
// guarded_elsewhere.
//
//	CODEQL_BUNDLE  bundle dir; CARGO_BIN_DIR  dir with cargo
func TestScanSiteEndToEnd(t *testing.T) {
	bundle := os.Getenv("CODEQL_BUNDLE")
	if bundle == "" {
		t.Skip("set CODEQL_BUNDLE (and CARGO_BIN_DIR) to run")
	}
	engine := codeql.NewWithBin(filepath.Join(bundle, "codeql"))
	libs, err := codeql.RustLibrariesPath(bundle)
	if err != nil {
		t.Fatal(err)
	}
	extraPATH := os.Getenv("CARGO_BIN_DIR")

	catalog, err := twe.Load(filepath.Join("..", "..", "knowledge", "twe"))
	if err != nil {
		t.Fatal(err)
	}

	fixture := filepath.Join("..", "..", "benchmark", "cases", "TWE-BIND-0001")
	harness := filepath.Join(fixture, "codeql")

	// The candidate the LLM front would produce: claim_field and
	// authority_subject located in the scanned registry.rs.
	cand := twe.TrustIRCandidate{
		TWEID:  "TWE-BIND-001",
		SiteID: "bind0001-registry",
		Roles: map[string]twe.RoleCandidate{
			"claim_field":       {Enum: "attested_public_key", Loc: twe.Loc{Path: "src/registry.rs", Line: registryLine(t, fixture, "verify_quote"), Symbol: "report.pubkey"}},
			"authority_subject": {Enum: "registered_worker", Loc: twe.Loc{Path: "src/registry.rs", Line: registryLine(t, fixture, "workers.push"), Symbol: "pubkey"}},
		},
	}

	for _, tc := range []struct {
		variant string
		want    solver.Status
	}{
		{"vulnerable", solver.Confirmed},
		{"fixed", solver.GuardedElsewhere},
	} {
		t.Run(tc.variant, func(t *testing.T) {
			crate := t.TempDir()
			if err := codeql.AssembleFixtureCrate(harness, filepath.Join(fixture, tc.variant), []string{"src/registry.rs"}, crate); err != nil {
				t.Fatal(err)
			}
			db := filepath.Join(t.TempDir(), "db")
			if err := engine.CreateDatabase(context.Background(), codeql.CreateDBOptions{
				Language: "rust", SourceRoot: crate, DBPath: db, Overwrite: true, ExtraPATH: extraPATH,
			}); err != nil {
				t.Fatal(err)
			}
			res, err := ScanSite(context.Background(), engine, catalog, cand, "rust", db, libs, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != tc.want {
				t.Fatalf("%s: status=%q want %q (%s)", tc.variant, res.Status, tc.want, res.Reason)
			}
			t.Logf("%s: %s — %s", tc.variant, res.Status, res.Reason)
		})
	}
}

// registryLine finds the 1-based line of the first occurrence of needle in the
// vulnerable variant's registry.rs, so the candidate tracks the fixture even if
// its line numbers shift.
func registryLine(t *testing.T, fixture, needle string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture, "vulnerable", "src", "registry.rs"))
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range strings.Split(string(data), "\n") {
		if strings.Contains(r, needle) {
			return i + 1
		}
	}
	t.Fatalf("needle %q not found in registry.rs", needle)
	return 0
}
