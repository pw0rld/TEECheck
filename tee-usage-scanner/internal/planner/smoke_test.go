package planner_test

// Smoke test: drive the M1+M2+M3a actions manually against a real repo
// to verify the foundations work end-to-end at the action level. This is
// NOT a true integration test — the planner main loop does not exist yet
// (M3b). It is gated on TEECHECK_SMOKE_REPO env var so normal `go test`
// runs skip it.
//
// Run with:
//   TEECHECK_SMOKE_REPO=/tmp/teecheck-runs/mobilecoin \
//     go test ./internal/planner/ -run TestSmokeActions -v

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func TestSmokeActions(t *testing.T) {
	repo := os.Getenv("TEECHECK_SMOKE_REPO")
	if repo == "" {
		t.Skip("TEECHECK_SMOKE_REPO not set; skipping manual smoke test")
	}
	if _, err := os.Stat(repo); err != nil {
		t.Fatalf("repo not found: %v", err)
	}

	reg := actions.NewDefaultRegistryWithNav()

	ctx := context.Background()

	run := func(name, argsJSON string) actions.ActionResult {
		t.Helper()
		result := reg.Run(ctx, actions.ActionRequest{
			Name:     name,
			Args:     json.RawMessage(argsJSON),
			RepoRoot: repo,
		})
		return result
	}

	header := func(title string) {
		t.Helper()
		fmt.Printf("\n=== %s ===\n", title)
	}

	// 1) list_dir top-level
	header("list_dir(\".\", depth=1)")
	r := run("list_dir", `{"path":".", "depth":1}`)
	if !r.OK {
		t.Fatalf("list_dir failed: %s", r.Error)
	}
	// Print first 15 lines only
	lines := strings.SplitN(r.Output, "\n", 16)
	for i, line := range lines {
		if i == 15 {
			fmt.Println("... (truncated)")
			break
		}
		fmt.Println(line)
	}

	// 2) list_dir attest subtree
	header("list_dir(\"attest\", depth=2)")
	r = run("list_dir", `{"path":"attest", "depth":2}`)
	if !r.OK {
		t.Fatalf("list_dir attest failed: %s", r.Error)
	}
	// Count and print first 30 lines
	lines = strings.Split(r.Output, "\n")
	fmt.Printf("(%d entries)\n", len(lines)-1)
	for i, line := range lines {
		if i == 30 {
			fmt.Println("... (truncated)")
			break
		}
		fmt.Println(line)
	}

	// 3) ripgrep for quote verification symbols
	header("ripgrep(\"verify_quote|verify_report\", globs=[\"*.rs\"])")
	r = run("ripgrep", `{"pattern":"verify_quote|verify_report", "globs":["*.rs"]}`)
	if !r.OK {
		t.Fatalf("ripgrep failed: %s", r.Error)
	}
	rgLines := strings.Split(r.Output, "\n")
	fmt.Printf("(%d match lines, truncated=%v)\n", len(rgLines), r.Truncated)
	for i, line := range rgLines {
		if i == 20 {
			fmt.Println("... (truncated)")
			break
		}
		fmt.Println(line)
	}

	// 4) tree_sitter_outline on a known attestation file
	header("tree_sitter_outline(\"attest/verifier/src/lib.rs\")")
	r = run("tree_sitter_outline", `{"path":"attest/verifier/src/lib.rs"}`)
	if !r.OK {
		// Not a failure — the file may not exist. Just print the error.
		fmt.Printf("(skipped: %s)\n", r.Error)
	} else {
		outlineLines := strings.Split(r.Output, "\n")
		fmt.Printf("(%d outline entries)\n", len(outlineLines)-1)
		for i, line := range outlineLines {
			if i == 25 {
				fmt.Println("... (truncated)")
				break
			}
			fmt.Println(line)
		}
	}

	// 5) ripgrep for key generation sinks
	header("ripgrep(\"KeyPair::generate|OsRng|thread_rng\", globs=[\"*.rs\"])")
	r = run("ripgrep", `{"pattern":"KeyPair::generate|OsRng|thread_rng", "globs":["*.rs"]}`)
	if !r.OK {
		t.Fatalf("ripgrep keys failed: %s", r.Error)
	}
	kgLines := strings.Split(r.Output, "\n")
	fmt.Printf("(%d key-source matches)\n", len(kgLines))
	for i, line := range kgLines {
		if i == 15 {
			fmt.Println("... (truncated)")
			break
		}
		fmt.Println(line)
	}
}
