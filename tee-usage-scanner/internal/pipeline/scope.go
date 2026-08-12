package pipeline

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// acquireSourceScope resolves the one tree every stage of the run reads, and
// checks it out if it is not there yet. It returns the resolved root and
// whether that root is the pinned repository@commit rather than the target
// directory the user named.
//
// Resolved once, at the top of the run, before the first stage. Everything
// downstream — preprocess, architecture, invariants, the planner's actions,
// the scanner bus tool, and the fact layer's own database build — takes this
// path. That single resolution is the point: a run where CodeQL analyses
// 460k lines while reverse_trace reads one file produces evidence that
// contradicts itself and cannot be reconciled by any later stage. On
// CVE-2026-44362 the fact layer located a caller in core/kernel/ree_fs_ta.c
// in the same run where reverse_trace reported the function had none, and
// the Challenger concluded the code was unreachable.
//
// A benchmark fixture is not a repository — it is the handful of files the
// upstream fix touched, kept as an exact vulnerable/fixed pair. Scanning it
// directly makes most of this tool meaningless: a CodeQL database over one
// file has no call graph, and reverse_trace, ripgrep and read_file can only
// report absence. The fixture stays the evaluator's ground truth; the
// scanner reads the revision it was cut from.
//
// Failure is never fatal. Without a pinned identity, or when the checkout
// fails, the run continues against the named target — a smaller scope, but a
// truthful one. What must never happen is reading the narrow tree while
// reporting about the wide one.
func acquireSourceScope(ctx context.Context, db *codedb.Manager, runDir, repository, commit, fallback string) (string, bool) {
	if repository == "" || commit == "" {
		return fallback, false
	}
	scope := codedb.Scope{RunDir: runDir, Repository: repository, Commit: commit}
	if db.SourceAvailable(scope) {
		return absOrSame(db.SourceDir(scope)), true
	}
	tree, err := db.EnsureSource(ctx, scope)
	if err != nil {
		fmt.Printf("Warning: could not check out %s@%s (%v); scanning %s instead\n",
			repository, truncate(commit, 12), err, fallback)
		return fallback, false
	}
	return absOrSame(tree), true
}

// absOrSame makes the source root absolute.
//
// The root is derived from the run directory, which is relative whenever the
// caller passed a relative --output-dir — "runs/run-b" by default. An
// in-process reader resolves that against the process's own directory and
// sees the tree; a tool that shells out does not. ripgrep runs through the
// executor, and for three consecutive runs every single one of its 17 calls
// failed with "No such file or directory" while read_file in the same round
// succeeded. Nothing surfaced it: the planner records a failed action as an
// observation like any other, and the run looked normal from the outside.
func absOrSame(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// recordScannedRoot rewrites the run manifest's local_path to the tree the
// run actually reads, and records that tree's scope.
//
// It is not bookkeeping. manifest.LocalPath is what invariants validates
// against and what expert and verifier resolve every cited byte range
// against — stages that never see the pipeline's own config. A manifest
// naming the target directory while the tools read the pinned checkout is
// the two-scope split all over again, and this time invisible: nothing would
// print the disagreement.
//
// The scope record is the machine-checkable half of the same guarantee.
// local_path says which tree; scope says how much code is in it, so a later
// stage that resolved a root of its own can call runfs.VerifyScope and fail
// with a scope error instead of reporting a conclusion about code it never
// saw.
func recordScannedRoot(runDir, root string) error {
	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		return err
	}
	scope := runfs.BuildScope(manifest.RepoURL, manifest.Commit, root)
	if manifest.LocalPath == root && manifest.Scope == scope {
		return nil
	}
	manifest.LocalPath = root
	manifest.Scope = scope
	return runfs.WriteJSON(runfs.ManifestPath(runDir), manifest)
}
