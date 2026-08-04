package projectmap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// probeRun writes a source tree, a manifest and a repo_facts artifact, and
// returns the config pointing at them.
func probeRun(t *testing.T, files map[string]string, facts artifacts.RepoFacts) config.Config {
	t.Helper()
	src := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runDir := t.TempDir()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1", RunID: "run-map",
		RepoURL: "https://example.invalid/r", Commit: "abc123", LocalPath: src,
	}); err != nil {
		t.Fatal(err)
	}
	facts.SchemaVersion = artifacts.SchemaVersionRepoFactsV1
	facts.RunID = "run-map"
	// repoindex validates before writing, so a repo_facts on disk is always
	// schema-valid. Mirroring that here means a test cannot accidentally
	// hand this stage an artifact production could never produce.
	data, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(schema.RepoFactsV1, data); err != nil {
		t.Fatalf("the probe wrote a repo_facts production could not: %v", err)
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
		t.Fatal(err)
	}
	return config.Config{RunDir: runDir}
}

func readMap(t *testing.T, runDir string) artifacts.ProjectMap {
	t.Helper()
	var m artifacts.ProjectMap
	if err := runfs.ReadJSON(runfs.ProjectMapPath(runDir), &m); err != nil {
		t.Fatalf("the stage must write the project map: %v", err)
	}
	return m
}

func capsule(file, module, name string) artifacts.FunctionCapsule {
	return artifacts.FunctionCapsule{
		SymbolID: artifacts.MakeSymbolID("cpp", file, 1, name, "()"),
		Name:     name, Module: module, File: file, Line: 1,
	}
}

func TestRun_WritesTheMapAndItsPages(t *testing.T) {
	cfg := probeRun(t,
		map[string]string{
			"README.md":                "# Probe\n\nA miniature repository for the project map.\n",
			"Makefile":                 "all:\n",
			"core/crypto/signed_hdr.c": "int f(void){return 0;}\n",
			"core/kernel/ree_fs_ta.c":  "int g(void){return 0;}\n",
			"lib/libmbedtls/aes.c":     "int h(void){return 0;}\n",
			".git/COMMIT_EDITMSG":      "wip\n",
		},
		artifacts.RepoFacts{
			Capabilities: artifacts.IndexCapabilities{
				Symbols: artifacts.CapabilityAvailable, DirectCalls: artifacts.CapabilityPartial,
				FieldAccesses: artifacts.CapabilityPartial, BuildReachability: artifacts.CapabilityUnavailable,
			},
			Languages: []string{"cpp"},
			Capsules: []artifacts.FunctionCapsule{
				capsule("core/crypto/signed_hdr.c", "core/crypto", "f"),
				capsule("core/kernel/ree_fs_ta.c", "core/kernel", "g"),
				capsule("lib/libmbedtls/aes.c", "lib/libmbedtls", "h"),
			},
		})

	if err := Run(cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := readMap(t, cfg.RunDir)

	if !strings.Contains(m.Repository.DocumentedPurpose, "miniature repository") {
		t.Errorf("documented purpose = %q, want the README's own words", m.Repository.DocumentedPurpose)
	}
	if len(m.Repository.BuildTargets) != 1 || m.Repository.BuildTargets[0] != "make" {
		t.Errorf("build targets = %v, want [make]", m.Repository.BuildTargets)
	}
	// .git is excluded, so the count describes the code.
	if m.Repository.FileCount != 5 {
		t.Errorf("file count = %d, want 5 — .git must not be counted", m.Repository.FileCount)
	}

	byPath := map[string]artifacts.ModuleCard{}
	for _, c := range m.Modules {
		byPath[c.Path] = c
	}
	if byPath["lib/libmbedtls"].FileCount != 1 || byPath["lib/libmbedtls"].FunctionCount != 1 {
		t.Errorf("lib/libmbedtls card = %+v, want one file and one function", byPath["lib/libmbedtls"])
	}

	// Every page reference must open.
	if len(m.FunctionPages) == 0 {
		t.Fatal("no function card pages were written")
	}
	for _, ref := range m.FunctionPages {
		full := filepath.Join(cfg.RunDir, filepath.FromSlash(ref.Path))
		body, err := os.ReadFile(full)
		if err != nil {
			t.Errorf("page %s does not exist: %v", ref.Path, err)
			continue
		}
		if len(body) > observationlimits.MaxBytes {
			t.Errorf("page %s is %d bytes, over the observation cap", ref.Path, len(body))
		}
	}
}

// The map carries the index's capability verdicts forward. Without them a
// Planner reading an empty module list cannot tell a repository with no
// indexed functions from a run where CodeQL never ran — and the map is the
// only thing it reads.
func TestRun_CarriesTheIndexCapabilitiesForward(t *testing.T) {
	cfg := probeRun(t, map[string]string{"a.c": "int a;\n"}, artifacts.RepoFacts{
		Capabilities: artifacts.IndexCapabilities{
			Symbols: artifacts.CapabilityUnavailable, DirectCalls: artifacts.CapabilityUnavailable,
			FieldAccesses: artifacts.CapabilityUnavailable, BuildReachability: artifacts.CapabilityUnavailable,
		},
		IndexNote: "codeql database: extractor found no compilable source",
	})
	if err := Run(cfg); err != nil {
		t.Fatalf("a degraded index must still produce a map: %v", err)
	}
	m := readMap(t, cfg.RunDir)
	if m.Capabilities.Symbols != artifacts.CapabilityUnavailable {
		t.Errorf("symbols = %q, want the index's own verdict carried through", m.Capabilities.Symbols)
	}
	if len(m.FunctionPages) != 0 {
		t.Error("no capsules means no pages")
	}
	// The tree is still described: modules and sizes do not need CodeQL.
	if m.Repository.FileCount != 1 {
		t.Errorf("file count = %d, want the tree still walked", m.Repository.FileCount)
	}
}

// A repository with no README gets an empty purpose. Inventing one would be
// an inference wearing a quote's clothes, and the architecture agent cites
// this field.
func TestRun_NoReadmeMeansNoDocumentedPurpose(t *testing.T) {
	cfg := probeRun(t, map[string]string{"a.c": "int a;\n"}, artifacts.RepoFacts{
		Capabilities: artifacts.IndexCapabilities{
			Symbols: artifacts.CapabilityAvailable, DirectCalls: artifacts.CapabilityAvailable,
			FieldAccesses: artifacts.CapabilityPartial, BuildReachability: artifacts.CapabilityUnavailable,
		},
	})
	if err := Run(cfg); err != nil {
		t.Fatal(err)
	}
	if got := readMap(t, cfg.RunDir).Repository.DocumentedPurpose; got != "" {
		t.Errorf("documented purpose = %q, want empty", got)
	}
}

// Missing the index is a pipeline error, not a degradation: this stage
// exists to derive from it, and deriving from nothing would produce a map
// that looks like a description of an empty repository.
func TestRun_MissingRepoFactsIsAnError(t *testing.T) {
	runDir := t.TempDir()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{RunID: "run-map"}); err != nil {
		t.Fatal(err)
	}
	if err := Run(config.Config{RunDir: runDir}); err == nil {
		t.Error("a missing program index must fail the stage")
	}
}
