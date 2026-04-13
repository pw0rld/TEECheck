# LLM Planner M2 — Sink Catalog + Tree-sitter Outline + Catalog Lookup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the sink catalog data file, the catalog loader/matcher package, the tree-sitter Rust outline action, and the sink_catalog_lookup action. After M2 the planner has a parsed catalog accessible by the LLM and can extract structured outlines from Rust files. No planner main loop yet (M3) and no pipeline integration yet (M4).

**Architecture:** New package `internal/planner/sinks` containing JSON catalog types, loader, and a matcher that supports two modes (`syntax` for tree-sitter node text matches and `symbol` for symbol-name globs). New `knowledge/sinks/rust.json` data file containing 3 groups × 13 categories scoped to attestation + key lifecycle. Two new action handlers under `internal/planner/actions/`: `tree_sitter_outline` (uses `go-tree-sitter` + Rust grammar via cgo) and `sink_catalog_lookup` (reads the catalog and returns table-of-contents / full-group / single-category responses).

**Tech Stack:** Go 1.25, stdlib + `github.com/smacker/go-tree-sitter` (with `rust` subpackage). cgo enabled. cgo smoke test on the dev machine has already passed (Linux x64) — the dependency builds cleanly without manual C library setup.

**Spec:** `docs/superpowers/specs/2026-04-11-llm-planner-design.md` — sections 4 (action menu), 5 (sink catalog), and the M2 row of section 12 (milestones).

**Prereq:** M1 must be merged. Latest commit before M2 should be `3c76ce1` (GLM timeout fix) or later.

---

## File Structure

### Files created

| Path | Purpose |
|---|---|
| `knowledge/sinks/rust.json` | v1 sink catalog data — 3 groups, 13 categories |
| `knowledge/sinks/README.md` | Sink taxonomy explanation for human readers |
| `internal/planner/sinks/types.go` | `Catalog`, `Group`, `Category`, `Match` Go types |
| `internal/planner/sinks/loader.go` | `Load(path) (*Catalog, error)` + lookup methods |
| `internal/planner/sinks/loader_test.go` | Catalog parsing + schema validation tests |
| `internal/planner/sinks/matcher.go` | `MatchSymbol(glob, symbol) bool` and helpers |
| `internal/planner/sinks/matcher_test.go` | Glob matcher tests |
| `internal/planner/actions/tree_sitter_outline.go` | `TreeSitterOutlineHandler` |
| `internal/planner/actions/tree_sitter_outline_test.go` | Outline extraction tests |
| `internal/planner/actions/sink_catalog_lookup.go` | `SinkCatalogLookupHandler` |
| `internal/planner/actions/sink_catalog_lookup_test.go` | 3-scope lookup tests |
| `internal/planner/actions/registry_with_sinks.go` | `NewDefaultRegistryWithSinks(catalogPath)` extension |

### Files modified

| Path | Change |
|---|---|
| `go.mod` / `go.sum` | Add `github.com/smacker/go-tree-sitter` |

### Out of scope for M2

- Planner main loop, state, prompt, budget — M3
- `reverse_trace` action — M3
- `legacy_keyword_scan`, `repomix_summarize`, `done` actions — M3
- Pipeline integration (`scanner/scan.go`, `cases/run.go`) — M4
- LLM-proposed sink writeback — v2

---

## Task 1: Create `knowledge/sinks/rust.json`

**Files:**
- Create: `knowledge/sinks/rust.json`
- Create: `knowledge/sinks/README.md`

This task is data-only. No Go code, no tests yet — the loader (Task 3) will validate this file's schema.

- [ ] **Step 1.1: Write the rust.json catalog**

Create `knowledge/sinks/rust.json` with this exact content:

```json
{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "Report/quote generation, verification, identity/TCB checks, and freshness — the full remote-attestation chain",
      "categories": [
        {
          "id": "attestation_report_creation",
          "description": "Quote/report generation and report_data field binding. Audit: what data (session pk, nonce, challenge) is bound into the report.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "sgx_create_report",
              "sgx_quote_*",
              "sgx_qe_*",
              "*::create_report*",
              "*::generate_quote*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_verification_and_trust",
          "description": "Verification entry points and the trust decisions made after verification. The exact trust-decision site is project-specific and must be located by reverse_trace from the verify call.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "*::verify_quote*",
              "*::verify_report*",
              "*::verify_attestation*",
              "*::verify_evidence*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_identity_and_tcb_checks",
          "description": "MRENCLAVE/MRSIGNER equality checks and TCB/QEIdentity/collateral/CRL validation. Audit: comparison targets correct, expiration/revocation honored.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "*MRENCLAVE*",
              "*MRSIGNER*",
              "*::check_tcb*",
              "*::verify_tcb*",
              "*::qe_identity*",
              "*::collateral*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_freshness",
          "description": "Nonce binding, challenge-response flow, time-window checks. Audit: replay resistance.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "*::nonce*",
              "*::challenge*",
              "*::freshness*"
            ]
          },
          "severity_hint": "high"
        }
      ]
    },
    {
      "id": "tee_platform_syscalls",
      "description": "Enclave entry/exit and SGX platform services — trust boundary crossings",
      "categories": [
        {
          "id": "sgx_ecall",
          "description": "Enclave entry — arguments are untrusted host input.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "sgx_tstd::*",
              "sgx_urts::*",
              "#[ecall]"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "sgx_ocall",
          "description": "Out-of-enclave calls — return values are host-controlled and must be re-validated inside the enclave.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "*::ocall_*",
              "sgx_ocall_*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "sgx_platform_services",
          "description": "SGX platform services including QE, RA, and AESM interaction. Audit: error and degradation paths.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "sgx_qe_*",
              "sgx_ra_*",
              "aesm_*",
              "*::aesm*"
            ]
          },
          "severity_hint": "medium"
        }
      ]
    },
    {
      "id": "key_lifecycle",
      "description": "Key generation, derivation, sealing, signature ops, AEAD, and secret hygiene — complete key lifecycle audit",
      "categories": [
        {
          "id": "key_generation",
          "description": "Key pair / secret key generation and the RNG source used. In a TEE the RNG must be attested (OsRng/getrandom with platform hardware entropy), never thread_rng or seeded PRNGs.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "KeyPair::generate",
              "*::SecretKey::random",
              "*::generate_keypair*",
              "OsRng",
              "thread_rng",
              "getrandom::*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "key_derivation_and_exchange",
          "description": "HKDF, KDF, derive_key, ECDH, X25519, key_agreement. Audit: context/info/salt binding prevents cross-context collision; peer identity is bound to an attested key.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "*::derive_key*",
              "*::hkdf*",
              "*::kdf*",
              "*::key_agreement*",
              "*::diffie_hellman*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "key_sealing",
          "description": "SGX sealing, runtime sealing, and unsealing. Audit: sealing policy binds to MRENCLAVE vs MRSIGNER appropriately; unseal results are re-validated.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "sgx_seal_data",
              "sgx_unseal_data",
              "*::seal*",
              "*::unseal*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "signature_ops",
          "description": "Signing and signature verification. Audit: signing key source is attested/sealed; verification failure paths cannot fall through; verifying key is trusted.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "*::sign",
              "*::sign_message*",
              "*::verify_signature*",
              "ed25519::*",
              "k256::*",
              "secp256k1::*"
            ]
          },
          "severity_hint": "high"
        },
        {
          "id": "aead_encryption",
          "description": "AEAD seal/open (ChaCha20-Poly1305, AES-GCM, etc.). Audit: nonce uniqueness, key lifetime, associated data binding.",
          "match": {
            "kind": "symbol",
            "symbols": [
              "*::seal_in_place*",
              "*::open_in_place*",
              "chacha20poly1305::*",
              "aes_gcm::*"
            ]
          },
          "severity_hint": "medium"
        },
        {
          "id": "secret_hygiene",
          "description": "Zeroize traits, secret wrapper types, and absence thereof. Audit: secret types lack Zeroize/ZeroizeOnDrop, or expose themselves via Debug/Display/serde.",
          "match": {
            "kind": "syntax",
            "patterns": [
              "Zeroize",
              "ZeroizeOnDrop",
              "Secret<",
              "secrecy::",
              "#[derive(Debug)]"
            ]
          },
          "severity_hint": "medium"
        }
      ]
    }
  ]
}
```

- [ ] **Step 1.2: Write the README**

Create `knowledge/sinks/README.md`:

```markdown
# Sink Catalog

This directory contains hand-curated sink catalogs that drive the L3 LLM
planner's reverse-trace audits. Each language has its own JSON file
(`rust.json`, `go.json`, ...) following the schema described below.

## What is a "sink"?

A **sink** is a code construct where the LLM should anchor a
reverse-trace audit. Sinks are not bug patterns themselves — they are
*starting points* the LLM uses to find bugs that result from missing
obligations on the path leading to the sink.

A category like `attestation_report_creation` says "wherever the code
generates an attestation report, audit which data is bound into it."
The LLM then uses `reverse_trace` to walk backward from those points
and inspect the call chain.

## Schema (`teecheck.sink_catalog.v2`)

```
{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id":          "<group_id>",
      "description": "<one-line group description (LLM sees this first)>",
      "categories": [
        {
          "id":          "<category_id>",
          "description": "<what to audit at sites matching this category>",
          "match": {
            "kind":     "symbol" | "syntax",
            "symbols":  ["<glob>", ...],   // when kind=symbol
            "patterns": ["<text>", ...]    // when kind=syntax
          },
          "severity_hint": "high" | "medium" | "low"
        }
      ]
    }
  ]
}
```

## Match modes

- **`symbol`**: glob match against fully-qualified symbol names. The
  glob syntax supports `*` as a wildcard. Example: `*::verify_quote*`
  matches `attest::verify_quote`, `sgx::verify_quote_extended`, etc.
- **`syntax`**: literal text match against tree-sitter node text. Used
  for things that are not callable symbols, e.g. `Zeroize` derive
  attribute presence or `extern "C"` block markers.

## Scope

v1 covers **attestation + key lifecycle only**. Memory safety, host
leakage, panic/debug smells, and generic runtime state mutation are
explicitly out of scope. The LLM can still investigate code outside
the catalog using `ripgrep` and `read_file`, but the catalog is what
focuses the reverse-trace effort.

## Adding new categories

1. Edit the appropriate `<lang>.json` file
2. Run `go test ./internal/planner/sinks/...` to verify schema validity
3. Submit a PR describing the threat model the new category is meant
   to expose

## Adding new languages

v1 ships only `rust.json`. Adding `go.json` or others requires:
1. A new JSON file following this schema
2. A tree-sitter grammar binding for the language (for the syntax
   matcher and the `tree_sitter_outline` action)
3. Tests under `internal/planner/sinks/`
```

- [ ] **Step 1.3: Verify JSON parses**

Run: `python3 -c "import json; json.load(open('knowledge/sinks/rust.json'))"`
Expected: exit 0, no output. (Python is just a quick syntax check; the Go schema validation comes in Task 3.)

- [ ] **Step 1.4: Commit**

```bash
git add knowledge/sinks/rust.json knowledge/sinks/README.md
git commit -m "$(cat <<'EOF'
feat(knowledge): add rust sink catalog (3 groups, 13 categories)

Initial v2 sink catalog scoped to attestation and key lifecycle:
- attestation: report_creation, verification_and_trust, identity_and_tcb_checks, freshness
- tee_platform_syscalls: sgx_ecall, sgx_ocall, sgx_platform_services
- key_lifecycle: generation, derivation_and_exchange, sealing, signature_ops, aead, secret_hygiene

Also adds README.md explaining the schema, match modes, and how to
extend the catalog. Memory safety, host leakage, panic/debug, and
generic runtime state mutation are deliberately out of scope per
spec section 5.

Part of M2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Sink catalog Go types

**Files:**
- Create: `internal/planner/sinks/types.go`

- [ ] **Step 2.1: Write the types file**

Create `internal/planner/sinks/types.go`:

```go
// Package sinks loads, validates, and matches against the planner's
// sink catalogs. A sink catalog is a hand-curated list of code
// constructs the LLM uses as anchors for reverse-trace audits.
//
// See knowledge/sinks/README.md for the JSON schema and the audit
// semantics of "sink" in this codebase.
package sinks

const SchemaVersion = "teecheck.sink_catalog.v2"

// Catalog is the top-level loaded form of a per-language JSON file.
type Catalog struct {
	SchemaVersion string  `json:"schema_version"`
	Language      string  `json:"language"`
	Groups        []Group `json:"groups"`
}

// Group bundles related categories under a single LLM-facing
// description. The LLM lists groups first ("*" scope) before drilling
// into a specific group.
type Group struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Categories  []Category `json:"categories"`
}

// Category is a single sink class the LLM can ask reverse_trace to
// anchor on. The Match field describes how the planner identifies
// concrete code sites that belong to this category.
type Category struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	Match         Match  `json:"match"`
	SeverityHint  string `json:"severity_hint"`
}

// Match describes how to find concrete sites for a Category.
//
// Two kinds:
//   - "symbol": glob-match against fully-qualified symbol names
//     (used by reverse_trace's call-site search). Symbols field is
//     the glob list, Patterns must be empty.
//   - "syntax": literal text match against tree-sitter node text
//     (used for non-callable constructs like derive attributes).
//     Patterns field is the text list, Symbols must be empty.
type Match struct {
	Kind     string   `json:"kind"`
	Symbols  []string `json:"symbols,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
}

const (
	MatchKindSymbol = "symbol"
	MatchKindSyntax = "syntax"
)
```

- [ ] **Step 2.2: Verify compilation**

Run: `go build ./internal/planner/sinks/`
Expected: exit 0.

- [ ] **Step 2.3: Commit**

```bash
git add internal/planner/sinks/types.go
git commit -m "$(cat <<'EOF'
feat(planner/sinks): add sink catalog Go types

Defines Catalog, Group, Category, and Match matching the v2 JSON
schema in knowledge/sinks/rust.json. Constants for SchemaVersion,
MatchKindSymbol, and MatchKindSyntax.

Part of M2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Sink catalog loader + schema validation

**Files:**
- Create: `internal/planner/sinks/loader_test.go` (FIRST)
- Create: `internal/planner/sinks/loader.go`

- [ ] **Step 3.1: Write loader tests**

Create `internal/planner/sinks/loader_test.go`:

```go
package sinks_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/sinks"
)

const validCatalogJSON = `{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "remote attestation chain",
      "categories": [
        {
          "id": "attestation_verify",
          "description": "verify entry points",
          "match": { "kind": "symbol", "symbols": ["*::verify_quote*"] },
          "severity_hint": "high"
        }
      ]
    }
  ]
}`

func writeCatalog(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rust.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_HappyPath(t *testing.T) {
	path := writeCatalog(t, validCatalogJSON)

	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cat.SchemaVersion != sinks.SchemaVersion {
		t.Fatalf("got schema %q, want %q", cat.SchemaVersion, sinks.SchemaVersion)
	}
	if cat.Language != "rust" {
		t.Fatalf("got language %q, want rust", cat.Language)
	}
	if len(cat.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(cat.Groups))
	}
	if cat.Groups[0].ID != "attestation" {
		t.Fatalf("got group id %q, want attestation", cat.Groups[0].ID)
	}
	if len(cat.Groups[0].Categories) != 1 {
		t.Fatalf("got %d categories, want 1", len(cat.Groups[0].Categories))
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := sinks.Load("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_RejectsWrongSchemaVersion(t *testing.T) {
	bad := strings.Replace(validCatalogJSON, "v2", "v99", 1)
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for wrong schema version")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("expected schema_version error, got %v", err)
	}
}

func TestLoad_RejectsEmptyGroups(t *testing.T) {
	bad := `{"schema_version": "teecheck.sink_catalog.v2", "language": "rust", "groups": []}`
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for empty groups")
	}
	if !strings.Contains(err.Error(), "groups") {
		t.Fatalf("expected groups error, got %v", err)
	}
}

func TestLoad_RejectsCategoryMissingMatchKind(t *testing.T) {
	bad := `{
		"schema_version": "teecheck.sink_catalog.v2",
		"language": "rust",
		"groups": [{
			"id": "g1", "description": "x",
			"categories": [{
				"id": "c1", "description": "x",
				"match": {},
				"severity_hint": "high"
			}]
		}]
	}`
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for missing match.kind")
	}
}

func TestLoad_RejectsSymbolKindWithPatterns(t *testing.T) {
	// kind=symbol must use symbols[], not patterns[]
	bad := `{
		"schema_version": "teecheck.sink_catalog.v2",
		"language": "rust",
		"groups": [{
			"id": "g1", "description": "x",
			"categories": [{
				"id": "c1", "description": "x",
				"match": { "kind": "symbol", "patterns": ["foo"] },
				"severity_hint": "high"
			}]
		}]
	}`
	path := writeCatalog(t, bad)

	_, err := sinks.Load(path)
	if err == nil {
		t.Fatal("expected error for symbol kind with patterns")
	}
}

func TestLoad_RustJSONFromKnowledge(t *testing.T) {
	// Load the real on-disk rust.json from knowledge/sinks/.
	// The path is relative to the repo root; the test runs from the
	// internal/planner/sinks directory, so go up four levels.
	path := filepath.Join("..", "..", "..", "knowledge", "sinks", "rust.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("knowledge/sinks/rust.json not found at %s: %v", path, err)
	}

	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatalf("real catalog failed to load: %v", err)
	}
	if len(cat.Groups) != 3 {
		t.Fatalf("expected 3 groups in real catalog, got %d", len(cat.Groups))
	}

	totalCategories := 0
	for _, g := range cat.Groups {
		totalCategories += len(g.Categories)
	}
	if totalCategories != 13 {
		t.Fatalf("expected 13 total categories in real catalog, got %d", totalCategories)
	}
}

func TestLookupGroup(t *testing.T) {
	path := writeCatalog(t, validCatalogJSON)
	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	g, err := cat.LookupGroup("attestation")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if g.ID != "attestation" {
		t.Fatalf("got %q", g.ID)
	}

	_, err = cat.LookupGroup("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestLookupCategory(t *testing.T) {
	path := writeCatalog(t, validCatalogJSON)
	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	c, err := cat.LookupCategory("attestation", "attestation_verify")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c.ID != "attestation_verify" {
		t.Fatalf("got %q", c.ID)
	}

	_, err = cat.LookupCategory("attestation", "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown category")
	}
}

func TestGroupHeaders(t *testing.T) {
	// GroupHeaders returns ID + description for each group, no categories.
	// This is what "*" scope returns to the LLM.
	path := writeCatalog(t, validCatalogJSON)
	cat, err := sinks.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	headers := cat.GroupHeaders()
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	if headers[0].ID != "attestation" {
		t.Fatalf("got %q", headers[0].ID)
	}
	if headers[0].Description == "" {
		t.Fatal("expected non-empty description")
	}
	// Critical: headers must NOT include categories (would blow LLM context)
	if len(headers[0].Categories) != 0 {
		t.Fatalf("GroupHeaders must strip categories, got %d", len(headers[0].Categories))
	}
}
```

- [ ] **Step 3.2: Run tests, see compile failure (RED)**

Run: `go test ./internal/planner/sinks/ -v`
Expected: compile error — `undefined: sinks.Load`, etc.

- [ ] **Step 3.3: Implement loader.go**

Create `internal/planner/sinks/loader.go`:

```go
package sinks

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads and validates a sink catalog JSON file.
func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sink catalog %s: %w", path, err)
	}
	var cat Catalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse sink catalog %s: %w", path, err)
	}
	if err := cat.Validate(); err != nil {
		return nil, fmt.Errorf("validate sink catalog %s: %w", path, err)
	}
	return &cat, nil
}

// Validate checks the catalog conforms to the v2 schema.
func (c *Catalog) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version: got %q, want %q", c.SchemaVersion, SchemaVersion)
	}
	if c.Language == "" {
		return fmt.Errorf("language: required")
	}
	if len(c.Groups) == 0 {
		return fmt.Errorf("groups: at least one required")
	}
	seenGroups := map[string]bool{}
	for i, g := range c.Groups {
		if g.ID == "" {
			return fmt.Errorf("groups[%d].id: required", i)
		}
		if seenGroups[g.ID] {
			return fmt.Errorf("groups[%d].id: duplicate %q", i, g.ID)
		}
		seenGroups[g.ID] = true
		if g.Description == "" {
			return fmt.Errorf("groups[%d].description: required", i)
		}
		if len(g.Categories) == 0 {
			return fmt.Errorf("groups[%d].categories: at least one required", i)
		}
		seenCats := map[string]bool{}
		for j, cat := range g.Categories {
			if cat.ID == "" {
				return fmt.Errorf("groups[%d].categories[%d].id: required", i, j)
			}
			if seenCats[cat.ID] {
				return fmt.Errorf("groups[%d].categories[%d].id: duplicate %q in group", i, j, cat.ID)
			}
			seenCats[cat.ID] = true
			if cat.Description == "" {
				return fmt.Errorf("groups[%d].categories[%d].description: required", i, j)
			}
			if err := cat.Match.Validate(); err != nil {
				return fmt.Errorf("groups[%d].categories[%d].match: %w", i, j, err)
			}
		}
	}
	return nil
}

// Validate checks a Match conforms to the schema rules:
//   - kind must be "symbol" or "syntax"
//   - kind=symbol requires non-empty symbols and forbids patterns
//   - kind=syntax requires non-empty patterns and forbids symbols
func (m Match) Validate() error {
	switch m.Kind {
	case MatchKindSymbol:
		if len(m.Symbols) == 0 {
			return fmt.Errorf("kind=symbol requires symbols[]")
		}
		if len(m.Patterns) > 0 {
			return fmt.Errorf("kind=symbol cannot have patterns[]")
		}
	case MatchKindSyntax:
		if len(m.Patterns) == 0 {
			return fmt.Errorf("kind=syntax requires patterns[]")
		}
		if len(m.Symbols) > 0 {
			return fmt.Errorf("kind=syntax cannot have symbols[]")
		}
	case "":
		return fmt.Errorf("kind: required (symbol or syntax)")
	default:
		return fmt.Errorf("kind: unknown %q (must be symbol or syntax)", m.Kind)
	}
	return nil
}

// LookupGroup returns the Group with the given ID, or an error.
func (c *Catalog) LookupGroup(id string) (*Group, error) {
	for i := range c.Groups {
		if c.Groups[i].ID == id {
			return &c.Groups[i], nil
		}
	}
	return nil, fmt.Errorf("group %q not found", id)
}

// LookupCategory returns the Category with the given group + category ID,
// or an error.
func (c *Catalog) LookupCategory(groupID, categoryID string) (*Category, error) {
	g, err := c.LookupGroup(groupID)
	if err != nil {
		return nil, err
	}
	for i := range g.Categories {
		if g.Categories[i].ID == categoryID {
			return &g.Categories[i], nil
		}
	}
	return nil, fmt.Errorf("category %q in group %q not found", categoryID, groupID)
}

// GroupHeaders returns a slice of Groups with their categories stripped,
// suitable for the "*" scope of sink_catalog_lookup. The LLM uses this
// as a table of contents to decide which groups to drill into.
func (c *Catalog) GroupHeaders() []Group {
	out := make([]Group, len(c.Groups))
	for i, g := range c.Groups {
		out[i] = Group{
			ID:          g.ID,
			Description: g.Description,
			// Categories deliberately omitted
		}
	}
	return out
}
```

- [ ] **Step 3.4: Run tests, confirm all pass (GREEN)**

Run: `go test ./internal/planner/sinks/ -v`
Expected: 10 PASS (TestLoad_RustJSONFromKnowledge will SKIP if rust.json missing — but Task 1 must have committed it, so it should run and PASS).

- [ ] **Step 3.5: Commit**

```bash
git add internal/planner/sinks/loader.go internal/planner/sinks/loader_test.go
git commit -m "$(cat <<'EOF'
feat(planner/sinks): add catalog loader and validator

Load(path) reads a v2 sink catalog JSON file and runs full schema
validation: schema_version, language, groups[], unique group IDs,
category fields, and per-Match rules (kind must be symbol or syntax;
each kind enforces its own field shape).

Adds Catalog methods: LookupGroup, LookupCategory, GroupHeaders.
GroupHeaders strips the categories[] field — used by the "*" scope of
sink_catalog_lookup so the LLM gets a table of contents without the
full payload.

Tests cover happy path, file-not-found, wrong schema version, empty
groups, missing match.kind, mismatched match fields, and a real-file
sanity check against knowledge/sinks/rust.json (3 groups, 13 categories
expected).

Part of M2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Symbol glob matcher

**Files:**
- Create: `internal/planner/sinks/matcher_test.go` (FIRST)
- Create: `internal/planner/sinks/matcher.go`

The matcher is M3's prerequisite (reverse_trace will use it), but we land it now in M2 because it's pure logic with no LLM dependency.

- [ ] **Step 4.1: Write matcher tests**

Create `internal/planner/sinks/matcher_test.go`:

```go
package sinks_test

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/sinks"
)

func TestMatchSymbol_ExactMatch(t *testing.T) {
	if !sinks.MatchSymbol("sgx_create_report", "sgx_create_report") {
		t.Fatal("exact match should succeed")
	}
	if sinks.MatchSymbol("sgx_create_report", "sgx_create_report_v2") {
		t.Fatal("exact match should not match suffix")
	}
}

func TestMatchSymbol_TrailingWildcard(t *testing.T) {
	if !sinks.MatchSymbol("sgx_quote_*", "sgx_quote_generate") {
		t.Fatal("trailing * should match suffix")
	}
	if !sinks.MatchSymbol("sgx_quote_*", "sgx_quote_") {
		t.Fatal("trailing * should match empty suffix")
	}
	if sinks.MatchSymbol("sgx_quote_*", "sgx_qu") {
		t.Fatal("trailing * should not match shorter prefix")
	}
}

func TestMatchSymbol_LeadingWildcard(t *testing.T) {
	if !sinks.MatchSymbol("*::verify_quote", "attest::verify_quote") {
		t.Fatal("leading * should match prefix")
	}
	if !sinks.MatchSymbol("*::verify_quote", "::verify_quote") {
		t.Fatal("leading * should match empty prefix")
	}
}

func TestMatchSymbol_DoubleWildcard(t *testing.T) {
	// *::verify_quote* must match attest::verify_quote_extended
	if !sinks.MatchSymbol("*::verify_quote*", "attest::verify_quote_extended") {
		t.Fatal("double * should match prefix and suffix")
	}
	// Also matches just "::verify_quote"
	if !sinks.MatchSymbol("*::verify_quote*", "::verify_quote") {
		t.Fatal("double * should match minimal form")
	}
}

func TestMatchSymbol_MidWildcardNotSupported(t *testing.T) {
	// We only support leading and trailing *. A pattern like
	// "sgx_*_create" with a middle * is not handled — document
	// the limitation explicitly via a test.
	// The matcher should treat the middle * as a literal character,
	// so this should NOT match "sgx_quote_create".
	if sinks.MatchSymbol("sgx_*_create", "sgx_quote_create") {
		t.Fatal("middle * should not be treated as wildcard (v1 limitation)")
	}
}

func TestMatchSymbol_PathSeparators(t *testing.T) {
	// "::" is not special — it's just literal characters in a glob.
	if !sinks.MatchSymbol("attest::*::verify*", "attest::sgx::verify_quote") {
		t.Fatal("multi-segment glob should work")
	}
}

func TestMatchAny_FirstHit(t *testing.T) {
	// MatchAny returns true if any glob in the slice matches.
	globs := []string{"foo_*", "bar_*", "baz_*"}
	if !sinks.MatchAny(globs, "bar_thing") {
		t.Fatal("MatchAny should hit middle glob")
	}
	if sinks.MatchAny(globs, "qux_thing") {
		t.Fatal("MatchAny should miss when no glob matches")
	}
	if sinks.MatchAny(nil, "anything") {
		t.Fatal("MatchAny on nil should return false")
	}
}

func TestMatchSymbol_EmptyGlob(t *testing.T) {
	// Empty glob is a degenerate case — it matches only an empty symbol.
	if !sinks.MatchSymbol("", "") {
		t.Fatal("empty matches empty")
	}
	if sinks.MatchSymbol("", "anything") {
		t.Fatal("empty should not match non-empty")
	}
}
```

- [ ] **Step 4.2: Run tests, see compile failure**

Run: `go test ./internal/planner/sinks/ -run TestMatch -v`
Expected: `undefined: sinks.MatchSymbol` / `undefined: sinks.MatchAny`.

- [ ] **Step 4.3: Implement matcher.go**

Create `internal/planner/sinks/matcher.go`:

```go
package sinks

import "strings"

// MatchSymbol reports whether `symbol` matches `glob`. The glob syntax
// is intentionally restricted in v1:
//
//   - A leading `*` matches any prefix (including empty).
//   - A trailing `*` matches any suffix (including empty).
//   - Both leading and trailing `*` may be present.
//   - Any other `*` (in the middle of the pattern) is treated as a
//     literal `*` character. This keeps the matcher predictable and
//     avoids the LLM accidentally writing globs that match too much.
//
// Examples:
//
//	"sgx_create_report"   matches only "sgx_create_report"
//	"sgx_quote_*"         matches "sgx_quote_generate", "sgx_quote_"
//	"*::verify_quote"     matches "attest::verify_quote", "::verify_quote"
//	"*::verify_quote*"    matches "attest::verify_quote_extended"
//	"sgx_*_create"        matches NOTHING containing a `*` (literal)
//
// The matcher is case-sensitive — Rust symbols are case-sensitive and
// the catalog should preserve case.
func MatchSymbol(glob, symbol string) bool {
	leading := strings.HasPrefix(glob, "*")
	trailing := strings.HasSuffix(glob, "*")
	core := glob
	if leading {
		core = core[1:]
	}
	if trailing && len(core) > 0 {
		core = core[:len(core)-1]
	}

	switch {
	case leading && trailing:
		return strings.Contains(symbol, core)
	case leading:
		return strings.HasSuffix(symbol, core)
	case trailing:
		return strings.HasPrefix(symbol, core)
	default:
		return symbol == core
	}
}

// MatchAny reports whether any glob in the slice matches the symbol.
func MatchAny(globs []string, symbol string) bool {
	for _, g := range globs {
		if MatchSymbol(g, symbol) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4.4: Run tests, confirm all pass**

Run: `go test ./internal/planner/sinks/ -run TestMatch -v`
Expected: 8 PASS.

Also run the full sinks package: `go test ./internal/planner/sinks/`
Expected: all PASS (loader + matcher).

- [ ] **Step 4.5: Commit**

```bash
git add internal/planner/sinks/matcher.go internal/planner/sinks/matcher_test.go
git commit -m "$(cat <<'EOF'
feat(planner/sinks): add symbol glob matcher

MatchSymbol implements a deliberately restricted glob syntax:
  - leading * matches any prefix
  - trailing * matches any suffix
  - both leading and trailing * → contains check
  - anywhere else, * is treated as a literal character

This avoids the LLM accidentally writing globs that match the entire
codebase (the classic "*" disaster). MatchAny iterates a slice of
globs and returns true on the first hit.

Tests cover exact, leading, trailing, both, mid-* (literal),
multi-segment paths, MatchAny, and the empty-glob edge case.

Part of M2. Used by reverse_trace in M3.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Add `go-tree-sitter` dependency

**Files:**
- Modify: `go.mod`, `go.sum`

This is a one-shot dependency add. The dependency was smoke-tested on the dev machine (Linux x64) before this plan was written; cgo builds cleanly without manual C library setup.

- [ ] **Step 5.1: Add the dependency**

Run from `tee-usage-scanner/`:

```bash
go get github.com/smacker/go-tree-sitter@v0.0.0-20240827094217-dd81d9e9be82
go get github.com/smacker/go-tree-sitter/rust@v0.0.0-20240827094217-dd81d9e9be82
```

- [ ] **Step 5.2: Verify the module builds**

Run: `go build ./...`
Expected: exit 0. cgo will compile the C parser the first time; this can take 30-60 seconds. Subsequent builds use the cache.

If the build fails with cgo errors, **STOP and escalate to the controller**. Do not attempt to fix cgo issues yourself — the spec calls out that M2 is the "highest technical risk milestone" precisely for this reason. Failure here triggers a tooling revisit, not a workaround.

- [ ] **Step 5.3: Tidy and commit**

```bash
go mod tidy
git add go.mod go.sum
git commit -m "$(cat <<'EOF'
chore(deps): add go-tree-sitter for M2 outline action

Adds github.com/smacker/go-tree-sitter and its rust subpackage. The
binding uses cgo to wrap the upstream tree-sitter C library; smoke
test on Linux x64 (the dev machine) verified the build is clean
without manual C library setup.

Used by internal/planner/actions/tree_sitter_outline.go to extract
function/struct/impl/use declarations from Rust source files.

Part of M2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: tree_sitter_outline action

**Files:**
- Create: `internal/planner/actions/tree_sitter_outline_test.go` (FIRST)
- Create: `internal/planner/actions/tree_sitter_outline.go`

- [ ] **Step 6.1: Write the outline tests**

Create `internal/planner/actions/tree_sitter_outline_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func outlineArgs(t *testing.T, path string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"path": path})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const sampleRust = `use core::ffi::c_void;
use std::ptr;

extern "C" {
    fn sgx_create_report(p: *const u8) -> u32;
}

#[no_mangle]
pub unsafe fn verify_quote(quote: &[u8]) -> Result<(), Error> {
    Ok(())
}

pub fn safe_helper(x: u64) -> u64 {
    x + 1
}

pub struct AttestationVerifier {
    pub mr_enclave: [u8; 32],
}

impl AttestationVerifier {
    pub fn new() -> Self {
        Self { mr_enclave: [0; 32] }
    }
    pub fn verify(&self, quote: &[u8]) -> bool {
        true
    }
}
`

func TestTreeSitterOutline_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "attest.rs"), []byte(sampleRust), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "attest.rs"),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}

	// The outline should mention every top-level construct.
	wants := []string{
		"use_declaration",
		"foreign_mod_item",
		"function_item",
		"verify_quote",
		"safe_helper",
		"struct_item",
		"AttestationVerifier",
		"impl_item",
	}
	for _, w := range wants {
		if !strings.Contains(result.Output, w) {
			t.Errorf("expected outline to mention %q, output:\n%s", w, result.Output)
		}
	}
}

func TestTreeSitterOutline_LineNumbersIncluded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte(sampleRust), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "a.rs"),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("error: %s", result.Error)
	}
	// Output should include "line N" annotations so the LLM can reference rows.
	if !strings.Contains(result.Output, "line ") {
		t.Fatalf("expected line annotations, got: %s", result.Output)
	}
}

func TestTreeSitterOutline_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "empty.rs"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "empty.rs"),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("error: %s", result.Error)
	}
	// Output may be empty or a header, but should not error.
}

func TestTreeSitterOutline_RejectsNonRust(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.py"), []byte("def x(): pass"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "f.py"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for non-Rust file")
	}
	if !strings.Contains(result.Error, "rust") && !strings.Contains(result.Error, ".rs") {
		t.Fatalf("expected rust extension error, got: %s", result.Error)
	}
}

func TestTreeSitterOutline_NotFound(t *testing.T) {
	dir := t.TempDir()

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "missing.rs"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for missing file")
	}
}

func TestTreeSitterOutline_EscapeRejected(t *testing.T) {
	dir := t.TempDir()

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "../escape.rs"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
}
```

- [ ] **Step 6.2: Run tests, see compile failure**

Run: `go test ./internal/planner/actions/ -run TestTreeSitterOutline -v`
Expected: `undefined: actions.TreeSitterOutlineHandler`.

- [ ] **Step 6.3: Implement tree_sitter_outline.go**

Create `internal/planner/actions/tree_sitter_outline.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

type treeSitterOutlineArgs struct {
	Path string `json:"path"`
}

// TreeSitterOutlineHandler extracts a structural outline (functions,
// structs, impls, use declarations, extern blocks) from a Rust source
// file using tree-sitter. Output is one line per top-level item with
// the node type, line number, and a truncated snippet.
//
// The action accepts only files with a `.rs` extension. Non-Rust files
// return an error so the LLM can fall back to read_file or ripgrep.
type TreeSitterOutlineHandler struct{}

func (TreeSitterOutlineHandler) Name() string { return "tree_sitter_outline" }

func (TreeSitterOutlineHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args treeSitterOutlineArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("tree_sitter_outline", fmt.Sprintf("invalid args: %v", err))
	}
	if !strings.HasSuffix(strings.ToLower(args.Path), ".rs") {
		return fail("tree_sitter_outline", fmt.Sprintf("only .rs files supported (got %s)", args.Path))
	}

	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("tree_sitter_outline", err.Error())
	}
	info, err := os.Stat(full)
	if err != nil {
		return fail("tree_sitter_outline", err.Error())
	}
	if info.IsDir() {
		return fail("tree_sitter_outline", fmt.Sprintf("%s is a directory", args.Path))
	}

	src, err := os.ReadFile(full)
	if err != nil {
		return fail("tree_sitter_outline", err.Error())
	}

	parser := sitter.NewParser()
	parser.SetLanguage(rust.GetLanguage())
	tree, err := parser.ParseCtx(ctx, nil, src)
	if err != nil {
		return fail("tree_sitter_outline", fmt.Sprintf("tree-sitter parse: %v", err))
	}
	defer tree.Close()

	var buf strings.Builder
	root := tree.RootNode()
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		emitOutlineNode(child, src, &buf)
	}

	return ActionResult{
		Name:   "tree_sitter_outline",
		OK:     true,
		Output: buf.String(),
	}
}

// outlineNodeKinds is the set of top-level Rust node types we surface
// in the outline. Other node types (comments, attribute_item alone,
// macros) are skipped because they would clutter the LLM's view.
var outlineNodeKinds = map[string]bool{
	"function_item":           true,
	"struct_item":             true,
	"enum_item":               true,
	"impl_item":               true,
	"trait_item":              true,
	"foreign_mod_item":        true,
	"use_declaration":         true,
	"mod_item":                true,
	"const_item":              true,
	"static_item":             true,
	"type_item":               true,
}

func emitOutlineNode(node *sitter.Node, src []byte, buf *strings.Builder) {
	t := node.Type()
	if !outlineNodeKinds[t] {
		return
	}
	startLine := node.StartPoint().Row + 1
	endLine := node.EndPoint().Row + 1
	snippet := nodeSnippet(node, src)
	fmt.Fprintf(buf, "[%s] line %d-%d: %s\n", t, startLine, endLine, snippet)

	// For impl blocks, also surface inner functions one level deep.
	if t == "impl_item" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "declaration_list" {
				for j := 0; j < int(ch.ChildCount()); j++ {
					inner := ch.Child(j)
					if inner.Type() == "function_item" {
						innerStart := inner.StartPoint().Row + 1
						innerEnd := inner.EndPoint().Row + 1
						innerSnippet := nodeSnippet(inner, src)
						fmt.Fprintf(buf, "  [function_item] line %d-%d: %s\n", innerStart, innerEnd, innerSnippet)
					}
				}
			}
		}
	}
}

// nodeSnippet returns the first line of a node's source text, truncated
// to 100 chars. Used as a one-line summary in the outline output.
func nodeSnippet(node *sitter.Node, src []byte) string {
	text := string(src[node.StartByte():node.EndByte()])
	// Take the first non-empty line
	lines := strings.SplitN(text, "\n", 2)
	first := strings.TrimSpace(lines[0])
	if len(first) > 100 {
		first = first[:100] + "..."
	}
	return first
}
```

- [ ] **Step 6.4: Run tests, confirm all pass**

Run: `go test ./internal/planner/actions/ -run TestTreeSitterOutline -v`
Expected: 6 PASS.

If any FAIL, do NOT modify the test expectations — fix the implementation. If the failure is a tree-sitter cgo issue at runtime (segfault, library not loaded), STOP and escalate.

- [ ] **Step 6.5: Commit**

```bash
git add internal/planner/actions/tree_sitter_outline.go internal/planner/actions/tree_sitter_outline_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add tree_sitter_outline action

Parses a Rust source file with tree-sitter and emits a structural
outline of top-level items: function_item, struct_item, enum_item,
impl_item, trait_item, foreign_mod_item, use_declaration, mod_item,
const_item, static_item, type_item. impl blocks are walked one level
deep to surface inner methods.

Each output line includes the node type, line range, and a truncated
single-line snippet so the LLM can identify and reference items
without re-reading the whole file.

Non-.rs paths are rejected with an explicit error so the LLM can fall
back to read_file. Sandbox ResolvePath enforces escape/symlink
rejection before parsing.

Part of M2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: sink_catalog_lookup action

**Files:**
- Create: `internal/planner/actions/sink_catalog_lookup_test.go` (FIRST)
- Create: `internal/planner/actions/sink_catalog_lookup.go`

The handler is constructed with an explicit catalog path. The default registry constructor in Task 8 will wire it up.

- [ ] **Step 7.1: Write the lookup tests**

Create `internal/planner/actions/sink_catalog_lookup_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

const testCatalogJSON = `{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "remote attestation chain",
      "categories": [
        {
          "id": "verify",
          "description": "verify entry points",
          "match": { "kind": "symbol", "symbols": ["*::verify_quote"] },
          "severity_hint": "high"
        }
      ]
    },
    {
      "id": "key_lifecycle",
      "description": "key generation and use",
      "categories": [
        {
          "id": "generation",
          "description": "key generation",
          "match": { "kind": "symbol", "symbols": ["KeyPair::generate"] },
          "severity_hint": "high"
        }
      ]
    }
  ]
}`

func writeTestCatalog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rust.json")
	if err := os.WriteFile(path, []byte(testCatalogJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func lookupArgs(t *testing.T, scope string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"scope": scope})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSinkCatalogLookup_AllScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "*"),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	// "*" returns group headers only — both groups present, no categories.
	if !strings.Contains(result.Output, "attestation") {
		t.Fatalf("expected attestation, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "key_lifecycle") {
		t.Fatalf("expected key_lifecycle, got: %s", result.Output)
	}
	// Categories must NOT be in the all-scope output.
	if strings.Contains(result.Output, "verify_quote") {
		t.Fatalf("'*' scope leaked category details: %s", result.Output)
	}
}

func TestSinkCatalogLookup_GroupScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "attestation"),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	// Group scope returns the group with all its categories.
	if !strings.Contains(result.Output, "verify") {
		t.Fatalf("expected verify category, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "*::verify_quote") {
		t.Fatalf("expected match patterns in group scope, got: %s", result.Output)
	}
	// Other groups should not be included.
	if strings.Contains(result.Output, "key_lifecycle") {
		t.Fatalf("group scope leaked other groups: %s", result.Output)
	}
}

func TestSinkCatalogLookup_CategoryScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "attestation.verify"),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "*::verify_quote") {
		t.Fatalf("expected verify pattern, got: %s", result.Output)
	}
	// Other categories from the same group should not appear.
	if strings.Contains(result.Output, "key_lifecycle") {
		t.Fatalf("category scope leaked other groups: %s", result.Output)
	}
}

func TestSinkCatalogLookup_UnknownGroup(t *testing.T) {
	path := writeTestCatalog(t)

	h := actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "nonexistent"),
	})
	if result.OK {
		t.Fatal("expected failure for unknown group")
	}
}

func TestSinkCatalogLookup_UnknownCategory(t *testing.T) {
	path := writeTestCatalog(t)

	h := actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "attestation.nonexistent"),
	})
	if result.OK {
		t.Fatal("expected failure for unknown category")
	}
}

func TestSinkCatalogLookup_EmptyScope(t *testing.T) {
	path := writeTestCatalog(t)

	h := actions.SinkCatalogLookupHandler{CatalogPath: path}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, ""),
	})
	if result.OK {
		t.Fatal("expected failure for empty scope")
	}
}

func TestSinkCatalogLookup_MissingCatalog(t *testing.T) {
	h := actions.SinkCatalogLookupHandler{CatalogPath: "/nonexistent/path.json"}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: lookupArgs(t, "*"),
	})
	if result.OK {
		t.Fatal("expected failure when catalog file missing")
	}
}
```

- [ ] **Step 7.2: Run tests, see compile failure**

Run: `go test ./internal/planner/actions/ -run TestSinkCatalogLookup -v`
Expected: `undefined: actions.SinkCatalogLookupHandler`.

- [ ] **Step 7.3: Implement sink_catalog_lookup.go**

Create `internal/planner/actions/sink_catalog_lookup.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/sinks"
)

type sinkCatalogLookupArgs struct {
	Scope string `json:"scope"`
}

// SinkCatalogLookupHandler implements sink_catalog_lookup. The LLM
// uses three scope levels:
//
//   - "*"               → group headers only (table of contents)
//   - "<group_id>"      → full group with all its categories
//   - "<group_id>.<cat>" → a single category definition
//
// The handler caches the parsed catalog after the first successful
// load. CatalogPath must be set before Run is called; the registry
// helper in registry_with_sinks.go wires this from the knowledge root.
type SinkCatalogLookupHandler struct {
	CatalogPath string

	// cached catalog after first successful Load
	cached *sinks.Catalog
}

func (h *SinkCatalogLookupHandler) Name() string { return "sink_catalog_lookup" }

func (h *SinkCatalogLookupHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args sinkCatalogLookupArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("sink_catalog_lookup", fmt.Sprintf("invalid args: %v", err))
	}
	if strings.TrimSpace(args.Scope) == "" {
		return fail("sink_catalog_lookup", "scope is required (use \"*\", a group id, or group.category)")
	}
	cat, err := h.catalog()
	if err != nil {
		return fail("sink_catalog_lookup", err.Error())
	}

	var payload any
	switch {
	case args.Scope == "*":
		payload = cat.GroupHeaders()
	case strings.Contains(args.Scope, "."):
		parts := strings.SplitN(args.Scope, ".", 2)
		c, err := cat.LookupCategory(parts[0], parts[1])
		if err != nil {
			return fail("sink_catalog_lookup", err.Error())
		}
		payload = c
	default:
		g, err := cat.LookupGroup(args.Scope)
		if err != nil {
			return fail("sink_catalog_lookup", err.Error())
		}
		payload = g
	}

	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fail("sink_catalog_lookup", fmt.Sprintf("marshal: %v", err))
	}
	return ActionResult{
		Name:   "sink_catalog_lookup",
		OK:     true,
		Output: string(out),
	}
}

// catalog returns the cached catalog, loading it on first call.
func (h *SinkCatalogLookupHandler) catalog() (*sinks.Catalog, error) {
	if h.cached != nil {
		return h.cached, nil
	}
	cat, err := sinks.Load(h.CatalogPath)
	if err != nil {
		return nil, err
	}
	h.cached = cat
	return cat, nil
}
```

- [ ] **Step 7.4: Run tests, confirm all pass**

Run: `go test ./internal/planner/actions/ -run TestSinkCatalogLookup -v`
Expected: 7 PASS.

- [ ] **Step 7.5: Commit**

```bash
git add internal/planner/actions/sink_catalog_lookup.go internal/planner/actions/sink_catalog_lookup_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add sink_catalog_lookup action

Implements three scope levels for the LLM to query the sink catalog:
  - "*"                → group headers only (~300 tokens)
  - "<group>"          → full group with categories (~1.5k tokens)
  - "<group>.<cat>"    → single category definition (~300 tokens)

Catalog is loaded once on first call and cached on the handler. The
handler is stateful (CatalogPath field + cache), so callers should
share a single instance via the registry rather than constructing per
request.

Output is JSON pretty-printed for LLM readability.

Tests cover all three scopes, unknown group, unknown category, empty
scope, and missing catalog file.

Part of M2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Registry helper for M2 actions

**Files:**
- Create: `internal/planner/actions/registry_with_sinks.go`
- Modify: `internal/planner/actions/registry_test.go` (add tests for the new helper)

The base `NewDefaultRegistry()` from M1 stays unchanged for backward compatibility. M2 adds a new constructor that wires up the M2 actions plus a catalog path.

- [ ] **Step 8.1: Add tests for the new registry helper**

Append to `internal/planner/actions/registry_test.go` (do not modify the existing M1 tests):

```go
func TestNewDefaultRegistryWithSinks_RegistersM2Actions(t *testing.T) {
	dir := t.TempDir()
	catalog := filepath.Join(dir, "rust.json")
	if err := os.WriteFile(catalog, []byte(testCatalogJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := actions.NewDefaultRegistryWithSinks(catalog)
	names := reg.Names()
	want := map[string]bool{
		"list_dir":            true,
		"read_file":           true,
		"ripgrep":             true,
		"tree_sitter_outline": true,
		"sink_catalog_lookup": true,
	}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) > 0 {
		t.Fatalf("registry missing handlers: %v", want)
	}
}

func TestNewDefaultRegistryWithSinks_LookupWorksEndToEnd(t *testing.T) {
	dir := t.TempDir()
	catalog := filepath.Join(dir, "rust.json")
	if err := os.WriteFile(catalog, []byte(testCatalogJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := actions.NewDefaultRegistryWithSinks(catalog)
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name: "sink_catalog_lookup",
		Args: json.RawMessage(`{"scope": "*"}`),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "attestation") {
		t.Fatalf("expected attestation in output, got: %s", result.Output)
	}
}
```

- [ ] **Step 8.2: Run tests, see compile failure**

Run: `go test ./internal/planner/actions/ -run TestNewDefaultRegistryWithSinks -v`
Expected: `undefined: actions.NewDefaultRegistryWithSinks`.

- [ ] **Step 8.3: Implement registry_with_sinks.go**

Create `internal/planner/actions/registry_with_sinks.go`:

```go
package actions

// NewDefaultRegistryWithSinks returns a registry pre-populated with
// the M1 read-only actions (list_dir, read_file, ripgrep) plus the
// M2 actions (tree_sitter_outline, sink_catalog_lookup).
//
// The catalogPath argument is the on-disk location of the sink
// catalog JSON file (typically `knowledge/sinks/rust.json`). It is
// stored on the SinkCatalogLookupHandler instance and lazy-loaded on
// first use, so a missing or invalid file is reported as an action
// error rather than a constructor panic.
func NewDefaultRegistryWithSinks(catalogPath string) *Registry {
	r := NewDefaultRegistry()
	r.Register(TreeSitterOutlineHandler{})
	// SinkCatalogLookupHandler caches state, so we register a pointer
	// rather than a value receiver.
	r.Register(&SinkCatalogLookupHandler{CatalogPath: catalogPath})
	return r
}
```

- [ ] **Step 8.4: Run tests**

Run: `go test ./internal/planner/actions/ -run TestNewDefaultRegistryWithSinks -v`
Expected: 2 PASS.

Also run the full actions package: `go test ./internal/planner/actions/`
Expected: all PASS (M1 + M2 tests).

- [ ] **Step 8.5: Commit**

```bash
git add internal/planner/actions/registry_with_sinks.go internal/planner/actions/registry_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add NewDefaultRegistryWithSinks helper

Extends the M1 NewDefaultRegistry with the two M2 actions:
tree_sitter_outline and sink_catalog_lookup. The catalog path is
passed in and stored on the SinkCatalogLookupHandler instance for
lazy loading.

The original NewDefaultRegistry from M1 is left unchanged for
backward compatibility — the planner main loop in M3 will call
NewDefaultRegistryWithSinks instead.

Part of M2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Full-package test sweep

**Files:** None — verification only.

- [ ] **Step 9.1: Run all M2 package tests**

Run: `go test ./internal/planner/...`
Expected: all PASS, no skips on Linux.

- [ ] **Step 9.2: Run the full project test suite**

Run: `go test ./...`
Expected: no new failures. cgo compile may add 30-60s on first run.

- [ ] **Step 9.3: go vet**

Run: `go vet ./...`
Expected: exit 0.

- [ ] **Step 9.4: Build the binary**

Run: `go build -o /tmp/teecheck-m2 ./cmd/teecheck/`
Expected: exit 0, binary produced. Smoke check, no commit.

- [ ] **Step 9.5: Smoke-run the catalog loader against the real rust.json**

Run a tiny inline script:

```bash
cd tee-usage-scanner && go run -tags m2smoke - <<'EOF' 2>&1 || true
package main

import (
	"fmt"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/sinks"
)

func main() {
	cat, err := sinks.Load("knowledge/sinks/rust.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d groups, %d categories\n",
		len(cat.Groups),
		func() int {
			n := 0
			for _, g := range cat.Groups {
				n += len(g.Categories)
			}
			return n
		}())
	for _, g := range cat.Groups {
		fmt.Printf("  - %s (%d categories)\n", g.ID, len(g.Categories))
	}
}
EOF
```

This is a one-shot Go run (no file written). Expected output:

```
Loaded 3 groups, 13 categories
  - attestation (4 categories)
  - tee_platform_syscalls (3 categories)
  - key_lifecycle (6 categories)
```

If counts differ, M2 has a bug — escalate.

- [ ] **Step 9.6: Mark M2 complete**

Reply: "M2 complete. Ready for M3 planning."

---

## Post-M2

After M2 lands, request an M3 plan covering:

- `internal/planner/planner.go` — main planner loop with state machine (SEEDED → PLANNING → EXECUTING → OBSERVING → DONE)
- `internal/planner/state.go` — `PlannerState` + persistence to `04_planner/rounds.jsonl`
- `internal/planner/prompt.go` — system prompt builder + per-round prompt assembly
- `internal/planner/budget.go` — 4-dimensional budget (max_rounds / max_tokens / per-action timeout / wall clock)
- `internal/planner/loop_detect.go` — repetition + stall detection
- `internal/planner/actions/reverse_trace.go` — BFS backward through call sites using tree-sitter
- `internal/planner/actions/legacy_keyword_scan.go` — wraps current mapper + hotspots
- `internal/planner/actions/repomix_summarize.go` — wraps existing internal/repomix
- `internal/planner/actions/done.go` — terminal action
- `internal/planner/planner_integration_test.go` — mocked-LLM end-to-end test

M3 has no new external dependencies — everything is built on top of M1 + M2 primitives.
