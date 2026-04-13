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
