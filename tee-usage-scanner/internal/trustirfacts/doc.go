// Package trustirfacts is the consumption end of the TrustIR-C fact layer
// (docs/TEECHECK_TEE_AUDIT_MERGE.zh-CN.md §6, §23): it builds a per-commit
// CodeQL C/C++ database, materializes a run-scoped copy of the
// codeql/trustir/cpp query pack with a generated fact table, runs the
// thin-shell query through the existing internal/codeql Engine, and
// persists the result as an artifacts.ToolFact.
//
// This is the FIRST SLICE described in §23.2: a deterministic skeleton.
// The fact table is populated from a small hand-authored registry (see
// facttable.go), not from an LLM annotation → resolver pipeline — that
// pipeline is explicitly deferred until this skeleton's DB build, caching,
// execution, and ToolFact status mapping are proven. Only the STATE/rollback
// family (TWE-STATE-001) is implemented; the other six families return
// StatusUnsupported.
//
// The package depends on CodeQL only through the Engine interface (see
// engine.go), never on internal/codeql's concrete Engine type directly, so
// tests can drive it with a canned stub instead of building a real database
// or running a real query — see run_test.go.
package trustirfacts
