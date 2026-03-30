# GitNexus MVP

## Goal

Build the simplest useful pipeline for repository compression:

1. Run GitNexus to produce a repository graph export.
2. Use Go to turn that export into a compact knowledge pack.
3. Feed the knowledge pack plus TEE misuse skills into an LLM.
4. Let a human reviewer validate the resulting audit candidates.

## Why This Differs From Joern

This MVP does not ask the graph backend to decide whether a vulnerability exists.

Instead:

- GitNexus is the structure compressor
- Go is the orchestration layer
- the LLM is the semantic judge
- the human reviewer is the final arbiter

## MVP Shape

### Step A: Repository Compression

GitNexus produces a graph export that captures repository structure such as:

- files and modules
- symbols and functions
- calls and imports
- high-connectivity hotspots

For this repository, the first automation target is an Orb-hosted export flow. The MVP now supports both the raw SSH command and the Go wrapper.

Raw SSH form:

```bash
ssh orb-vscode \
  "node /Users/pw0rld/Desktop/TEENET/TEECheck/tee-usage-scanner/scripts/gitnexus/export_graph.mjs \
    --repo /Users/pw0rld/Desktop/TEENET/TEECheck/dcap-qvl-v038 \
    --out /Users/pw0rld/Desktop/TEENET/TEECheck/tee-usage-scanner/reports/dcap-qvl-gitnexus-graph.json"
```

This uses the cloned GitNexus source on Orb and writes the graph export back into the shared workspace.

Wrapped form:

```bash
go run ./cmd/tee-usage-scanner kgpack \
  --src /Users/pw0rld/Desktop/TEENET/TEECheck/dcap-qvl-v038 \
  --gitnexus-ssh-target orb-vscode \
  --graph-json reports/dcap-qvl-gitnexus-graph.json \
  --focus tee \
  --report reports/dcap-qvl-knowledge-pack.json \
  --prompt reports/dcap-qvl-knowledge-pack.md
```

### Step B: Knowledge Pack

The Go command `kgpack` reads the GitNexus export and emits:

- `reports/knowledge-pack.json`
- `reports/knowledge-pack.md`

These artifacts summarize:

- graph size
- top node and edge types
- relevant files
- relevant symbols
- audit questions for the chosen focus area

### Step C: AI Audit

The LLM should use the knowledge pack together with a TEE misuse skill document to answer:

- which files should be reviewed first
- which trust boundaries look suspicious
- which modules likely make sensitive decisions
- which symbols deserve manual security review

The repository now contains the first pairing for this stage:

- `prompts/gitnexus_tee_audit_prompt.md`
- `skills/tee-usage-audit/SKILL.md`

## OrbStack Assumption

Orb is still useful in this design, but differently from Joern:

- it can host GitNexus or its supporting runtime
- it can generate graph exports for larger repositories
- the Go backend can remain local and consume the exported JSON artifact

For the first MVP, we intentionally stop at exported graph JSON rather than integrating a live GitNexus service protocol.

## Immediate Next Steps

1. Improve the exact GitNexus hotspot heuristics we want to consume for TEE review.
2. Add trust-boundary candidates and audit slices to the knowledge pack.
3. Add a small pack-merging step so the knowledge pack and the TEE audit skill can be handed to Codex with less manual glue.
