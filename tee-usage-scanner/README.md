# TEECheck Harness

`TEECheck` is being rebuilt as a collaborative harness-engineering project for
AI-assisted TEE security research.

This branch intentionally starts with the smallest useful collaborative
harness:

- one design document
- one minimal Go runtime
- one file-based run layout
- one knowledge layer with curated wiki pages
- one end-to-end collaborative path from structure graph to arbiter packet

The system target is a multi-agent review harness, not a one-shot scanner.

Current architectural direction:

- case-driven collaborative agents
- file-based artifact flow
- accumulated knowledge wiki instead of plain chunk-RAG
- human review as a required stage

## Current Focus

The current branch is focused on:

- run orchestration
- artifact contracts
- agent role definitions
- replayable run directories
- human review as a first-class stage

The main design document is:

- `docs/MULTI_AGENT_HARNESS.md`
- `docs/ARCHITECTURE_RESERVATIONS.md`

## Preferred Collaborative CLI

The new preferred path is the collaborative harness flow:

1. initialize or reuse the knowledge layer
2. preprocess the repository into a project profile
3. map repository structure into hotspots
4. build bounded `case_pack` artifacts
5. let `expert`, `challenge`, `verifier`, and `arbiter` collaborate on each case
6. hand the resulting review packets to a human reviewer

One-shot collaborative run:

```bash
go run ./cmd/teecheck knowledge-init \
  --knowledge-root ./knowledge

go run ./cmd/teecheck collab-run \
  --repo-url https://github.com/oasisprotocol/oasis-sdk \
  --local-path /abs/path/to/oasis-sdk \
  --commit 8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76 \
  --graph-json /abs/path/to/graph.json \
  --knowledge-root ./knowledge \
  --focus runtime \
  --run-id oasis-sdk-collab-001 \
  --max-hotspots 12 \
  --max-cases 12
```

This executes:

`knowledge-init -> init-run -> preprocess -> mapper -> cases -> expert -> challenge -> verifier -> arbiter`

Key collaborative outputs:

```text
runs/oasis-sdk-collab-001/
├── 01_profile/project_profile.json
├── 01_repo_map/repo_map.json
├── 02_hotspots/hotspot_index.json
├── 03_cases/
├── 04_expert/
├── 05_challenger/
├── 06_verifier/
└── 07_arbiter/
    ├── packets/
    └── findings.json
```

The repository-level knowledge layer lives outside runs:

```text
knowledge/
├── raw/
├── wiki/
└── learned/
```

## Sample Test Data

The repository includes a tiny synthetic graph and source tree so the harness
can be exercised without external dependencies:

- `testdata/sample_graph.json`
- `testdata/sample_repo/`

The automated test covers:

`knowledge-init -> init-run -> preprocess -> mapper -> cases -> expert -> challenge -> verifier -> arbiter`

## Harness Layout

```text
tee-usage-scanner/
├── cmd/
├── docs/
├── knowledge/
└── internal/
```

## Near-Term Build Order

1. stabilize artifact structs and schemas
2. turn repo structure into `project_profile` and `repo_map`
3. build the first `hotspot_index`
4. generate bounded `case_pack` artifacts
5. let `expert` and `challenge` collaborate over each case
6. use `verifier` to strengthen or weaken the evidence
7. let `arbiter` produce human-facing review packets
8. keep expanding `knowledge/wiki` from reviewed cases

## Current State

The collaborative harness is now the only supported flow in this branch.

Implemented today:

- `knowledge-init`
- `collab-run`
- `init-run`
- `preprocess`
- `mapper`
- `map`
- `hotspots`
- `cases`
- `expert`
- `challenge`
- `verifier`
- `arbiter`

Still intentionally simple:

- `expert`, `challenge`, and `verifier` are heuristic, not yet model-backed
- knowledge lookup is wiki-first and metadata-based
- human review and feedback writeback will be rebuilt on top of the new case
  protocol next
- it is the intended insertion point for stronger static checks later
