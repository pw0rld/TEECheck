# GitNexus Knowledge Pack

Focus: `runtime`

Graph export: `reports/oasis-sdk-gitnexus-graph.json`

Source tree: `/Users/pw0rld/Desktop/TEENET/TEECheck/oasis-sdk`

## Overview

- The imported GitNexus graph contains 9623 nodes and 23899 edges.
- Focus area "runtime" currently points to 8 likely files and 8 likely symbols for review.
- Top file hotspot: types.ts. Top symbol hotspot: with.
- This MVP consumes exported graph structure and does not yet call a live GitNexus backend. Use it as compressed context for AI review, not as a vulnerability verdict.

## Relevant Files

- `types.ts` (client-sdk/ts-web/core/src/types.ts) score=287: high graph connectivity
- `types.ts` (client-sdk/ts-web/rt/src/types.ts) score=218: high graph connectivity
- `client.ts` (client-sdk/ts-web/core/src/client.ts) score=202: high graph connectivity
- `state.rs` (runtime-sdk/src/state.rs) score=135: matches 1 focus keyword(s) and has high graph connectivity
- `mod.rs` (runtime-sdk/src/modules/core/mod.rs) score=119: matches 1 focus keyword(s) and has high graph connectivity
- `types.go` (client-sdk/go/modules/roflmarket/types.go) score=107: high graph connectivity
- `types.rs` (runtime-sdk/modules/rofl-market/src/types.rs) score=100: matches 1 focus keyword(s) and has high graph connectivity
- `mod.rs` (runtime-sdk/src/modules/accounts/mod.rs) score=100: matches 1 focus keyword(s) and has high graph connectivity

## Relevant Symbols

- `with` (runtime-sdk/src/state.rs) score=160: matches 1 focus keyword(s) and has high graph connectivity
- `with_store` (runtime-sdk/src/state.rs) score=152: matches 1 focus keyword(s) and has high graph connectivity
- `NodeInternal` (client-sdk/ts-web/core/src/client.ts) score=135: high graph connectivity
- `callUnary` (client-sdk/ts-web/core/src/client.ts) score=127: high graph connectivity
- `from_slice` (contract-sdk/src/memory.rs) score=120: high graph connectivity
- `ok_or` (runtime-sdk/src/module.rs) score=114: matches 1 focus keyword(s) and has high graph connectivity
- `with_transaction_opts` (runtime-sdk/src/state.rs) score=101: matches 1 focus keyword(s) and has high graph connectivity
- `with_env` (runtime-sdk/src/state.rs) score=95: matches 1 focus keyword(s) and has high graph connectivity

## Audit Questions

- Which files and symbols look most central to the selected focus area?
- Which hotspots deserve manual review first?

## Analyst Notes

- GitNexus is treated as a structure compressor in this MVP.
- Candidates are heuristic hotspots based on graph degree plus focus keywords.
- AI should reason over these hotspots together with TEE misuse skills and original code snippets.
