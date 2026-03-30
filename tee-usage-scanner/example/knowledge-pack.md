# GitNexus Knowledge Pack

Focus: `tee`

Graph export: `fixtures/gitnexus/sample_graph.json`

Source tree: `/tmp/project`

## Overview

- The imported GitNexus graph contains 3 nodes and 3 edges.
- Focus area "tee" currently points to 1 likely files and 2 likely symbols for review.
- Top file hotspot: verify.js. Top symbol hotspot: verifyQeIdentityPolicy.
- This MVP consumes exported graph structure and does not yet call a live GitNexus backend. Use it as compressed context for AI review, not as a vulnerability verdict.

## Relevant Files

- `verify.js` (src/verify.js) score=5: matches 1 focus keyword(s) and has high graph connectivity

## Relevant Symbols

- `verifyQeIdentityPolicy` (src/verify.js) score=11: matches 3 focus keyword(s) and has high graph connectivity
- `sessionCheck` (src/session.js) score=5: matches 1 focus keyword(s) and has high graph connectivity

## Audit Questions

- Which modules or entrypoints appear to cross a trust boundary between trusted and untrusted worlds?
- Which high-connectivity files look responsible for attestation, key handling, command dispatch, or session state?
- Do any hotspot symbols look like they make trust decisions without nearby verification or binding logic?
- Where should a human reviewer start if they want to validate session binding, attestation validation, or insecure fallback behavior?

## Analyst Notes

- GitNexus is treated as a structure compressor in this MVP.
- Candidates are heuristic hotspots based on graph degree plus focus keywords.
- AI should reason over these hotspots together with TEE misuse skills and original code snippets.
