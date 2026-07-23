# CodeQL bootstrap notes for TEE×Web3

## Purpose
Use this file as the stage-4 source of truth.

Run CodeQL only after the fingerprint, dossier, invariants, and analysis-family matrix exist.

CodeQL is one required deterministic lane for supported languages. It is not the whole audit.

## Completion rule

If the repo's trust-relevant language is visible in `codeql resolve languages`, the audit is not complete until:

1. preflight succeeds
2. full database creation succeeds
3. at least one baseline suite produces SARIF

Preflight or smoke checks do not count as completed coverage.

## What a CodeQL database is
A CodeQL database is an extracted representation of the repository for one language. Queries run against that database.

## Required workflow

1. ensure `codeql` is installed
2. ensure the language is actually supported locally
3. choose a bounded artifact root such as `/tmp/tee-web3-audit`
4. run helper preflight
5. create a clean database in full mode
6. run a baseline query suite
7. record the exact command, output path, and summary
8. map baseline results and invariant-derived requirements into small deterministic rule candidates

## Helper modes

- `--mode preflight` validates environment, language support, source root, and artifact paths
- `--mode smoke` is optional and does not count as completed coverage
- `--mode full` is the only mode that counts toward baseline completion

If a prior database path already exists, fail loudly unless the operator explicitly requests a clean rerun.

For Rust workspaces, prefer isolating extractor Cargo state under the artifact root so one machine's shared Cargo cache does not change another audit's outcome.

Use `CARGO_NET_OFFLINE=true` only when the needed registry and git data is already available locally. Do not make offline mode the default for repos that still need dependency metadata resolution.

## Example Rust-first commands
```bash
bash .agents/skills/tee-web3-audit/scripts/create_codeql_db.sh \
  --mode preflight \
  <repo> rust <source-root> /tmp/tee-web3-audit

bash .agents/skills/tee-web3-audit/scripts/create_codeql_db.sh \
  --mode full \
  --force \
  <repo> rust <source-root> /tmp/tee-web3-audit

bash .agents/skills/tee-web3-audit/scripts/run_baseline_scan.sh \
  --force \
  /tmp/tee-web3-audit/codeql-dbs/<repo>-rust \
  codeql/rust-queries:codeql-suites/rust-security-and-quality.qls \
  /tmp/tee-web3-audit/results/<repo>-rust-baseline.sarif
```

## Use baseline analysis to answer
- Does the extraction succeed?
- What ordinary security/quality results appear?
- Which TEE×Web3 guard, binding, lifecycle, or flow rules should be added next?

## Failure discipline

- Do not claim baseline coverage from timed-out extraction, partial databases, or preflight-only runs.
- Do not reuse stale or partial databases unless you intentionally clean and recreate them.
- If a supported-language baseline fails, keep the non-CodeQL evidence but mark the audit incomplete.

## When CodeQL is not enough

Even when CodeQL succeeds, use other tools when:

- the property is not well expressed as flow or structural checks
- the property is mostly lifecycle or trust-model reasoning
- the repo contains trust-relevant code outside the supported language

## Supporting references

Pull these in as needed after the baseline path is planned:

- `search-patterns.md`
- `platform-caveats.md`
- `rule-seeds.md`
