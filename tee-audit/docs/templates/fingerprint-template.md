# Project fingerprint template

Use this before the dossier so the audit starts from repo truth.

## 0. Repo identity
- Project name:
- Repo URL:
- Commit / tag audited:
- Primary languages:
- Likely CodeQL coverage:

## 1. TEE and platform shape
- TEE platform(s): SGX / TDX / Nitro / SEV / SNP / mixed / unclear
- Where TEE-specific code appears:
- Where verification appears:
- Where simulation or debug paths appear:

## 2. Web3 role shape
- Project role(s):
  - validator / consensus
  - confidential runtime / coprocessor
  - key manager / signer
  - oracle / bridge
  - watcher / indexer / gateway
  - wallet / client
  - off-chain worker
  - other:
- User-facing security promise:

## 3. Trust artifacts and state surfaces
- Attestation artifacts:
- Identity artifacts:
- State or continuity artifacts:
- Policy or authorization artifacts:

## 4. Build and deployment signals
- Build flags or feature gates:
- Simulation or debug toggles:
- Environment-driven trust inputs:
- Deployment or orchestration assumptions:

## 5. Likely trust boundaries
List the major boundaries and why they matter.

## 6. Likely critical directories and files
List the highest-signal paths for the first pass.

## 7. Tooling recommendation
- Best first-pass tools:
- Coverage gaps:
- Notes:
