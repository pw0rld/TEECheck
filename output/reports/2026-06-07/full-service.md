# TEE Usage Audit Report: full-service

## Executive Summary
This TEE audit identified **2 active vulnerabilities** (1 Critical, 1 High), **4 partially-confirmed positive guards**, and **12 unknown checks** spanning 7 invariant categories. Six findings were dismissed as false positives during adversarial review.

**Active Vulnerabilities:**
- **IV-INV-05 [Config] (Critical)**: Missing SGX HW mode runtime assertion enables enclave execution in simulation mode, bypassing hardware isolation. Remediation: enforce explicit `SGX_MODE=HW` assertion at enclave initialization.
- **IV-INV-12 [Binding] (High)**: MRENCLAVE omitted from attestation identity check weakens enclave binding, allowing potential code substitution. Remediation: bind MRENCLAVE to attestation report identity verification.

**Formally Dismissed:**
- **U-INV-06**: False positive—CLI mnemonic handling does not derive TEE sealing or attestation keys; no TEE-relevant exposure.
- **U-INV-07**: Architectural by-design—signer binary generates key material for enclave provisioning; out-of-enclave operation is standard practice for pre-provisioning tooling.

## Dashboard Summary

| Severity | Trust-Path Tier | Count |
| --- | --- | --- |
| Critical | core | 1 |
| High | core | 1 |

## Trust Boundary Analysis

| Actor | Component | Context | Boundary Type |
| --- | --- | --- | --- |
| MobileCoin | SGX SDK Integration Layer | trusted | build-time |
| SGX Enclave | Key Manager / Signer | trusted | enclave/host |
| Intel SGX Hardware | DCAP Attestation Module | trusted | hardware_roots_of_trust |
| Node Operator | Full-Service Host Binary | untrusted | enclave/host |
| End User | Client API Layer | untrusted | network |
| Node Operator | Mirror Component | untrusted | network |
| Node Operator | Diesel ORM / DB Layer | untrusted | storage |
| MobileCoin Network | MobileCoin Ledger | untrusted | network |

## Trust Boundary Partition Evidence

### Partition Methodology

**Path and content heuristics** classified files by directory patterns (enclave/, host/, trusted/) and TEE API usage (sgx_trts, sgx_urts, attestation).

### Source Code Zone Partition

```
├── full-service/  🟡 Mixed (26 trusted, 30 untrusted, 1 mixed)
│   ├── src/  🟡 Mixed (1 trusted, 1 untrusted, 1 mixed)
│   │   ├── 🟡 config.rs
│   │   ├── 🟢 test_utils.rs
│   │   └── 🔴 check_host.rs
│   ├── src/bin/  🔴 Untrusted (1 file)  — binaries
│   ├── src/db/  🟢 Trusted (6 files)  — database
│   ├── src/json_rpc/  🟢 Trusted (1 file)
│   ├── src/json_rpc/v1/api/  🟢 Trusted (3 files)  — API definitions
│   ├── src/json_rpc/v1/e2e_tests/account/  🟢 Trusted (1 file)
│   ├── src/json_rpc/v1/e2e_tests/account/create_import/  🟢 Trusted (2 files)
│   ├── src/json_rpc/v1/models/  🟢 Trusted (2 files)
│   ├── src/json_rpc/v2/api/  🟢 Trusted (2 files)  — API definitions
│   ├── src/json_rpc/v2/e2e_tests/account/  🟢 Trusted (1 file)
│   ├── src/json_rpc/v2/e2e_tests/account/create_import/  🟢 Trusted (2 files)
│   ├── src/json_rpc/v2/models/  🟢 Trusted (4 files)
│   ├── src/service/  🔴 Untrusted (22 files)
│   ├── src/service/models/  🔴 Untrusted (6 files)
│   └── src/util/b58/  🟢 Trusted (1 file)
├── signer/  🟡 Mixed (1 trusted, 7 untrusted)  — signing
│   ├── src/bin/  🔴 Untrusted (1 file)  — binaries
│   ├── src/hardware_service/api/  🟢 Trusted (1 file)  — API definitions
│   ├── src/hardware_service/bin/  🔴 Untrusted (1 file)  — binaries
│   ├── src/service/  🔴 Untrusted (1 file)
│   ├── src/service/api/  🔴 Untrusted (3 files)  — API definitions
│   └── src/service/bin/  🔴 Untrusted (1 file)  — binaries
└── validator/  🔴 Untrusted (6 files)
    ├── service/src/  🔴 Untrusted (5 files)
    └── service/src/bin/  🔴 Untrusted (1 file)  — binaries
```

_Legend: 🟢 Trusted (enclave) · 🔴 Untrusted (host) · 🟡 Mixed (boundary)_

### Trust Boundary Rationale

No TEE manifest, EDL, or PAL files were found. Classification is based on LLM-assisted analysis of directory structure, TEE API usage patterns, and project role inference.

## Architecture Diagrams

### System Architecture with Trust Boundaries
The MobileCoin full-service node architecture is anchored by an Intel SGX enclave (trusted zone) that isolates cryptographic key management and transaction signing from the host environment. The enclave communicates across a strict ECALL/OCALL boundary to a Rust-based host binary (untrusted zone), which handles client API requests, ledger synchronization via a gRPC mirror, and database persistence through Diesel ORM. Sensitive data crossing the storage boundary is sealed by the enclave, ensuring confidentiality and integrity against the untrusted node operator.

```mermaid
flowchart TD
    subgraph TZ [" Trusted Zone"]
        ENCL["SGX Enclave<br>-Key Mgmt / Signer"]
        DCAP["DCAP Attestation<br>Module"]
        CSS["Enclave Sig.<br>Structure -CSS"]
    end

    subgraph UZ ["⚠️ Untrusted Zone"]
        HOST["Full-Service<br>Host Binary"]
        API["Client API Layer"]
        MIRROR["Mirror Component"]
        DB["Diesel ORM<br>Database"]
    end

    subgraph NZ [" External Network"]
        CLIENT["External Clients"]
        NET["MobileCoin Network"]
        PCCS["Intel PCCS / QVL"]
    end

    ENCL ---|Attestation Quote| DCAP
    CSS ---|Signed Measurement| ENCL
    ENCL <--->|ECALLs / OCALLs| HOST
    HOST -->|Sealed Key Material| DB
    HOST -->|Tx Requests| API
    HOST <-->|Ledger Sync (gRPC)| MIRROR
    MIRROR <-->|Block Data| NET
    API <-->|REST / JSON| CLIENT
    DCAP <-->|Verify Quote| PCCS

    classDef trusted fill:#d4edda,stroke:#28a745,color:#1a1a2e,font-weight:bold
    classDef untrusted fill:#f8d7da,stroke:#dc3545,color:#1a1a2e,font-weight:bold
    classDef extnet fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e
    classDef crypto fill:#e2d5f1,stroke:#6a4c93,color:#1a1a2e

    class ENCL trusted
    class DCAP trusted
    class CSS crypto
    class HOST untrusted
    class API untrusted
    class MIRROR untrusted
    class DB untrusted
    class CLIENT extnet
    class NET extnet
    class PCCS extnet
```

### Trust Boundary Narrative

The trust boundary separates enclave-side components (**Enclave ↔ Host (Primary Trust Boundary) — ECALL parameter passing**, **Attestation Flow (DCAP) — Quote verification from enclave to relying party**, **Attestation Flow (DCAP) — Quote report_data binding to key material**, **Enclave sealed state restoration**, **SGX enclave initialization**) from host-side components (**Host ↔ Database**, **Host**). Data and control flow across this boundary via the invariants listed below.

**Trust Paths Identified:**
- `INV-01`: Enclave ↔ Host (Primary Trust Boundary) — ECALL parameter passing — Host-provided ECALL input parameters must be validated before use in enclave key derivation, transaction signing, or sealed-state operations.
- `INV-02`: Attestation Flow (DCAP) — Quote verification from enclave to relying party — DCAP quote verification must validate TCB status, advisory status, and collateral freshness before accepting an attestation result as trustworthy.
- `INV-03`: Attestation Flow (DCAP) — Quote report_data binding to key material — Attestation quote report_data must cryptographically bind to the enclave's public key or session identity being established, preventing man-in-the-middle substitution.
- `INV-04`: Host ↔ Database → Enclave sealed state restoration — Sealed data restored from untrusted host storage must include monotonic version or epoch validation to prevent rollback to previously compromised states.
- `INV-05`: Build/Deployment configuration → SGX enclave initialization — SGX must operate in hardware mode (SGX_MODE=HW) in production; simulation or debug mode must not be reachable in deployment.
- `INV-06`: Enclave ↔ Host (Primary Trust Boundary) — secret data exfiltration path — Private key material, spending keys, and transaction secrets must never cross the enclave-host boundary in plaintext toward the untrusted host.
- `INV-07`: Design-level trust boundary: which operations occur inside vs outside the enclave — Transaction signing and sensitive cryptographic operations must execute entirely within the enclave and never in the untrusted host process.
- `INV-08`: Build-time signing → Runtime enclave loading → CSS verification — Loaded enclave CSS (enclave signature structure) must be verified against expected MRENCLAVE measurements; bypass paths controlled by host environment variables must be validated.
- `INV-09`: Enclave ↔ Database — sealed data binding to enclave identity — Seal policy must bind sealed data to the correct enclave identity (MRENCLAVE or MRSIGNER) to prevent a different enclave from unsealing the data.
- `INV-10`: Enclave → Host → Client API — error message propagation — Error responses propagated from the enclave to the host must not reveal secret-dependent internal state, key material details, or enclave configuration.
- `INV-11`: Enclave ↔ Host — OCALL return value trust — OCALL return values used in enclave security decisions must be validated before trust, as the host controls OCALL execution and return data.
- `INV-12`: Attestation Flow (DCAP) — Measurement identity verification — Measurement comparison during attestation verification must check both MRENCLAVE and MRSIGNER as required by the trust model, not just one.

**Cross-Boundary Connections:**
- Enclave sealed state restoration ↔ Host ↔ Database

### Data Flow Summary

Of 12 invariants, **10** involve data crossing the trust boundary between enclave and host.

**Host → Enclave** (1 flow)
_External data entering the TEE — highest validation burden_
- `INV-04`: **unsealed blob from host filesystem or database** → **enclave state restoration**

**Enclave → Host** (1 flow)
_TEE outputs and secrets leaving the enclave — leakage risk_
- `INV-10`: **enclave internal error states** → **RPC error response to host**

**Bidirectional** (8 flows)
_Flows crossing the boundary in both directions_
- `INV-01`: **host-provided buffers to ECALL** → **enclave key derivation**
- `INV-02`: **unverified DCAP quote from network** → **policy decision accepting enclave as trusted**
- `INV-03`: **enclave public key** → **quote report_data field**
- `INV-06`: **enclave private key generation** → **ECALL return buffer visible to host**
- `INV-07`: **architectural trust assumption — enclave handles all signing** → **security guarantee claim — transactions are signed securely**
- `INV-09`: **seal key derivation policy** → **sealed blob persisted to database**
- `INV-11`: **OCALL return values** → **enclave policy decision**
- `INV-12`: **MRENCLAVE from quote** → **attestation acceptance decision**

**Boundary Interface Summary:**
- **Enclave entry points** (1): data enters TEE via `INV-04`
- **Enclave exit points** (1): data leaves TEE via `INV-10`

_Internal flows (2): `INV-05`, `INV-08` — these stay within a single zone and are covered by individual findings._

### Invariant Reference

| ID | Description | Trust Path |
| --- | --- | --- |
| INV-01 | Host-provided ECALL input parameters must be validated before use in enclave key derivation, transaction signing, or sealed-state operations. | Enclave ↔ Host (Primary Trust Boundary) — ECALL parameter passing |
| INV-02 | DCAP quote verification must validate TCB status, advisory status, and collateral freshness before accepting an attestation result as trustworthy. | Attestation Flow (DCAP) — Quote verification from enclave to relying party |
| INV-03 | Attestation quote report_data must cryptographically bind to the enclave's public key or session identity being established, preventing man-in-the-middle substitution. | Attestation Flow (DCAP) — Quote report_data binding to key material |
| INV-04 | Sealed data restored from untrusted host storage must include monotonic version or epoch validation to prevent rollback to previously compromised states. | Host ↔ Database → Enclave sealed state restoration |
| INV-05 | SGX must operate in hardware mode (SGX_MODE=HW) in production; simulation or debug mode must not be reachable in deployment. | Build/Deployment configuration → SGX enclave initialization |
| INV-06 | Private key material, spending keys, and transaction secrets must never cross the enclave-host boundary in plaintext toward the untrusted host. | Enclave ↔ Host (Primary Trust Boundary) — secret data exfiltration path |
| INV-07 | Transaction signing and sensitive cryptographic operations must execute entirely within the enclave and never in the untrusted host process. | Design-level trust boundary: which operations occur inside vs outside the enclave |
| INV-08 | Loaded enclave CSS (enclave signature structure) must be verified against expected MRENCLAVE measurements; bypass paths controlled by host environment variables must be validated. | Build-time signing → Runtime enclave loading → CSS verification |
| INV-09 | Seal policy must bind sealed data to the correct enclave identity (MRENCLAVE or MRSIGNER) to prevent a different enclave from unsealing the data. | Enclave ↔ Database — sealed data binding to enclave identity |
| INV-10 | Error responses propagated from the enclave to the host must not reveal secret-dependent internal state, key material details, or enclave configuration. | Enclave → Host → Client API — error message propagation |
| INV-11 | OCALL return values used in enclave security decisions must be validated before trust, as the host controls OCALL execution and return data. | Enclave ↔ Host — OCALL return value trust |
| INV-12 | Measurement comparison during attestation verification must check both MRENCLAVE and MRSIGNER as required by the trust model, not just one. | Attestation Flow (DCAP) — Measurement identity verification |

## TEE Usage Problems

### [CRITICAL] IV-INV-05: Missing SGX HW mode runtime assertion [Configuration Integrity] (incorrect_usage) (CWE-489)

**Root Cause**: SGX_MODE=HW is only documented as a build-time environment variable in README instructions but never enforced by a runtime check in the validator service entry point.
**Impact**: The entire TEE security model is defeated: private keys, mnemonics, and transaction signing material in the enclave memory can be inspected by any process, completely undermining confidentiality guarantees.
**Confidence**: Likely | **Invariant**: INV-05 | **Tier**: core

**Preconditions**:
- Attacker can deploy a custom-built binary with SGX_MODE=SW
- Attestation verifier does not independently check debug flag in quote

**Attack Scenario**:
  1. Attacker builds enclave with SGX_MODE=SW or debug flag enabled. (`[HOST] validator/service/src/bin/main.rs:20`)
  2. Binary runs without any runtime check rejecting simulation mode. (`[HOST] validator/service/src/config.rs:7`)
  3. Enclave operates without hardware memory protection.
  4. Private keys and transaction data become extractable from memory.

### Code Evidence

**`validator/service/src/bin/main.rs:20 [HOST]`**
```
      10 | use mc_ledger_sync::{LedgerSyncServiceThread, PollingNetworkState, ReqwestTransactionsFetcher};
      11 | use mc_validator_service::{Config, Service};
      12 | use std::{
      13 |     process::exit,
      14 |     sync::{Arc, RwLock},
      15 | };
      16 | 
      17 | // Exit codes.
      18 | const EXIT_INVALID_HOST: i32 = 4;
      19 | 
>>>   20 | fn main() {
      21 |     mc_common::setup_panic_handler();
      22 |     let _sentry_guard = mc_common::sentry::init();
      23 | 
      24 |     let (logger, _global_logger_guard) = create_app_logger(o!());
      25 | 
      26 |     let config = Config::parse();
      27 | 
      28 |     // Exit if the user is not in an authorized country.
      29 |     if check_host::check_host_is_allowed_country_and_region().is_err() {
      30 |         eprintln!("Could not validate host");
```
Attacker builds enclave with SGX_MODE=SW or debug flag enabled.

**`validator/service/src/config.rs:7 [HOST]`**
```
       1 | use clap::Parser;
       2 | use mc_full_service::config::{LedgerDbConfig, PeersConfig};
       3 | use mc_util_parse::parse_duration_in_seconds;
       4 | use mc_validator_api::ValidatorUri;
       5 | use std::time::Duration;
       6 | 
>>>    7 | /// Configuration options for the validator service
       8 | #[derive(Clone, Debug, Parser)]
       9 | #[clap(
      10 |     name = "mc-validator-service",
      11 |     about = "Ledger validator service. Provides a ledger and transaction proxying for Full Service (without attestation)."
      12 | )]
      13 | pub struct Config {
      14 |     /// Listening URI.
      15 |     #[clap(
      16 |         long,
      17 |         default_value = "insecure-validator://127.0.0.1/",
```
Binary runs without any runtime check rejecting simulation mode.

**Remediation**: Add a runtime assertion at startup that verifies the SGX quote FLAGS field indicates non-debug mode, and verify the enclave is loaded in HW mode before proceeding with any sensitive operations.

### [HIGH] IV-INV-12: MRENCLAVE omitted from attestation identity check [Binding Weakness] (incorrect_usage) (CWE-345)

**Root Cause**: The trusted identity is constructed solely as TrustedIdentity::MrSigner, omitting MRENCLAVE binding.
**Impact**: Any enclave signed by the trusted signer key is accepted, including malicious, debug, or outdated enclaves with different code than expected.
**Confidence**: Confirmed | **Invariant**: INV-12 | **Tier**: core

**Preconditions**:
- Attacker can build and sign a custom enclave with the trusted signer's key.

**Attack Scenario**:
  1. TrustedIdentity uses only MrSigner variant, never MrEnclave. (`[HOST] validator/service/src/bin/main.rs:39`)
  2. Attestation accepts any enclave signed by the trusted key.
  3. Malicious enclave with same signer but different code passes verification.

### Code Evidence

**`validator/service/src/bin/main.rs:39 [HOST]`**
```
      29 |     if check_host::check_host_is_allowed_country_and_region().is_err() {
      30 |         eprintln!("Could not validate host");
      31 |         exit(EXIT_INVALID_HOST);
      32 |     }
      33 | 
      34 |     log::info!(logger, "Read Configs: {:?}", config);
      35 | 
      36 |     // Create enclave trusted identity.
      37 |     let config_advisories: Vec<&str> = vec![];
      38 |     let signature = mc_consensus_enclave_measurement::sigstruct();
>>>   39 |     let trusted_identity = TrustedIdentity::MrSigner(TrustedMrSignerIdentity::new(
      40 |         MrSigner::from(signature.mrsigner()),
      41 |         signature.product_id(),
      42 |         signature.version(),
      43 |         config_advisories,
      44 |         mc_consensus_enclave_measurement::HARDENING_ADVISORIES,
      45 |     ));
      46 | 
      47 |     log::debug!(logger, "TrustedIdentity: {:?}", trusted_identity);
      48 | 
      49 |     // Create peer manager.
```
TrustedIdentity uses only MrSigner variant, never MrEnclave.

**Remediation**: Add a TrustedIdentity::MrEnclave entry alongside the MrSigner entry, or switch to MrEnclave-only to enforce exact code identity.

## Positive Guards (Confirmed Security Controls)

### PG-INV-07: Enclave-based signing architecture
- **Invariants**: INV-07
- **Completeness**: partial
- **Evidence**: validator/service/src/bin/main.rs:38-45 (enclave identity setup); python/mobilecoin/client.py:261-266 (build_transaction delegates to API); python/mobilecoin/client.py:289-297 (submit_transaction sends tx_proposal)

The provided code shows enclave-aware architecture with TrustedIdentity and MrSigner verification in the validator host process. No signing or key material handling is present in the untrusted host code (main.rs) or Python client libraries. Clients delegate transaction operations to the full-service API, which is expected to route signing through the enclave. However, the enclave EDL and trusted signing implementation are not in the provided files.

### PG-INV-08: Build-time MrSigner identity from sigstruct
- **Invariants**: INV-08
- **Completeness**: partial
- **Evidence**: validator/service/src/bin/main.rs:38-45

The trusted enclave identity is constructed from mc_consensus_enclave_measurement::sigstruct(), which embeds expected measurements at build time. MrSigner, product_id, and version are extracted and wrapped in TrustedIdentity::MrSigner for later verification. No environment variables or runtime config influence this identity.

### PG-U-INV-09: MrSigner identity binding for attestation
- **Invariants**: INV-09
- **Completeness**: partial
- **Evidence**: validator/service/src/bin/main.rs:38-45 constructs TrustedIdentity::MrSigner from signature.mrsigner(), signature.product_id(), signature.version(); full-service/src/config.rs:140-151 mirrors the same pattern for fog ingest enclave verification

The codebase consistently uses MrSigner-based trusted identity construction via TrustedMrSignerIdentity, binding to mrsigner, product_id, and version from enclave signatures. While the actual sgx_seal_data calls remain out of scope, the identity management patterns demonstrate correct MRSIGNER-based enclave identity binding throughout attestation and peer verification code.

### PG-U-INV-02: Advisory and TCB identity configured
- **Invariants**: INV-02
- **Completeness**: partial
- **Evidence**: validator/service/src/bin/main.rs:37-45, full-service/src/config.rs:140-151

TrustedIdentity objects are constructed with HARDENING_ADVISORIES and MRSIGNER/product_id/version for TCB validation. The config_advisories vec is empty but HARDENING_ADVISORIES from mc_consensus_enclave_measurement provides the advisory list, indicating advisory-aware verification is intended. Collateral freshness checks are not visible in this code but would reside in the mc_attestation_verifier crate.

## Dismissed Findings

_The following findings were dismissed during adversarial review._

### ~~IV-INV-05: Missing SGX hardware mode runtime assertion~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. False positive. The SGX_MODE is determined at enclave build/signing time and is embedded in the enclave measurement. A simulation-mode enclave cannot produce valid remote attestation quotes that would pass verification by peers. In any multi-validator deployment, attestation would naturally reject non-hardware enclaves. The attack path requires a malicious operator deliberately building in SIM mode—but such an operator already controls the deployment environment and cannot fool remote validators. No concrete end-to-end exploit; no trust boundary trace provided.
- **Location(s)**: `validator/service/src/bin/main.rs:20`, `validator/service/src/bin/main.rs:38`

### ~~IV-INV-12: MRSIGNER-only attestation identity check~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. False positive. MRSIGNER-only attestation is an intentional and well-documented design pattern in SGX for supporting enclave upgrades and version compatibility. The attack path requires 'Attacker creates alternate enclave signed by same trusted signer key'—which presupposes compromise of the signing private key, a separate high-barrier event outside the code's threat model. If the signing key is compromised, the attacker has far more fundamental problems. The TrustedIdentity also constrains product_id and version, further limiting scope. No trust boundary trace; this is a design discussion, not a code vulnerability.
- **Location(s)**: `validator/service/src/bin/main.rs:39`

### ~~RV-U-INV-02: Empty config_advisories in trusted identity~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. The attack path is tautological and requires triple-condition coincidence: (1) an unpatched CVE must exist, (2) HARDENING_ADVISORIES must not already cover it, AND (3) the attacker must be able to exploit it on a running node. Empty config_advisories is a valid default when all critical advisories are already handled by HARDENING_ADVISORIES in the verification library. No concrete evidence shows a specific advisory gap leading to exploitation.
- **Location(s)**: `full-service/src/config.rs:142`, `validator/service/src/bin/main.rs:37`

### ~~RV-U-INV-06: CLI exports secret entropy mnemonic~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. This is intentional CLI functionality. Wallet CLIs are designed to export account secrets at the user's explicit request via 'export' command. An attacker who can invoke arbitrary CLI commands on a user's machine already has full local access - the export command adds no new attack surface. The TEE classification is incorrect: this is client-side Python code, not enclave code, and 'tee_category: Trust Boundary Flow' is inapplicable.
- **Location(s)**: `python/mobilecoin/cli.py:95`, `python/mobilecoin/cli.py:96`, `python/mobilecoin/cli.py:99`

### ~~RV3-U-INV-03: Atestation report_data binding absent~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Fundamentally misunderstands SGX quote structure. report_data is an OUTPUT field that the enclave writes into the quote to bind application-specific data (like public keys). The attestation verification library handles report_data verification - application code at line 39 configures the TrustedIdentity policy, which is the correct layer for identity checks. No evidence is presented that report_data binding is actually absent from the verification flow. The Weak confidence rating acknowledges this speculation.
- **Location(s)**: `validator/service/src/bin/main.rs:39`

### ~~RV-U-INV-07: Standalone signer binary outside enclave~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. Describes an intentional offline/air-gapped signing design pattern. Standalone signer binaries are a standard cryptocurrency security practice allowing transaction signing on isolated machines. The attack path requires 'compromising the host OS' which already grants far greater capability than key extraction from one process. The reference to full-service/src/test_utils.rs confirms test/non-production context. This is a design choice, not a vulnerability.
- **Location(s)**: `signer/src/bin/main.rs:3`, `python/mobilecoin/client.py:268`, `python/mobilecoin/client_v1.py:177`, `full-service/src/test_utils.rs:36`

## Appendix

_Info-severity TEE findings, items requiring manual review, and non-TEE findings are included here for completeness._

### Items Requiring Manual Review

#### U-INV-01: ECALL input validation not verifiable

Signer CLI binary for input validation before key derivation and signing operations.
- **Why Uncertain**: Provided code is a host-side CLI binary (signer/src/bin/main.rs), not enclave ECALL handlers; actual enclave boundary code is not present in the source samples.

Second-pass notes: The additional source code provided (full-service config, Python CLI, signer binary main, validator service binary) is entirely host-side/untrusted code. No enclave ECALL handler implementations, EDL interface definitions, or mc-signer::service enclave-side input validation guards are present. The signer binary at signer/src/bin/main.rs performs SLIP-0010 key derivation and account operations entirely outside the enclave. The full-service config constructs TrustedIdentity objects for enclave ver
- **Recommended Steps**: Provide enclave ECALL handler source code for analysis, Check mc-transaction-signer Operations trait implementations, Review mc-signer::service for input validation guards

#### U-INV-04: Sealed state rollback guards not visible

Validator service init and wallet CLI for sealed state restoration anti-rollback guards.
- **Why Uncertain**: Enclave sealing/unsealing logic with monotonic counter checks is not present in the provided source files.

Second-pass notes: The additional source code provided (config.rs, main.rs, test_utils.rs, client_v1.py) is all at the application/service layer and does not contain any enclave sealing/unsealing logic. There are references to mc_consensus_enclave_measurement (used for trusted identity creation via SigStruct) but no enclave-internal code such as EDL files, trusted ECALL/OCALL implementations, monotonic counter usage, or sealed state restoration paths. The invariant requires inspection of enclave-internal code (e.g
- **Recommended Steps**: Inspect enclave unseal/seal Rust EDL and trusted code, Search for monotonic counter or epoch comparison in enclave src, Check mc-consensus-enclave sealed state restoration path

#### U-INV-10: Enclave error sanitization unverifiable

Error propagation paths in host-side GRPC client and Python client API layers.
- **Why Uncertain**: Enclave-to-host boundary error handling code (SGX OCALL/ECALL error returns) not provided; only host-to-client layer visible.

Second-pass notes: The provided code (config.rs, test_utils.rs, Python clients) contains only host-side configuration, test infrastructure, and external client libraries. The enclave-to-host boundary error handling code (SGX ECALL/OCALL error return paths, enclave error serialization) remains absent. The Python clients show that error responses are passed through as-is via WalletAPIError(response_data), but this is client-side receipt of errors, not the enclave boundary itself. No evidence of either guards (generi
- **Recommended Steps**: Review enclave ECALL error return paths for detail leakage, Check full-service server error serialization code, Audit enclave boundary for generic error wrapping

#### U-INV-11: OCALL return validation not assessable

Validator service and CLI code for OCALL return value handling patterns.
- **Why Uncertain**: Provided code is entirely host-side/untrusted (main.rs, validator_api.rs, cli.py); no enclave-side OCALL handlers or EDL files visible to assess validation.

Second-pass notes: The additional source code (config.rs, test_utils.rs, validator_api.rs, main.rs, check_host.rs) is entirely host-side/untrusted code. None of it contains enclave EDL files, trusted OCALL handler implementations, or enclave-side logic that processes OCALL return values. The invariant concerns validation of OCALL return data *inside* the TEE boundary, which requires enclave source code (e.g., consensus_enclave/src/*.rs, *.edl files, or ocall_* handler functions). Without any enclave-side code avai
- **Recommended Steps**: Provide enclave EDL files and trusted OCALL handler implementations, Search for ocall_* or ECALL wrappers in enclave src directories, Inspect consensus-enclave lib.rs for OCALL return usage

#### U-INV-03: report_data key binding unverifiable

MRSIGNER-based trusted identity creation in validator service entry point.
- **Why Uncertain**: The provided code only shows TrustedIdentity construction via MrSigner; quote generation, report_data population, and verification logic are in libraries not included in the sample.

Second-pass notes: The additional source code shows how TrustedIdentity is constructed via MrSigner in validator/service/src/bin/main.rs (lines 38-45) and full-service/src/config.rs (lines 140-151), but these only configure enclave identity trust (MRSIGNER, product_id, version). The critical code paths for report_data population during quote generation and client-side report_data extraction/key binding verification remain in mc_attest_core and mc_attestation_verifier libraries, which are still not provided. No evi
- **Recommended Steps**: Review mc_attest_core and mc_attestation_verifier library source, Trace report_data field population during quote generation, Verify client-side report_data extraction and key binding check

#### U-INV-07: Enclave signing boundary not auditable

Host-side validator main and Python wallet clients for out-of-enclave signing.
- **Why Uncertain**: Enclave EDL files and signing implementation not provided; only host orchestration and client wrappers visible.

Second-pass notes: The additional source code provides context about the SGX enclave infrastructure (config.rs references MrSigner, mc_sgx_css::Signature, mc_consensus_enclave_measurement::HARDENING_ADVISORIES) and transaction building pipeline (test_utils.rs imports WalletTransactionBuilder, UnsignedTxProposal, TxProposal). However, the critical pieces remain unavailable: (1) the EDL files defining trusted/untrusted boundary for signing operations, (2) the actual transaction signing implementation, and (3) the en
- **Recommended Steps**: Provide consensus enclave EDL and signing entry points, Provide full-service enclave transaction signing code, Audit EDL trusted/untrusted boundary for signing calls

#### U-INV-01: ECALL input validation not observable

Whether host-provided inputs are validated before key derivation or signing.
- **Why Uncertain**: Provided code is host-side CLI binary (bin/main.rs), not enclave ECALL handler; no enclave-side code available to inspect.
- **Recommended Steps**: Provide enclave ECALL dispatch and handler code, Check sign_tx/sync_txos implementations for input validation, Review .edl files for ECALL parameter definitions

#### U-INV-03: report_data key binding not observable

Validator service trusted identity setup and CLI code for report_data to key binding.
- **Why Uncertain**: Provided code only shows MrSigner-based identity configuration; quote generation and report_data binding logic reside in mc_attest_core/mc_attestation_verifier crates not included.
- **Recommended Steps**: Review mc_attest_core quote generation for report_data population, Review mc_attestation_verifier for report_data extraction and binding checks, Trace session key establishment to verify report_data hash comparison

#### U-INV-04: Sealed state rollback protection

Validator service init and wallet client for sealed state restoration and version/epoch checks.
- **Why Uncertain**: The enclave-side seal/unseal implementation handling monotonic counters is not present in provided snippets.
- **Recommended Steps**: Audit enclave seal/unseal code for monotonic counter checks, Check mc_consensus_enclave sealed state restoration paths, Verify anti-rollback counter comparison during unseal

#### U-INV-06: Private key boundary crossing in production

Whether private keys leak across enclave-host boundary in test code.
- **Why Uncertain**: Only e2e test code provided; production ECALL/OCALL boundary handlers not available for inspection.
- **Recommended Steps**: Inspect production ECALL return handlers for plaintext private key fields, Audit sealing/encryption of key material before crossing enclave boundary, Review JSON-RPC response serialization for spending key fields

#### U-INV-10: Enclave error sanitization at boundary

Error propagation paths from host/client layers for enclave detail leakage.
- **Why Uncertain**: Provided code covers host gRPC client and Python API client layers, not enclave boundary error handling or sanitization logic.
- **Recommended Steps**: Examine enclave OCALL/edge error handlers for detail leakage, Review full-service Rust error types wrapping enclave responses, Check protobuf error message definitions at enclave boundary

#### U-INV-11: OCALL return validation not observable

Host-side validator service and Python CLI for OCALL return value handling.
- **Why Uncertain**: Provided code is host-side validator service and CLI client; enclave OCALL handlers and EDL files are not present.
- **Recommended Steps**: Examine enclave EDL files for OCALL definitions, Trace OCALL return value usage inside enclave code, Check consensus_enclave for host data validation
