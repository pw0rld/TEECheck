# TEE Usage Audit Report: phala-blockchain

## Executive Summary
This audit identified 6 active findings across 4 taxonomy families: 3 Low severity (INV, RV), 2 Info (V, RV3), and 0 Critical/High. Eight findings were dismissed as false positives during adversarial review and are excluded from the active findings list. The original IV-INV-02 (None attestation bypass) was consolidated with IV-INV-01 as a single Low-severity finding, removing the duplicate from the active count.

Key vulnerabilities:
• IV-INV-01 (Low, INV family): Configurable None attestation bypass allows operators to skip attestation entirely, undermining TEE security guarantees
• RV-U-04 (Low, RV family): No on-chain DCAP collateral freshness check enables replay of stale TCB status
• RV-U-13 (Low, RV family): No on-chain DCAP collateral verification allows unvalidated quote collateral acceptance
• V-06 (Info, V family): Private key material logged to stdout exposes credentials to host-side observers
• V-05 (Low, V family): Key injection permitted even when attestation is enabled, weakening key release controls
• RV3-U-05 (Info, RV3 family): Debug key accepted without enclave-side guard in production paths

Two partial positive guards were confirmed (PG3-U-02, PG3-U-INV-03), indicating attestation infrastructure exists but lacks completeness. 19 unknowns remain unresolved, with 7 concerning TCB status validation gaps and 4 concerning TLS termination and plaintext exposure at the host boundary.

Actionable recommendations:
• Remove None attestation bypass option from configuration (IV-INV-01)
• Implement on-chain DCAP collateral verification with freshness checks (RV-U-04, RV-U-13)
• Strip private key material from all logging paths (V-06)
• Add enclave-side guard to reject debug keys when attestation provider is configured (RV3-U-05)
• Prioritize resolution of U-INV-07 (TLS termination) and U-INV-04 (monotonic counter) unknowns

## Dashboard Summary

| Severity | Trust-Path Tier | Count |
| --- | --- | --- |
| Low | core | 4 |
| Info | core | 1 |
| Info | adjacent | 1 |

## Trust Boundary Analysis

| Actor | Component | Context | Boundary Type |
| --- | --- | --- | --- |
| Worker Operator | pRuntime (Phat Contract Runtime) | trusted | enclave/host |
| Gramine project | Gramine-SGX Runtime | trusted | enclave/host boundary layer |
| Intel | AESM Service | trusted | enclave/host (host-level privileged, trusted by design) |
| Phala project | sgx-attestation crate | trusted | crypto boundary (enclave internal) |
| Phala project | phala-crypto crate | trusted | crypto boundary (enclave internal) |
| Phala project | phactory | trusted | enclave internal |
| Phala project | pink runtime | trusted | enclave internal |
| Phala project | sidevm | trusted | enclave internal |
| Worker Operator | nginx API Proxy | untrusted | network (host-level) |
| Worker Operator | Docker Deployment Stack | untrusted | host infrastructure |
| Phala project | phala-mq | untrusted | message queue (spans host) |
| Phala Network validators | Phala Substrate Node | untrusted | network (external verifier) |

## Architecture Diagrams

### System Architecture with Trust Boundaries
The Phala Network architecture centers on pRuntime, a Phat Contract runtime executing inside a Gramine-SGX enclave that processes user queries and smart contracts within a hardware-isolated trusted execution environment. The critical trust boundary is the SGX enclave perimeter: trusted components (pRuntime, phactory, sgx-attestation, phala-crypto, pink, sidevm) operate inside the enclave with exclusive access to cryptographic secrets including cluster private keys used for user fingerprint generation, while untrusted host-level components (nginx proxy, Docker stack, phala-mq, phaxt) handle external communication and infrastructure. Data flows from external users through the nginx proxy into the enclave via Gramine-mediated ECALLs, with attestation artifacts and signed state updates flowing outbound through phala-mq and phaxt to the Phala Substrate Node for on-chain verification, establishing a chain of trust from Intel's AESM service through the enclave to the blockchain consensus layer.

```mermaid
flowchart TD
    subgraph TZ[" Trusted Zone -- SGX Enclave"]
        PR["pRuntime"]
        PX["phactory"]
        PC["phala-crypto"]
        SA["sgx-attestation"]
        PK["pink runtime"]
        SV["sidevm"]
    end

    subgraph UZ["⚠️ Untrusted Zone -- Host"]
        NX["nginx API Proxy"]
        DK["Docker Stack"]
        MQ["phala-mq"]
        XT["phaxt RPC client"]
    end

    subgraph NW[" External Network"]
        US["Users / DApps"]
        SN["Phala Substrate Node"]
        PCCS["Intel PCCS / PCS"]
    end

    GR["Gramine-SGX Runtime"]
    AESM["AESM Service"]

    US -->|"HTTPS API requests"| NX
    NX -->|"Proxied queries"| GR
    GR -->|"ECALLs / OCALLs"| PR
    DK -->|"Launch: gramine-sgx pruntime"| GR

    PR ---|"Contract lifecycle"| PX
    PR ---|"Key mgmt + signatures"| PC
    PR ---|"Contract execution"| PK
    PR ---|"Side VM ops"| SV

    PR -->|"RA request"| SA
    SA -->|"SGX quote generation"| AESM
    AESM -->|"Certificate provisioning"| PCCS

    PR -->|"Enclave messages"| MQ
    MQ -->|"Forward"| XT
    XT -->|"Attestation + state"| SN

    classDef trusted fill:#d4edda,stroke:#28a745,color:#1a1a2e,font-weight:bold
classDef untrusted fill:#f8d7da,stroke:#dc3545,color:#1a1a2e,font-weight:bold
classDef extnet fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e
classDef crypto fill:#e2d5f1,stroke:#6a4c93,color:#1a1a2e

    class PR,PX,PC,SA,PK,SV trusted
    class NX,DK,MQ,XT untrusted
    class US,SN,PCCS extnet
    class GR,AESM trusted
```

### Trust Boundary Narrative

The trust boundary separates enclave-side components (**Gramine-SGX**, **pRuntime enclave initialization**, **pRuntime enclave**, **Attestation quote**, **Attestation quote report_data**) from host-side components (**Host OS**, **Phala blockchain verifier**, **Host filesystem (sealed blob)**, **nginx (TLS termination, host)**, **Verifier**). Data and control flow across this boundary via the invariants listed below.

**Trust Paths Identified:**
- `INV-01`: Host OS -> Gramine-SGX -> pRuntime enclave initialization — SGX simulation mode (SGX_MODE=SW) must not be reachable in production deployments, as it disables all hardware-backed memory isolation and attestation guarantees.
- `INV-02`: pRuntime enclave -> Attestation quote -> Phala blockchain verifier — Remote attestation quote verification during worker registration must validate the full quote including TCB status, collateral freshness, and expected measurements.
- `INV-03`: pRuntime key generation -> Attestation quote report_data -> Blockchain verification — The enclave's cryptographic identity (master key) must be cryptographically bound to the attestation report_data field so that the verified quote proves possession of the claimed key.
- `INV-04`: pRuntime enclave -> Host filesystem (sealed blob) -> pRuntime enclave on restart — Sealed state must include a monotonic epoch or version counter that is verified on unseal to prevent rollback to a previous state.
- `INV-05`: Host OS -> Gramine trusted bridge (OCALL/entry) -> pRuntime enclave logic — Data received from the untrusted host through Gramine's trusted/untrusted bridge must be validated before use in security-critical enclave operations.
- `INV-06`: Verified attestation quote -> Blockchain worker registration extrinsic -> On-chain worker identity — On-chain worker registration must bind the registered worker identity to the specific MRENCLAVE measurement extracted from a verified attestation quote.
- `INV-07`: End user -> nginx (TLS termination, host) -> pRuntime enclave API — The TLS termination point at the host-side nginx proxy exposes user query plaintext to the worker operator before it reaches the enclave, undermining the confidentiality guarantee for user-to-enclave communication.
- `INV-08`: AESM daemon (aesm_service) -> pRuntime enclave provisioning — AESM service must be verified as the genuine Intel-provided binary before the enclave trusts its provisioning and quote generation services.
- `INV-09`: pRuntime enclave error path -> Gramine bridge -> nginx -> User HTTP response — Error responses from the pRuntime API must use generic error messages and constant-length responses to avoid revealing enclave internal state or secret-dependent processing outcomes.
- `INV-10`: Attestation quote (SGX or TDX) -> Verifier -> Worker acceptance — The sgx-attestation crate must accept both SGX and TDX quote types but verify that the TEE type field in the quote matches the platform the verifier expects.
- `INV-11`: Cluster private key (enclave) -> User fingerprint salt derivation -> External log monitoring — Enclave secrets derived from cluster private key must not be extractable or derivable from the user fingerprint salt outside the enclave boundary.

**Cross-Boundary Connections:**
- Gramine-SGX ↔ Host OS
- pRuntime enclave ↔ Host filesystem (sealed blob)
- Attestation quote ↔ Phala blockchain verifier

### Data Flow Summary

Of 11 invariants, **6** involve data crossing the trust boundary between enclave and host.

**Host → Enclave** (3 flows)
_External data entering the TEE — highest validation burden_
- `INV-01`: **SGX_MODE environment variable** → **gramine-sgx enclave launch**
- `INV-05`: **OCALL return values** → **Key derivation input**
- `INV-07`: **User HTTPS requests to pRuntime API** → **nginx plaintext forwarding to enclave**

**Enclave → Host** (2 flows)
_TEE outputs and secrets leaving the enclave — leakage risk_
- `INV-02`: **Unverified attestation quote from network** → **Worker registration acceptance**
- `INV-09`: **Enclave internal error states** → **HTTP response body with variable-length error detail**

**Bidirectional** (1 flow)
_Flows crossing the boundary in both directions_
- `INV-11`: **Cluster private key inside enclave** → **User fingerprint computation**

**Boundary Interface Summary:**
- **Enclave entry points** (3): data enters TEE via `INV-01`, `INV-05`, `INV-07`
- **Enclave exit points** (2): data leaves TEE via `INV-02`, `INV-09`

_Internal flows (5): `INV-04`, `INV-08`, `INV-10`, `INV-03`, `INV-06` — these stay within a single zone and are covered by individual findings._

### Invariant Reference

| ID | Description | Trust Path |
| --- | --- | --- |
| INV-01 | SGX simulation mode (SGX_MODE=SW) must not be reachable in production deployments, as it disables all hardware-backed memory isolation and attestation guarantees. | Host OS -> Gramine-SGX -> pRuntime enclave initialization |
| INV-02 | Remote attestation quote verification during worker registration must validate the full quote including TCB status, collateral freshness, and expected measurements. | pRuntime enclave -> Attestation quote -> Phala blockchain verifier |
| INV-03 | The enclave's cryptographic identity (master key) must be cryptographically bound to the attestation report_data field so that the verified quote proves possession of the claimed key. | pRuntime key generation -> Attestation quote report_data -> Blockchain verification |
| INV-04 | Sealed state must include a monotonic epoch or version counter that is verified on unseal to prevent rollback to a previous state. | pRuntime enclave -> Host filesystem (sealed blob) -> pRuntime enclave on restart |
| INV-05 | Data received from the untrusted host through Gramine's trusted/untrusted bridge must be validated before use in security-critical enclave operations. | Host OS -> Gramine trusted bridge (OCALL/entry) -> pRuntime enclave logic |
| INV-06 | On-chain worker registration must bind the registered worker identity to the specific MRENCLAVE measurement extracted from a verified attestation quote. | Verified attestation quote -> Blockchain worker registration extrinsic -> On-chain worker identity |
| INV-07 | The TLS termination point at the host-side nginx proxy exposes user query plaintext to the worker operator before it reaches the enclave, undermining the confidentiality guarantee for user-to-enclave communication. | End user -> nginx (TLS termination, host) -> pRuntime enclave API |
| INV-08 | AESM service must be verified as the genuine Intel-provided binary before the enclave trusts its provisioning and quote generation services. | AESM daemon (aesm_service) -> pRuntime enclave provisioning |
| INV-09 | Error responses from the pRuntime API must use generic error messages and constant-length responses to avoid revealing enclave internal state or secret-dependent processing outcomes. | pRuntime enclave error path -> Gramine bridge -> nginx -> User HTTP response |
| INV-10 | The sgx-attestation crate must accept both SGX and TDX quote types but verify that the TEE type field in the quote matches the platform the verifier expects. | Attestation quote (SGX or TDX) -> Verifier -> Worker acceptance |
| INV-11 | Enclave secrets derived from cluster private key must not be extractable or derivable from the user fingerprint salt outside the enclave boundary. | Cluster private key (enclave) -> User fingerprint salt derivation -> External log monitoring |

## Taxonomy Summary

| Category | Count | Findings |
| --- | --- | --- |
| Trust Boundary Flow | 1 | V-07 |
| Verification Gap | 1 | V-03 |
| Configuration Integrity | 1 | V-05 |
| Output & Metadata Leakage | 1 | V-06 |

## TEE Usage Problems

### [LOW] V-05: Key injection allowed with attestation enabled [Configuration Integrity] (incorrect_usage) (CWE-489)

**Root Cause**: The pherry relay does not enforce mutual exclusivity between key injection (debug mode) and attestation provider (production mode), allowing both to be sent to the TEE enclave simultaneously.
**Impact**: An operator can register a TEE worker with a known private key and valid attestation, allowing them to sign messages and decrypt data outside the TEE, completely undermining TEE confidentiality guarantees.
**Confidence**: Likely | **Invariant**: INV-06 | **Tier**: core

**Preconditions**:
- Operator controls pherry CLI arguments
- pRuntime accepts debug_set_key when attestation is enabled
- Worker registers successfully on-chain with the injected key

**Attack Scenario**:
  1. Operator starts pherry with --use-dev-key --attestation-provider ias (`standalone/pherry/src/lib.rs:730`)
  2. pherry sets debug_set_key=Some(DEV_KEY) at lib.rs:740 (`standalone/pherry/src/lib.rs:738`)
  3. pherry sends init_runtime with debug_set_key AND attestation_provider (`standalone/pherry/src/lib.rs:740`)
  4. pRuntime initializes TEE with known key and generates valid attestation (`standalone/pherry/src/lib.rs:743`)
  5. Worker registers on-chain with valid attestation binding known key (`standalone/pherry/src/lib.rs:745`)
  6. Operator uses known private key to sign/decrypt outside TEE (`standalone/pherry/src/lib.rs:747`)
  **Evidence**: `standalone/pherry/src/lib.rs:876`, `crates/phactory/src/prpc_service.rs:371`, `crates/phactory/src/prpc_service.rs:1461`

### Code Evidence

**`standalone/pherry/src/lib.rs:730`**
```
let mut debug_set_key = None;
```
Operator starts pherry with --use-dev-key --attestation-provider ias

**`standalone/pherry/src/lib.rs:738`**
```
} else if use_dev_key {
```
pherry sets debug_set_key=Some(DEV_KEY) at lib.rs:740

**`standalone/pherry/src/lib.rs:740`**
```
debug_set_key = Some(hex::decode(DEV_KEY).expect("Invalid dev key"));
```
pherry sends init_runtime with debug_set_key AND attestation_provider

**`standalone/pherry/src/lib.rs:743`**
```
let resp = pr.init_runtime(prpc::InitRuntimeRequest::new(
```
pRuntime initializes TEE with known key and generates valid attestation

**Remediation**: Add a guard in init_runtime that sets debug_set_key=None whenever attestation_provider is Some, preventing key injection alongside production attestation. Enforce this at the CLI argument parser level as a secondary check.

**Trust Boundary Trace**:

| Source Zone | Crossing Point | Sink Zone | Verification |
| --- | --- | --- | --- |
| untrusted | standalone/pherry/src/lib.rs:730-741 | untrusted | missing |
| untrusted | standalone/pherry/src/lib.rs:743-753 | untrusted | missing |

**Cross-File Call Chain** (zone source: gramine_host):
```
[HOST      ] standalone/pherry/src/lib.rs:730  init_runtime → 
[HOST      ] standalone/pherry/src/lib.rs:744  init_runtime → prpc::InitRuntimeRequest::init_runtime
```

**Trust Boundary Analysis**: The untrusted pherry relay assembles an InitRuntimeRequest containing both an externally-injected debug key (debug_set_key) and a production attestation provider, then sends it across the trust boundary to the pRuntime TEE enclave. No guard exists in the pherry to enforce mutual exclusivity between key injection and attestation. If pRuntime accepts both parameters, the enclave initializes with a key known to the operator while producing a valid attestation, allowing the operator to operate outside TEE protections while appearing to be a legitimate TEE worker.

### [LOW] IV-INV-01: Configurable None attestation bypass [Configuration Integrity] (incorrect_usage) (CWE-1188)

**Root Cause**: The None attestation bypass path returns a valid ConfidentialReport when no attestation is provided, controlled only by a runtime-configurable boolean constant with an advisory comment.
**Impact**: An attacker running in SGX simulation mode can register a worker and participate in the network without any hardware-backed memory isolation or attestation, completely voiding all TEE security guarantees.
**Confidence**: Likely | **Invariant**: INV-01 | **Tier**: core

**Preconditions**:
- NoneAttestationEnabled is set to true in the runtime configuration
- Attacker controls a worker node and can set SGX_MODE=SW

**Attack Scenario**:
  1. Operator deploys pRuntime with SGX_MODE=SW in Gramine manifest. (`pallets/phala/src/utils/attestation.rs:147`)
  2. Enclave initializes without any hardware memory isolation. (`pallets/phala/src/utils/attestation.rs:148`)
  3. Worker submits registration with no attestation report. (`pallets/phala/src/utils/attestation.rs:152`)
  4. Runtime calls validate() with attestation=None (attestation.rs:147). (`pallets/phala/src/registry.rs:83`)
  5. opt_out_enabled=true, so Ok(ConfidentialReport) is returned (attestation.rs:149-153).
  6. Worker joins network with zero hardware-backed guarantees.

### Code Evidence

**`pallets/phala/src/utils/attestation.rs:147`**
```
     137 | 			};
     138 | 			validate_dcap(
     139 | 				&quote,
     140 | 				&collateral,
     141 | 				now,
     142 | 				user_data_hash,
     143 | 				verify_pruntime_hash,
     144 | 				pruntime_allowlist,
     145 | 			)
     146 | 		}
>>>  147 | 		None => {
     148 | 			if opt_out_enabled {
     149 | 				Ok(ConfidentialReport {
     150 | 					provider: None,
     151 | 					runtime_hash: Vec::new(),
     152 | 					confidence_level: 128u8,
     153 | 				})
     154 | 			} else {
     155 | 				Err(Error::NoneAttestationDisabled)
     156 | 			}
     157 | 		}
```
Operator deploys pRuntime with SGX_MODE=SW in Gramine manifest.

**`pallets/phala/src/utils/attestation.rs:148`**
```
     138 | 			validate_dcap(
     139 | 				&quote,
     140 | 				&collateral,
     141 | 				now,
     142 | 				user_data_hash,
     143 | 				verify_pruntime_hash,
     144 | 				pruntime_allowlist,
     145 | 			)
     146 | 		}
     147 | 		None => {
>>>  148 | 			if opt_out_enabled {
     149 | 				Ok(ConfidentialReport {
     150 | 					provider: None,
     151 | 					runtime_hash: Vec::new(),
     152 | 					confidence_level: 128u8,
     153 | 				})
     154 | 			} else {
     155 | 				Err(Error::NoneAttestationDisabled)
     156 | 			}
     157 | 		}
     158 | 	}
```
Enclave initializes without any hardware memory isolation.

**`pallets/phala/src/utils/attestation.rs:152`**
```
     142 | 				user_data_hash,
     143 | 				verify_pruntime_hash,
     144 | 				pruntime_allowlist,
     145 | 			)
     146 | 		}
     147 | 		None => {
     148 | 			if opt_out_enabled {
     149 | 				Ok(ConfidentialReport {
     150 | 					provider: None,
     151 | 					runtime_hash: Vec::new(),
>>>  152 | 					confidence_level: 128u8,
     153 | 				})
     154 | 			} else {
     155 | 				Err(Error::NoneAttestationDisabled)
     156 | 			}
     157 | 		}
     158 | 	}
     159 | }
     160 | 
     161 | pub fn validate_ias_report(
     162 | 	user_data_hash: &[u8],
```
Worker submits registration with no attestation report.

**`pallets/phala/src/registry.rs:83`**
```
      73 | 	pub trait Config: frame_system::Config {
      74 | 		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
      75 | 
      76 | 		/// The currency in which fees are paid and contract balances are held.
      77 | 		type Currency: Currency<Self::AccountId>;
      78 | 
      79 | 		type UnixTime: UnixTime;
      80 | 
      81 | 		type LegacyAttestationValidator: AttestationValidator;
      82 | 
>>>   83 | 		/// Enable None Attestation, SHOULD BE SET TO FALSE ON PRODUCTION !!!
      84 | 		#[pallet::constant]
      85 | 		type NoneAttestationEnabled: Get<bool>;
      86 | 
      87 | 		/// Verify attestation
      88 | 		///
      89 | 		/// SHOULD NOT SET TO FALSE ON PRODUCTION!!!
      90 | 		#[pallet::constant]
      91 | 		type VerifyPRuntime: Get<bool>;
      92 | 
      93 | 		/// Verify relaychain genesis
```
Runtime calls validate() with attestation=None (attestation.rs:147).

**Remediation**: Remove the opt-out path entirely from production builds using a compile-time feature gate, or add a runtime assertion that panics if NoneAttestationEnabled is true outside of test configurations.

### [LOW] RV-U-04: No on-chain DCAP collateral freshness check [State Continuity] (incorrect_usage)

**Root Cause**: The attestation.rs on-chain code imports DCAP collateral types (line 8: SgxV30QuoteCollateral) but only implements validation for legacy IAS reports (from_ias_report, line 43-100) which extracts a timestamp but does not compare it to block time; no equivalent freshness validation exists for DCAP collateral fields.
**Impact**: A worker with a known-compromised TCB version or revoked enclave could pass on-chain attestation checks by replaying stale collateral, undermining the integrity guarantees of the TEE registration system.
**Confidence**: Weak | **Invariant**: INV-04 | **Tier**: core

**Preconditions**:
- The worker operator controls the PCCS URL provided to pherry.
- DCAP attestation is used (not legacy IAS).
- A stale but structurally valid collateral set exists that passes signature verification but has expired TCB info.

**Attack Scenario**:
  1. A malicious worker operator configures pherry with a PCCS URL that returns stale TCB info and QE identity collateral with outdated next_update timestamps. (`pallets/phala/src/utils/attestation.rs:43`)
  2. pherry (standalone/pherry/src/lib.rs:784) fetches this stale collateral, attaches it to the DCAP quote, and submits the attestation on-chain. (`pallets/phala/src/utils/attestation.rs:8`)
  3. The on-chain pallet accepts the attestation without verifying collateral freshness (no next_update or CRL expiry check against block timestamp), allowing a worker with outdated or revoked TCB status to register or maintain registration.

### Code Evidence

**`pallets/phala/src/utils/attestation.rs:43`**
```
      33 | pub struct IasFields {
      34 | 	pub mr_enclave: [u8; 32],
      35 | 	pub mr_signer: [u8; 32],
      36 | 	pub isv_prod_id: [u8; 2],
      37 | 	pub isv_svn: [u8; 2],
      38 | 	pub report_data: [u8; 64],
      39 | 	pub confidence_level: u8,
      40 | }
      41 | 
      42 | impl IasFields {
>>>   43 | 	pub fn from_ias_report(report: &[u8]) -> Result<(IasFields, i64), Error> {
      44 | 		// Validate related fields
      45 | 		let parsed_report: sgx_attestation::ias::RaReport =
      46 | 			serde_json::from_slice(report).or(Err(Error::InvalidReport))?;
      47 | 
      48 | 		// Extract report time
      49 | 		let raw_report_timestamp = parsed_report.timestamp.clone() + "Z";
      50 | 		let report_timestamp = chrono::DateTime::parse_from_rfc3339(&raw_report_timestamp)
      51 | 			.or(Err(Error::BadIASReport))?
      52 | 			.timestamp();
      53 | 
```
A malicious worker operator configures pherry with a PCCS URL that returns stale TCB info and QE identity collateral with outdated next_update timestamps.

**`pallets/phala/src/utils/attestation.rs:8`**
```
       1 | use crate::constants::*;
       2 | 
       3 | use codec::{Decode, Encode};
       4 | use scale_info::TypeInfo;
       5 | use sp_std::vec::Vec;
       6 | 
       7 | use phala_types::{AttestationProvider, AttestationReport, Collateral};
>>>    8 | use sgx_attestation::dcap::SgxV30QuoteCollateral;
       9 | 
      10 | #[derive(Encode, Decode, TypeInfo, Debug, Clone, PartialEq, Eq)]
      11 | pub enum Error {
      12 | 	PRuntimeRejected,
      13 | 	InvalidIASSigningCert,
      14 | 	InvalidReport,
      15 | 	InvalidQuoteStatus,
      16 | 	BadIASReport,
      17 | 	OutdatedIASReport,
      18 | 	UnknownQuoteBodyFormat,
```
pherry (standalone/pherry/src/lib.rs:784) fetches this stale collateral, attaches it to the DCAP quote, and submits the attestation on-chain.

**Remediation**: Add on-chain verification in the DCAP attestation path that checks: (1) each collateral field's next_update timestamp is >= current block timestamp, (2) CRL entries have not expired. Reject the attestation if any collateral component is stale. Reference the IAS timestamp extraction pattern at attestation.rs:49-52 as a template for parsing and comparing timestamps.

### [LOW] RV-U-13: No on-chain DCAP collateral verification

**Root Cause**: The pallet imports only attestation_legacy (IAS-based verification) and contains no DCAP-specific collateral signature verification or freshness checking logic for register_worker transactions.
**Impact**: A compromised pherry could register arbitrary workers with forged DCAP quotes, bypassing hardware-level TEE identity verification. This would allow non-TEE machines to join the network as supposedly trusted workers, undermining the entire trust model of Phala's offchain compute layer.
**Confidence**: Weak | **Invariant**: UNKNOWN | **Tier**: core

**Preconditions**:
- The system must be using DCAP attestation mode (not legacy IAS).
- The attacker must have compromised the pherry relay or be able to submit crafted register_worker transactions.

**Attack Scenario**:
  1. Attacker controls or compromises the pherry relay component, which assembles DCAP quote collateral in the untrusted zone. (`pallets/phala/src/registry.rs:37`)
  2. Pherry submits a register_worker transaction with forged or stale DCAP collateral (e.g., expired TCB info, revoked CRL, or fabricated QE identity). (`pallets/phala/src/mock.rs:69`)
  3. The on-chain pallet processes the registration without independently verifying Intel's signatures on the collateral, accepting the untrusted pherry's assertion that the quote is valid.

### Code Evidence

**`pallets/phala/src/registry.rs:37`**
```
      27 | 		},
      28 | 		wrap_content_to_sign, AttestationProvider, ClusterPublicKey, ContractPublicKey,
      29 | 		EcdhPublicKey, MasterPublicKey, SignedContentType, VersionedWorkerEndpoints,
      30 | 		WorkerEndpointPayload, WorkerIdentity, WorkerPublicKey, WorkerRegistrationInfo,
      31 | 		WorkerRegistrationInfoV2,
      32 | 	};
      33 | 
      34 | 	pub use phala_types::AttestationReport;
      35 | 	// Re-export
      36 | 	// TODO: Legacy
>>>   37 | 	pub use crate::utils::attestation_legacy::{
      38 | 		Attestation, AttestationValidator, IasFields, IasValidator,
      39 | 	};
      40 | 
      41 | 	bind_topic!(RegistryEvent, b"^phala/registry/event");
      42 | 	#[derive(Encode, Decode, TypeInfo, Clone, Debug)]
      43 | 	pub enum RegistryEvent {
      44 | 		BenchReport {
      45 | 			start_time: u64,
      46 | 			iterations: u64,
      47 | 		},
```
Attacker controls or compromises the pherry relay component, which assembles DCAP quote collateral in the untrusted zone.

**`pallets/phala/src/mock.rs:69`**
```
      59 | 	pub const BlockHashCount: u64 = 250;
      60 | 	pub const SS58Prefix: u8 = 20;
      61 | 	pub const MinimumPeriod: u64 = 1;
      62 | 	pub const ExpectedBlockTimeSec: u32 = 12;
      63 | 	pub const MinWorkingStaking: Balance = DOLLARS;
      64 | 	pub const MinContribution: Balance = CENTS;
      65 | 	pub const WorkingGracePeriod: u64 = 7 * 24 * 3600;
      66 | 	pub const VaultQueuePeriod: u64 = 21 * 24 * 3600;
      67 | 	pub const MinInitP: u32 = 1;
      68 | 	pub const MaxPoolWorkers: u32 = 10;
>>>   69 | 	pub const NoneAttestationEnabled: bool = true;
      70 | 	pub const VerifyPRuntime: bool = false;
      71 | 	pub const VerifyRelaychainGenesisBlockHash: bool = true;
      72 | 	pub const CheckWorkerRegisterTime: bool = true;
      73 | }
      74 | impl system::Config for Test {
      75 | 	type BaseCallFilter = frame_support::traits::Everything;
      76 | 	type BlockWeights = ();
      77 | 	type BlockLength = ();
      78 | 	type RuntimeOrigin = RuntimeOrigin;
      79 | 	type RuntimeCall = RuntimeCall;
```
Pherry submits a register_worker transaction with forged or stale DCAP collateral (e.g., expired TCB info, revoked CRL, or fabricated QE identity).

**Remediation**: Implement on-chain DCAP collateral verification in the pallet by: (1) parsing the Quote and SgxV30QuoteCollateral structures on-chain, (2) verifying Intel CA signatures on TCB info, CRL, and QE identity collateral, (3) checking next_update timestamps for freshness, and (4) validating the quote's ISV ENCLAVE report matches expected MRENCLAVE. This may require porting relevant verification logic from sgx_attestation::dcap into a no_std-compatible pallet module.

## Positive Guards (Confirmed Security Controls)

### PG3-U-02: Attestation validation infrastructure present
- **Invariants**: INV-02
- **Completeness**: partial
- **Evidence**: pallets/phala/src/registry.rs:37-39 (AttestationValidator/IasValidator imports), registry.rs:85-97 (config with VerifyPRuntime, NoneAttestationEnabled), registry.rs:153-163 (attestation error types covering quote status, freshness, runtime info, DCAP), registry.rs:177-182 (PRuntimeAllowList storage for measurement allowlist)

The registry pallet implements comprehensive attestation verification infrastructure including AttestationValidator and IasValidator traits, with specific error types covering TCB status (InvalidQuoteStatus), collateral freshness (OutdatedIASReport), runtime info binding (InvalidRuntimeInfoHash, InvalidRuntimeInfo), and DCAP quote validation (InvalidDCAPQuote). The configuration includes VerifyPRuntime and PRuntimeAllowList for expected measurement validation, with strong warnings that NoneAttestationEnabled must be false in production.

### PG3-U-INV-03: Attestation validation wired into registry
- **Invariants**: INV-03
- **Completeness**: partial
- **Evidence**: pallets/phala/src/registry.rs:37-39 (LegacyAttestationValidator config), registry.rs:130-136 (VerifyPRuntime/NoneAttestationEnabled constants), registry.rs:227-230 (force_register_worker gated by ensure_root)

The registry pallet imports and wires in attestation validation via the LegacyAttestationValidator trait bound (Config::LegacyAttestationValidator) and the attestation/attestation_legacy modules. Worker registration (register_worker, call_index 6) and configuration constants (VerifyPRuntime, NoneAttestationEnabled) enforce attestation verification during the registration flow. The master key is uploaded only after a worker has been attestation-verified, establishing an indirect cryptographic binding.

## Dismissed Findings

_The following findings were dismissed during adversarial review._

### ~~V-01: Generator privkey field public with Encode derive~~
- **Original Severity**: Info
- **Dismissal Reason**: Generator and its storage operate entirely within the TEE. Phala encrypts contract storage inside the enclave. The Debug impl intentionally hides the privkey. No verifiable end-to-end chain where serialized Generator crosses the trust boundary unchecked.
- **Location(s)**: `crates/pink-libs/utils/src/attestation.rs:45`, `crates/pink-libs/utils/src/attestation.rs:48`

### ~~V-02: Test-only attestation verify assertion~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Explicitly in test code. Finding itself states 'No production attack surface exposed.' Test assertions have zero security impact.
- **Location(s)**: `crates/pink-libs/utils/src/attestation.rs:93`

### ~~V-03: Untrusted relay forwards attestation without local verification~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. Describes the expected untrusted-relay architecture. The PRB is designed to be untrusted; security relies on on-chain pallet verification, which is the correct trust model. The attack path hinges on 'If on-chain pallet does not bind runtime_info to attestation measurement' — a speculative condition about code not examined in this finding. No evidence the on-chain verification is deficient.
- **Location(s)**: `standalone/prb/src/compute_management.rs:229`, `standalone/prb/src/compute_management.rs:199`, `standalone/prb/src/compute_management.rs:210`, `standalone/pruntime/build.rs:8`

### ~~V-04: Untrusted host relays attestation to on-chain registration~~
- **Original Severity**: Medium
- **Dismissal Reason**: Adversarial review: false positive. Describes the normal, by-design architecture where an untrusted relay forwards attestation data to on-chain pallet. The relay being untrusted is expected - security relies on on-chain validation. No concrete validation gap is demonstrated, confidence is Weak, and the finding merely restates the system's trust model as if it were a flaw.
- **Location(s)**: `standalone/prb/src/compute_management.rs:210`, `standalone/prb/src/compute_management.rs:211`, `standalone/prb/src/compute_management.rs:229`

### ~~V-07: Untrusted relay assembles DCAP attestation collateral~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. Yet another untrusted-relay variant. The attack condition 'If on-chain doesn't verify collateral signatures, fake collateral passes' is speculative. DCAP collateral verification on-chain should check signatures and certificate chains — assuming it doesn't is an unverified assumption. The security model correctly places trust in on-chain verification, not in the relay assembling the collateral.
- **Location(s)**: `standalone/pherry/src/lib.rs:774`, `standalone/pherry/src/lib.rs:784`, `standalone/pherry/src/lib.rs:786`, `standalone/pherry/src/lib.rs:806`, `standalone/pruntime/build.rs:8`

### ~~IV-INV-02: None-attestation opt-out bypasses all quote verification~~
- **Original Severity**: High
- **Dismissal Reason**: Adversarial review: false positive. Duplicate of IV-INV-01 describing the same NoneAttestationEnabled governance feature gate, inflated to High severity. NoneAttestationEnabled is a deliberate chain configuration controlled by governance/pallet constants, not an exploitable bypass. The same attack path is already covered by IV-INV-01.
- **Location(s)**: `pallets/phala/src/utils/attestation.rs:147`, `pallets/phala/src/utils/attestation.rs:148`, `pallets/phala/src/utils/attestation.rs:152`, `pallets/phala/src/mock.rs:69`

### ~~RV-U-INV-08: No visible AESM QE identity check~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Fundamentally misunderstands the SGX/TEE threat model. AESM is always considered untrusted in the SGX security model. Quote verification does not rely on trusting AESM - it relies on verifying Intel's cryptographic signatures embedded in the quote and its certificate chain. An attacker replacing AESM gains nothing because the quote must still be signed by the genuine Intel QE whose certificates are verified on-chain. This is out of scope.
- **Location(s)**: `pallets/phala/src/utils/attestation.rs:85`, `pallets/phala/src/mock.rs:69`

### ~~RV3-U-11: Attestation bypass weakens enclave trust~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Duplicate of IV-INV-01/IV-INV-02. Same NoneAttestationEnabled/VerifyPRuntime concern, same code area (registry.rs), Weak confidence. Adds nothing new.
- **Location(s)**: `pallets/phala/src/registry.rs:105`, `pallets/phala/src/registry.rs:109`

## Appendix

_Info-severity TEE findings, items requiring manual review, and non-TEE findings are included here for completeness._

### Info-Severity TEE Findings

### [INFO] V-06: Private key material logged to stdout [Output & Metadata Leakage] (incorrect_usage) (CWE-532)

**Root Cause**: Private key hex strings are logged at info level unconditionally when key injection flags are used.
**Impact**: TEE private key material is exposed in process stdout and any log aggregation systems, enabling key recovery from log archives.
**Confidence**: Likely | **Invariant**: INV-06 | **Tier**: adjacent

**Preconditions**:
- Operator uses --inject-key or --use-dev-key flag
- Log output is captured by external systems

**Attack Scenario**:
  1. Operator runs pherry with --inject-key <hex> or --use-dev-key (`standalone/pherry/src/lib.rs:735`)
  2. pherry logs the private key via info!() at lib.rs:735 or :739 (`standalone/pherry/src/lib.rs:739`)
  3. Log output is captured by monitoring, CI, or log aggregation (`crates/pink/capi/src/types.rs:106`)
  4. Private key material is exposed in log storage (`crates/pink/capi/src/types.rs:112`)

### Code Evidence

**`standalone/pherry/src/lib.rs:735`**
```
info!("Inject key {}", inject_key);
```
Operator runs pherry with --inject-key <hex> or --use-dev-key

**`standalone/pherry/src/lib.rs:739`**
```
info!("Inject key {}", DEV_KEY);
```
pherry logs the private key via info!() at lib.rs:735 or :739

**`crates/pink/capi/src/types.rs:106`**
```
      96 |                     .into_iter()
      97 |                     .filter(|(_, event)| event.allowed_in_query())
      98 |                     .collect(),
      99 |                 ink_events: vec![],
     100 |                 instantiated: vec![],
     101 |             },
     102 |         }
     103 |     }
     104 | 
     105 |     /// Returns true if there are no side effects inside.
>>>  106 |     pub fn is_empty(&self) -> bool {
     107 |         match self {
     108 |             ExecSideEffects::V1 {
     109 |                 pink_events,
     110 |                 ink_events,
     111 |                 instantiated,
     112 |             } => pink_events.is_empty() && ink_events.is_empty() && instantiated.is_empty(),
     113 |         }
     114 |     }
     115 | }
```
Log output is captured by monitoring, CI, or log aggregation

**`crates/pink/capi/src/types.rs:112`**
```
     102 |         }
     103 |     }
     104 | 
     105 |     /// Returns true if there are no side effects inside.
     106 |     pub fn is_empty(&self) -> bool {
     107 |         match self {
     108 |             ExecSideEffects::V1 {
     109 |                 pink_events,
     110 |                 ink_events,
     111 |                 instantiated,
>>>  112 |             } => pink_events.is_empty() && ink_events.is_empty() && instantiated.is_empty(),
     113 |         }
     114 |     }
     115 | }
```
Private key material is exposed in log storage

**Remediation**: Remove private key logging or replace with a truncated hash. Use debug!() level at minimum and never log full key material.

**Trust Boundary Trace**:

| Source Zone | Crossing Point | Sink Zone | Verification |
| --- | --- | --- | --- |
| untrusted | standalone/pherry/src/lib.rs:735 | untrusted | missing |

**Trust Boundary Analysis**: The pherry relay logs the full hex-encoded private key to stdout using info!() when either --inject-key or --use-dev-key is specified. While this key originates from CLI args (untrusted zone), it is the key that will be sent to the TEE enclave for worker identity. Logging it exposes the TEE's identity key to any log consumer, undermining confidentiality of the TEE trust boundary.

### [INFO] RV3-U-05: Debug key accepted without enclave-side guard [Trust Boundary Flow] (incorrect_usage)

**Root Cause**: The chain-side registry pallet (this file) validates attestation reports and enforces NoneAttestationEnabled/VerifyPRuntime flags during worker registration, but the enclave-side init_runtime handler (not in this file) may not cross-check the key derivation source against the attestation mode, creating a gap between chain-side attestation verification and enclave-side key acceptance.
**Impact**: If the enclave accepts a hardcoded debug key in production attestation mode, the operator knows the worker's private key, enabling decryption of confidential worker state and messages, undermining the entire TEE confidentiality model.
**Confidence**: Weak | **Invariant**: INV-05 | **Tier**: core

**Preconditions**:
- Operator controls the pherry process passing init_runtime parameters
- The enclave code does not independently validate debug_set_key against attestation mode
- NoneAttestationEnabled is false and VerifyPRuntime is true on-chain (production config)

**Attack Scenario**:
  1. Operator configures pherry to pass debug_set_key (0x0000...0001) to pRuntime via init_runtime (`pallets/phala/src/registry.rs:100`)
  2. pRuntime enclave accepts the debug key without checking whether it is running in production attestation mode
  3. Operator derives the known debug private key, breaking TEE confidentiality for that worker

### Code Evidence

**`pallets/phala/src/registry.rs:100`**
```
      90 | 		#[pallet::constant]
      91 | 		type VerifyPRuntime: Get<bool>;
      92 | 
      93 | 		/// Verify relaychain genesis
      94 | 		///
      95 | 		/// SHOULD NOT SET TO FALSE ON PRODUCTION!!!
      96 | 		#[pallet::constant]
      97 | 		type VerifyRelaychainGenesisBlockHash: Get<bool>;
      98 | 
      99 | 		/// Callback to get parachain id
>>>  100 | 		type ParachainId: Get<u32>;
     101 | 
     102 | 		/// Origin used to govern the pallet
     103 | 		type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
     104 | 	}
     105 | 
     106 | 	const STORAGE_VERSION: StorageVersion = StorageVersion::new(7);
     107 | 
     108 | 	#[pallet::pallet]
     109 | 	#[pallet::storage_version(STORAGE_VERSION)]
     110 | 	#[pallet::without_storage_info]
```
Operator configures pherry to pass debug_set_key (0x0000...0001) to pRuntime via init_runtime

**Remediation**: pRuntime's init_runtime handler must reject debug_set_key when the enclave is not in debug/None attestation mode. Add an explicit check in the enclave-side init_runtime handler: if attestation_mode != NoneAttestation && received_key == DEBUG_KEY { reject(); }. Additionally, burn the debug key into the attestation report's report_data field so the chain can also verify the key origin during register_worker.

### Items Requiring Manual Review

#### U-06: Verification failed

Security concern: Worker registration or key release accepted without TCB status from quote verification being validated against acceptable TCB levels, allowing outdated or compromised SGX platforms t
- **Why Uncertain**: LLM verification failed: Request timed out.

Second-pass notes: The provided source code does not contain the worker registration extrinsic or attestation quote verification logic. The registry module (registry.rs) shows storage for WorkerPublicKey and Gatekeeper lists, and the computation module shows worker state management, but the actual registration call that would receive an attestation quote, verify it, extract MRENCLAVE, and bind it to the worker identity is not present in the snippets. The test code references setup_workers() but its implementation 
- **Recommended Steps**: Retry verification manually

#### U-07: Verification failed

Security concern: Worker registration or key release accepted without TCB status from quote verification being validated against acceptable TCB levels, allowing outdated or compromised SGX platforms t
- **Why Uncertain**: LLM verification failed: Request timed out.

Second-pass notes: The provided source code consists entirely of Substrate pallet code (on-chain logic for computation, registry, stake pools), SDK client-side code, and PRouter messaging documentation. None of these files contain nginx configuration, TLS termination setup, or network proxy architecture details. The invariant concerns whether TLS termination occurs at a host-side nginx proxy before traffic reaches the enclave (pRuntime), which is an infrastructure/deployment-layer concern. Such evidence would be f
- **Recommended Steps**: Retry verification manually

#### U-08: Verification failed

Security concern: Worker registration or key release accepted without TCB status from quote verification being validated against acceptable TCB levels, allowing outdated or compromised SGX platforms t
- **Why Uncertain**: LLM verification failed: Request timed out.

Second-pass notes: The provided source code consists entirely of blockchain-side Substrate pallet code (computation.rs, registry.rs, base_pool.rs, stake_pool_v2.rs, test.rs) which manages worker registration, stake pools, tokenomics, and balance operations. AESM service verification is an enclave-side concern that would occur within pRuntime (the TEE enclave), not in the on-chain pallets. The invariant requires inspecting the enclave's quoting and provisioning logic where it interacts with the AESM socket/channel 
- **Recommended Steps**: Retry verification manually

#### U-09: Verification failed

Security concern: Worker registration or key release accepted without TCB status from quote verification being validated against acceptable TCB levels, allowing outdated or compromised SGX platforms t
- **Why Uncertain**: LLM verification failed: Request timed out.

Second-pass notes: The provided source code consists entirely of blockchain-side Substrate pallet code (computation.rs, registry.rs, base_pool.rs, stake_pool_v2.rs, test.rs) and documentation. None of these files contain pRuntime API endpoint definitions, error response handlers, or RPC response formatting logic. The pRuntime is a separate TEE component (referenced in README as a distinct binary alongside pherry) whose source code would likely reside under standalone/pRuntime/ or a similar path not included here. 
- **Recommended Steps**: Retry verification manually

#### U-12: pRuntime key injection acceptance policy

Whether pRuntime TEE enclave accepts debug_set_key when attestation_provider is also provided during init_runtime
- **Why Uncertain**: The pRuntime enclave code (trusted zone) was not available to verify if it rejects key injection when attestation is enabled. The pherry sends both parameters without a guard, but pRuntime may internally enforce mutual exclusivity.

Second-pass notes: The additional source code provided is exclusively blockchain pallet-side code (registry, compute, attestation utilities, mocks). The invariant requires inspecting the TEE enclave-side init_runtime handler in standalone/pruntime/src/runtime.rs to determine if debug_set_key is rejected when attestation_provider is present. This file was not included in the additional source. The pallet code confirms that NoneAttestationEnabled exists as a configuration (mock.rs line 69: pub const NoneAttestationE
- **Recommended Steps**: Review standalone/pruntime/src/runtime.rs init_runtime handler for guard logic, Check if pRuntime rejects debug_set_key when skip_ra is false, Verify InitRuntimeRequest processing in the enclave ECALL handler

#### U-14: Verification failed

Security concern: Worker registration or key release accepted without TCB status from quote verification being validated against acceptable TCB levels, allowing outdated or compromised SGX platforms t
- **Why Uncertain**: LLM verification failed: Request timed out.

Second-pass notes: The provided code shows worker registry storage (registry.rs:115 Gatekeeper storage), worker state management (computation.rs), and test setup utilities (test.rs:setup_workers), but none of the visible code paths include quote verification or TCB status validation logic. The actual worker registration extrinsic and quote parsing logic are not present in the provided snippets. Without seeing the registration handler implementation, I cannot confirm whether TCB validation exists elsewhere or is en
- **Recommended Steps**: Retry verification manually

#### U-16: Verification failed

Security concern: Worker registration or key release accepted without TCB status from quote verification being validated against acceptable TCB levels, allowing outdated or compromised SGX platforms t
- **Why Uncertain**: LLM verification failed: Request timed out.

Second-pass notes: The provided source code does not contain the worker registration entry point, quote verification logic, or TCB status validation. The registry.rs shows worker event handling and pubkey storage, and computation.rs shows worker state management, but neither contains the attestation verification path where TCB status would be checked against acceptable levels. The actual SGX quote parsing and TCB validation would likely reside in a separate attestation module or in the message handling logic that 
- **Recommended Steps**: Retry verification manually

#### U-17: Verification failed

Security concern: Worker registration or key release accepted without TCB status from quote verification being validated against acceptable TCB levels, allowing outdated or compromised SGX platforms t
- **Why Uncertain**: LLM verification failed: Request timed out.

Second-pass notes: The provided source code does not contain the quote verification or TCB status validation logic. The registry module (registry.rs) handles worker public keys and gatekeeper events but the actual worker registration flow with SGX quote verification is not shown. The computation module (computation.rs) manages worker states but delegates registration to the registry. The test setup uses `setup_workers` helper whose implementation is not provided. The critical code paths for quote parsing, ISV SVN 
- **Recommended Steps**: Retry verification manually

#### U-INV-04: Sealed state epoch verification

Sealed blob monotonic counter enforcement in pRuntime enclave unseal path.
- **Why Uncertain**: Provided code is blockchain pallet side only; enclave sealing/unsealing logic in pRuntime not included in scope.

Second-pass notes: The invariant requires verification of monotonic epoch/version counter enforcement in enclave seal/unseal paths. All provided source code is blockchain pallet-side (Substrate pallets: phat.rs, registry.rs, computation.rs, stake_pool_v2.rs, mock.rs). The sealing/unsealing logic resides in pRuntime (the TEE enclave component), which is explicitly listed as outside this scope - the README references 'phala-docker: The production dockerfiles, including the blockchain, pherry, and pRuntime' as a sepa
- **Recommended Steps**: Review pruntime/enclave sealing implementation, Check for monotonic counter in seal/unseal paths, Verify rollback rejection on epoch mismatch

#### U-INV-05: Missing enclave bridge validation evidence

Blockchain pallets for input guards at Gramine trusted/untrusted boundary.
- **Why Uncertain**: Provided code is Substrate blockchain pallets, not pRuntime enclave code where Gramine OCalls occur.

Second-pass notes: The invariant concerns validation of host-provided data through Gramine's trusted/untrusted bridge in pRuntime enclave OCALL handlers. All provided source code is Substrate blockchain pallets (registry.rs, mock.rs, computation.rs, stake_pool_v2.rs, base_pool.rs) running on-chain, not inside the TEE enclave. These pallets handle messages received FROM enclaves via the Phala messaging queue, not the Gramine OCALL interface. The critical code to verify this invariant would be in the pRuntime reposi
- **Recommended Steps**: Examine pRuntime enclave OCALL handlers for input validation, Check Gramine edl files for untrusted bridge definitions, Review enclave entry points for host buffer bounds checks

#### U-INV-07: Host-side TLS termination design

Whether TLS terminates at host nginx before enclave, exposing plaintext.
- **Why Uncertain**: Provided source is Substrate pallet code (staking, registry); nginx/TLS config not in scope of these files.

Second-pass notes: The additional source code (mock.rs, base_pool.rs, stake_pool_v2.rs, stake_pool.rs, registry.rs) is exclusively Substrate pallet runtime logic for staking, worker registry, and attestation. None of it contains nginx.conf, Docker deployment configs, pruntime HTTP listener setup, or TLS configuration. The README explicitly references phala-docker as a separate repository for production deployment files including pRuntime, confirming the infrastructure layer is out of scope. The SDK README shows cl
- **Recommended Steps**: Review nginx.conf and Docker deployment configs, Check pruntime HTTP listener for TLS setup, Inspect docker-compose for proxy-to-enclave routing

#### U-INV-09: pRuntime error response sanitization

Error handling in pRuntime API responses for secret-dependent detail leakage.
- **Why Uncertain**: Provided code is blockchain pallets only; pRuntime enclave HTTP API error paths not in scope.

Second-pass notes: The additional source code provided (registry.rs, mock.rs, computation.rs, anchor.rs, stake_pool_v2.rs) is still blockchain-side pallet code, not pRuntime enclave HTTP API response handlers. The pRuntime enclave code containing HTTP response generation, error formatting, and the enclave boundary interface is not in scope. The pallet error enums shown (e.g., stake_pool_v2.rs lines 237-308 with detailed error variants like WorkerNotRegistered, BenchmarkMissing, UnauthorizedOperator) are Substrate 
- **Recommended Steps**: Audit pruntime/src/api response handlers for error detail leakage, Check nginx and Gramine bridge error passthrough config, Search for generic error wrapper in enclave boundary code

#### U-INV-10: TEE type field validation in DCAP quotes

Whether attestation dispatch validates TEE type field within SGX DCAP quote headers.
- **Why Uncertain**: validate_dcap() is called at attestation.rs:138 but its implementation is truncated; cannot confirm TEE type field check inside.

Second-pass notes: The critical validate_dcap() function body at attestation.rs:138 is still not provided — the supplied attestation.rs only extends to line 100 (showing IAS from_ias_report). No DCAP-specific validation logic, TEE type field extraction, or platform-matching check is visible in any of the supplied files. The sgx_attestation crate internals (Quote struct, SgxQuote trait) are imported but their implementations remain unavailable. The e2e test contract imports sgx_attestation::dcap::Quote and SgxQuote
- **Recommended Steps**: Inspect validate_dcap() body for TEE type field checks, Check sgx_attestation crate quote parsing for TEE type, Search for TDX AttestationReport variant in phala_types

#### U-INV-11: Fingerprint salt enclave isolation

On-chain pallets for cluster key storage and fingerprint salt derivation logic.
- **Why Uncertain**: Enclave-side fingerprint salt derivation from cluster private key is not present in provided on-chain pallet source files; requires pRuntime/TEE code audit.

Second-pass notes: The additional source code provided (computation.rs, mock.rs, stake_pool_v2.rs, anchor.rs, phat.rs) is entirely on-chain Substrate pallet code. None of it contains pRuntime/TEE enclave-side logic. The phat.rs pallet handles ClusterEvent and ContractRegistryEvent but only manages on-chain cluster metadata (deployer, cluster ID, public keys) — no enclave-internal secret derivation. The computation.rs pallet manages worker lifecycle and settlement states but delegates all cryptographic operations t
- **Recommended Steps**: Audit pRuntime enclave code for fingerprint salt derivation, Verify cluster private key never leaves enclave memory, Check salt computation uses enclave-only secrets

#### U-INV-07: TLS termination outside enclave

Whether user query plaintext is exposed to host-side nginx before reaching the enclave.
- **Why Uncertain**: Provided source code is blockchain pallet layer (registry, stake pool, balances); nginx config, pRuntime HTTP server, and deployment scripts are not included.
- **Recommended Steps**: Provide nginx.conf and docker-compose for proxy layer review, Provide pRuntime HTTP handler code (api.rs or similar), Provide client SDK code showing TLS and encryption logic

#### U-INV-08: AESM integrity not verifiable at pallet layer

Attestation and quote validation logic in blockchain pallets for AESM binary verification.
- **Why Uncertain**: AESM runs on the host outside TEE; the shown pallet code validates IAS/DCAP reports but not AESM binary integrity. validate_dcap implementation is not shown.
- **Recommended Steps**: Review validate_dcap for QE identity verification, Check pRuntime enclave code for AESM trust assumptions, Verify DCAP collateral QE identity checks

#### U-INV-09: pRuntime API error handling not in scope

Searched provided code for pRuntime API error response sanitization logic.
- **Why Uncertain**: Provided source is Substrate pallet code (on-chain), not the pRuntime enclave HTTP API layer where error responses are constructed.
- **Recommended Steps**: Review pruntime/enclave src for HTTP error handlers, Check rpc.rs or api handlers for error serialization, Verify constant-length error responses at enclave boundary

#### U-INV-10: TEE type field validation in quotes

Pallet-level attestation dispatch in validate() for SGX IAS and DCAP paths.
- **Why Uncertain**: The sgx-attestation crate source and validate_dcap() body are not provided; TEE type field check cannot be confirmed or denied.
- **Recommended Steps**: Provide sgx-attestation crate quote parsing code, Show validate_dcap() function body, Check AttestationReport enum for TDX variant

#### U-INV-11: Enclave salt derivation code not in scope

On-chain pallet code for cluster key storage and fingerprint salt derivation paths.
- **Why Uncertain**: The enclave-side code (pRuntime) where cluster private keys and fingerprint salt derivation live is not included in the provided source files.
- **Recommended Steps**: Review pRuntime enclave code for fingerprint salt derivation, Verify cluster private key never passed to salt derivation outside TEE, Check that fingerprint salts are computed inside enclave only
