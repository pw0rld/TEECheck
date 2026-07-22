# TEE Usage Audit Report: suave-geth

## Executive Summary
This audit examined the provided codebase for TEE security properties. The core finding is structural: no enclave implementation, attestation logic, or TEE boundary exists in the audited code. The codebase consists of standard go-ethereum library components (trie sync, RLP encoding, interface definitions) with zero SGX/TEE integration.

**Active Findings (2)**:
- V-04 (Medium): SSRF via insufficient URL validation in faucet authentication
- IV-INV-09 (Medium): Unsanitized error leakage via RLP decode

Both are application-level vulnerabilities with no TEE boundary interaction. 12 additional findings (V-01 through V-12) were dismissed to a separate appendix as explicitly non-TEE-relevant — they should not appear in the active findings list.

**Positive Guards Confirmed**: 0 of 22 checked. No TEE-related defensive patterns were found.

**Architectural Gaps (22 Unknowns)**: These are not vulnerabilities in existing TEE usage — they represent absent TEE primitives. The codebase lacks:
- Attestation: No quote generation, report_data construction, MRENCLAVE comparison, TCB verification, or collateral freshness logic (U-INV-03, U-INV-04, U-INV-11, U-INV-12)
- Sealing: No seal/unseal APIs, no monotonic counters, no anti-rollback protection (U-INV-05, U-INV-06)
- Boundary validation: No ECALL parameter validation, no OCALL return value verification (U-INV-01, U-INV-02)
- Configuration: No SGX debug flag checks (U-INV-07)
- Encryption: No encryption guards before host-side data writes (U-INV-10)
- **Binding (distinct gap)**: No MRENCLAVE/MRSIGNER identity binding, no key-to-enclave binding logic, no seal policy enforcement exists anywhere in the codebase

**Recommendation**: Before TEE security can be audited meaningfully, an actual enclave integration must be implemented. The current remediation path is architectural design and build, not patching specific TEE misuse.

## Dashboard Summary

| Severity | Trust-Path Tier | Count |
| --- | --- | --- |
| Medium | core | 1 |

## Trust Boundary Analysis

| Actor | Component | Context | Boundary Type |
| --- | --- | --- | --- |
| SGX Enclave | Confidential TX & Auction Engine | trusted | enclave/host |
| suave-geth Host Process | Ethereum Client Stack (p2p, sync, RPC) | untrusted | enclave/host |
| SGX SDK ECALL/OCALL Bridge | C/C++ Integration Layer | mixed | enclave/host |
| Account/Keystore | Key Management (accounts/keystore/) | trusted | crypto boundary |
| GraphQL/JSON-RPC API | External dApp/User Interface | untrusted | network |
| P2P Networking Layer | Inter-node Communication (p2p/, les/) | untrusted | network |
| Beacon Chain Integration | Consensus Layer Support (beacon/dencun) | untrusted | network |
| Core Blockchain | State Management (core/blockchain.go) | trusted | storage |
| Consensus Engine | Beacon + Clique (consensus/) | trusted | consensus |
| Dockerfile.suave | TEE-Enabled Binary Build Target | mixed | provisioning/build |
| Attestation Service | Remote Attestation Verification | untrusted | network |

## Trust Boundary Partition Evidence

### Partition Methodology

**Path and content heuristics** classified files by directory patterns (enclave/, host/, trusted/) and TEE API usage (sgx_trts, sgx_urts, attestation).

### Source Code Zone Partition

```
├── (root)/  🟢 Trusted (1 file)
│   └── ./  🟢 Trusted (1 file)
├── accounts/  🟡 Mixed (12 trusted, 1 mixed)
│   ├── abi/  🟢 Trusted (2 files)
│   ├── abi/bind/  🟢 Trusted (3 files)
│   ├── abi/bind/backends/  🟢 Trusted (2 files)
│   ├── keystore/  🟢 Trusted (2 files)
│   ├── scwallet/  🟢 Trusted (1 file)
│   ├── usbwallet/  🟢 Trusted (2 files)
│   └── usbwallet/trezor/  🟡 Mixed (1 mixed)
│       └── 🟡 messages-management.pb.go
├── beacon/  🟢 Trusted (4 files)
│   ├── params/  🟢 Trusted (1 file)
│   └── types/  🟢 Trusted (3 files)  — type definitions
├── cmd/  🟡 Mixed (17 trusted, 2 mixed)  — CLI commands
│   ├── clef/  🟡 Mixed (1 mixed)
│   │   └── 🟡 main.go
│   ├── devp2p/  🟢 Trusted (3 files)
│   ├── devp2p/internal/ethtest/  🟢 Trusted (2 files)
│   ├── devp2p/internal/v4test/  🟢 Trusted (1 file)
│   ├── evm/  🟢 Trusted (2 files)
│   ├── faucet/  🟢 Trusted (1 file)
│   ├── geth/  🟢 Trusted (8 files)
│   └── utils/  🟡 Mixed (1 mixed)  — utilities
│       └── 🟡 flags.go
├── common/  🟢 Trusted (4 files)
│   ├── hexutil/  🟢 Trusted (2 files)
│   └── math/  🟢 Trusted (2 files)
├── consensus/  🟢 Trusted (7 files)
│   ├── ./  🟢 Trusted (1 file)
│   ├── beacon/  🟢 Trusted (1 file)
│   ├── clique/  🟢 Trusted (3 files)
│   └── ethash/  🟢 Trusted (2 files)
├── console/  🟢 Trusted (2 files)
│   └── ./  🟢 Trusted (2 files)
├── core/  🟡 Mixed (63 trusted, 5 mixed)  — core logic
│   ├── ./  🟡 Mixed (11 trusted, 1 mixed)  — core logic
│   │   ├── 🟡 blockchain_test.go
│   │   ├── 🟢 bench_test.go
│   │   ├── 🟢 block_validator_test.go
│   │   ├── 🟢 blockchain.go
│   │   ├── 🟢 blockchain_insert.go
│   │   ├── 🟢 chain_indexer.go
│   │   ├── 🟢 error.go
│   │   ├── 🟢 forkchoice.go
│   │   ├── 🟢 genesis.go
│   │   ├── 🟢 headerchain.go
│   │   ├── 🟢 mkalloc.go
│   │   └── 🟢 state_processor_test.go
│   ├── asm/  🟢 Trusted (1 file)
│   ├── bloombits/  🟢 Trusted (1 file)
│   ├── forkid/  🟢 Trusted (1 file)
│   ├── rawdb/  🟢 Trusted (10 files)
│   ├── state/  🟡 Mixed (5 trusted, 1 mixed)
│   │   ├── 🟡 statedb.go
│   │   ├── 🟢 iterator.go
│   │   ├── 🟢 iterator_test.go
│   │   ├── 🟢 statedb_test.go
│   │   ├── 🟢 sync_test.go
│   │   └── 🟢 trie_prefetcher.go
│   ├── state/pruner/  🟢 Trusted (2 files)
│   ├── state/snapshot/  🟢 Trusted (9 files)
│   ├── txpool/  🟡 Mixed (2 trusted, 2 mixed)
│   │   ├── 🟡 txpool.go
│   │   ├── 🟡 txpool_test.go
│   │   ├── 🟢 journal.go
│   │   └── 🟢 list.go
│   ├── types/  🟢 Trusted (6 files)  — type definitions
│   ├── vm/  🟡 Mixed (14 trusted, 1 mixed)
│   │   ├── 🟡 gas_table.go
│   │   ├── 🟢 contract.go
│   │   ├── 🟢 contracts_suave.go
│   │   ├── 🟢 contracts_suave_eth.go
│   │   ├── 🟢 contracts_test.go
│   │   ├── 🟢 eips.go
│   │   ├── 🟢 evm.go
│   │   ├── 🟢 instructions.go
│   │   ├── 🟢 instructions_test.go
│   │   ├── 🟢 interface.go
│   │   ├── 🟢 jump_table.go
│   │   ├── 🟢 memory_table.go
│   │   ├── 🟢 opcodes.go
│   │   ├── 🟢 operations_acl.go
│   │   └── 🟢 suave.go
│   └── vm/runtime/  🟢 Trusted (1 file)  — runtime engine
├── crypto/  🟢 Trusted (15 files)  — cryptography
│   ├── ./  🟢 Trusted (1 file)  — cryptography
│   ├── secp256k1/libsecp256k1/contrib/  🟢 Trusted (2 files)
│   ├── secp256k1/libsecp256k1/include/  🟢 Trusted (2 files)
│   ├── secp256k1/libsecp256k1/src/  🟢 Trusted (7 files)
│   ├── secp256k1/libsecp256k1/src/modules/recovery/  🟢 Trusted (1 file)
│   └── signify/  🟢 Trusted (2 files)
├── eth/  🟡 Mixed (30 trusted, 7 mixed)
│   ├── ./  🟡 Mixed (6 trusted, 2 mixed)
│   │   ├── 🟡 backend.go
│   │   ├── 🟡 handler.go
│   │   ├── 🟢 api.go
│   │   ├── 🟢 api_backend.go
│   │   ├── 🟢 bloombits.go
│   │   ├── 🟢 handler_eth_test.go
│   │   ├── 🟢 handler_test.go
│   │   └── 🟢 state_accessor.go
│   ├── catalyst/  🟡 Mixed (2 trusted, 1 mixed)
│   │   ├── 🟡 api.go
│   │   ├── 🟢 api_test.go
│   │   └── 🟢 tester.go
│   ├── downloader/  🟡 Mixed (4 trusted, 2 mixed)
│   │   ├── 🟡 beaconsync.go
│   │   ├── 🟡 downloader.go
│   │   ├── 🟢 downloader_test.go
│   │   ├── 🟢 fetchers_concurrent.go
│   │   ├── 🟢 queue.go
│   │   └── 🟢 skeleton.go
│   ├── ethconfig/  🟢 Trusted (1 file)
│   ├── filters/  🟢 Trusted (3 files)
│   ├── gasprice/  🟢 Trusted (1 file)
│   ├── protocols/eth/  🟢 Trusted (1 file)
│   ├── protocols/snap/  🟡 Mixed (2 trusted, 1 mixed)
│   │   ├── 🟡 sync.go
│   │   ├── 🟢 handler.go
│   │   └── 🟢 sync_test.go
│   ├── tracers/  🟡 Mixed (2 trusted, 1 mixed)
│   │   ├── 🟡 api.go
│   │   ├── 🟢 api_test.go
│   │   └── 🟢 tracers_test.go
│   ├── tracers/internal/tracetest/  🟢 Trusted (1 file)
│   ├── tracers/js/  🟢 Trusted (2 files)  — JS bindings
│   ├── tracers/logger/  🟢 Trusted (2 files)
│   └── tracers/native/  🟢 Trusted (3 files)
├── ethclient/  🟡 Mixed (2 trusted, 1 mixed)
│   ├── ./  🟡 Mixed (1 trusted, 1 mixed)
│   │   ├── 🟡 ethclient.go
│   │   └── 🟢 ethclient_test.go
│   └── gethclient/  🟢 Trusted (1 file)
├── ethdb/  🟢 Trusted (5 files)
│   ├── ./  🟢 Trusted (2 files)
│   ├── leveldb/  🟢 Trusted (1 file)
│   ├── pebble/  🟢 Trusted (1 file)
│   └── remotedb/  🟢 Trusted (1 file)
├── ethstats/  🟢 Trusted (1 file)
│   └── ./  🟢 Trusted (1 file)
├── event/  🟢 Trusted (1 file)
│   └── ./  🟢 Trusted (1 file)
├── graphql/  🟡 Mixed (1 trusted, 1 mixed)
│   ├── ./  🟢 Trusted (1 file)
│   └── internal/graphiql/  🟡 Mixed (1 mixed)
│       └── 🟡 graphiql.min.js
├── internal/  🟢 Trusted (9 files)
│   ├── debug/  🟢 Trusted (1 file)
│   ├── ethapi/  🟢 Trusted (4 files)
│   ├── jsre/  🟢 Trusted (1 file)
│   ├── shutdowncheck/  🟢 Trusted (1 file)
│   ├── utesting/  🟢 Trusted (1 file)
│   └── web3ext/  🟢 Trusted (1 file)
├── les/  🟡 Mixed (22 trusted, 27 untrusted, 1 mixed)
│   ├── ./  🟡 Mixed (15 trusted, 1 mixed)
│   │   ├── 🟡 fetcher.go
│   │   ├── 🟢 api.go
│   │   ├── 🟢 api_backend.go
│   │   ├── 🟢 api_test.go
│   │   ├── 🟢 benchmark.go
│   │   ├── 🟢 bloombits.go
│   │   ├── 🟢 client.go
│   │   ├── 🟢 client_handler.go
│   │   ├── 🟢 odr.go
│   │   ├── 🟢 odr_test.go
│   │   ├── 🟢 peer.go
│   │   ├── 🟢 retrieve.go
│   │   ├── 🟢 server.go
│   │   ├── 🟢 server_requests.go
│   │   └── 🟢 test_helper.go
│   │       ... 1 more files
│   ├── catalyst/  🟢 Trusted (1 file)
│   ├── downloader/  🟢 Trusted (4 files)
│   ├── flowcontrol/  🟢 Trusted (2 files)
│   ├── vflux/client/  🔴 Untrusted (15 files)  — client code
│   └── vflux/server/  🔴 Untrusted (12 files)  — server logic
├── light/  🟢 Trusted (6 files)
│   └── ./  🟢 Trusted (6 files)
├── log/  🟢 Trusted (4 files)
│   └── ./  🟢 Trusted (4 files)
├── metrics/  🟢 Trusted (7 files)
│   ├── ./  🟢 Trusted (3 files)
│   ├── exp/  🟢 Trusted (1 file)
│   ├── influxdb/  🟢 Trusted (2 files)
│   └── librato/  🟢 Trusted (1 file)
├── miner/  🟡 Mixed (4 trusted, 2 mixed)
│   ├── ./  🟡 Mixed (3 trusted, 2 mixed)
│   │   ├── 🟡 unconfirmed.go
│   │   ├── 🟡 worker.go
│   │   ├── 🟢 miner.go
│   │   ├── 🟢 payload_building.go
│   │   └── 🟢 worker_test.go
│   └── stress/clique/  🟢 Trusted (1 file)
├── node/  🟡 Mixed (6 trusted, 1 mixed)
│   └── ./  🟡 Mixed (6 trusted, 1 mixed)
│       ├── 🟡 config.go
│       ├── 🟢 api.go
│       ├── 🟢 config_test.go
│       ├── 🟢 doc.go
│       ├── 🟢 node.go
│       ├── 🟢 node_test.go
│       └── 🟢 rpcstack_test.go
├── p2p/  🟡 Mixed (13 trusted, 4 mixed)
│   ├── ./  🟡 Mixed (2 trusted, 1 mixed)
│   │   ├── 🟡 peer.go
│   │   ├── 🟢 server.go
│   │   └── 🟢 server_test.go
│   ├── discover/  🟡 Mixed (3 trusted, 1 mixed)
│   │   ├── 🟡 v5_udp.go
│   │   ├── 🟢 table.go
│   │   ├── 🟢 v4_udp_test.go
│   │   └── 🟢 v5_udp_test.go
│   ├── enode/  🟢 Trusted (2 files)
│   ├── enr/  🟢 Trusted (1 file)
│   ├── msgrate/  🟡 Mixed (1 mixed)
│   │   └── 🟡 msgrate.go
│   ├── netutil/  🟢 Trusted (1 file)
│   ├── nodestate/  🟢 Trusted (1 file)
│   ├── rlpx/  🟢 Trusted (2 files)
│   ├── simulations/  🟢 Trusted (1 file)
│   └── simulations/adapters/  🟡 Mixed (1 mixed)
│       └── 🟡 exec.go
├── params/  🟡 Mixed (1 trusted, 1 mixed)
│   └── ./  🟡 Mixed (1 trusted, 1 mixed)
│       ├── 🟡 config.go
│       └── 🟢 protocol_params.go
├── rlp/  🟢 Trusted (4 files)
│   ├── ./  🟢 Trusted (3 files)
│   └── rlpgen/  🟢 Trusted (1 file)
├── rpc/  🟢 Trusted (4 files)  — RPC interface
│   └── ./  🟢 Trusted (4 files)  — RPC interface
├── signer/  🟢 Trusted (9 files)  — signing
│   ├── core/  🟢 Trusted (3 files)  — core logic
│   ├── fourbyte/  🟢 Trusted (3 files)
│   ├── rules/  🟢 Trusted (1 file)
│   └── storage/  🟢 Trusted (2 files)  — storage layer
├── suave/  🟢 Trusted (4 files)
│   ├── cstore/  🟢 Trusted (1 file)
│   ├── e2e/  🟢 Trusted (2 files)
│   └── gen/  🟢 Trusted (1 file)
├── tests/  🟢 Trusted (3 files)  — test suite
│   ├── ./  🟢 Trusted (2 files)  — test suite
│   └── fuzzers/bn256/  🟢 Trusted (1 file)
└── trie/  🟢 Trusted (7 files)
    ├── ./  🟢 Trusted (6 files)
    └── triedb/hashdb/  🟢 Trusted (1 file)
```

_Legend: 🟢 Trusted (enclave) · 🔴 Untrusted (host) · 🟡 Mixed (boundary)_

### Trust Boundary Rationale

No TEE manifest, EDL, or PAL files were found. Classification is based on LLM-assisted analysis of directory structure, TEE API usage patterns, and project role inference.

## Architecture Diagrams

### System Architecture with Trust Boundaries
The SUAVE system is partitioned into a trusted SGX Enclave executing confidential transaction processing and auction logic, and an untrusted suave-geth host process running the full Ethereum client stack (p2p, sync, RPC). The critical trust boundary crosses the ECALL/OCALL bridge between the enclave and host, where only enclave-side operations are protected by TEE hardware guarantees. External data flows from dApps through the untrusted GraphQL/JSON-RPC API into the host, which forwards confidential payloads into the enclave via ECALLs, while attestation artifacts and key material remain anchored inside the trusted zone.

```mermaid
flowchart TD
    subgraph TZ [" Trusted Zone"]
        ENCLAVE["SGX Enclave\nConfidential TX + Auction"]
        KEYSTORE["Account/Keystore\nKey Management"]
        CORE["Core Blockchain\nState Management"]
        CONSENSUS["Consensus Engine\nBeacon + Clique"]
    end

    subgraph UTZ ["⚠️ Untrusted Zone"]
        HOST["suave-geth Host\nEthereum Client Stack"]
        BRIDGE["SGX SDK ECALL/OCALL\nBridge Layer"]
        P2P["P2P Networking\nMsg Rate Limiting"]
        BEACON["Beacon Chain\nDencun Support"]
    end

    subgraph NET [" External Network"]
        RPC["GraphQL/JSON-RPC API"]
        DAPPS["External dApps & Users"]
        PEERS["Peer Nodes"]
        ATTSVC["Remote Attestation\nService"]
    end

    subgraph CRYPTO [" Crypto Operations"]
        SIG["TX Signing &\nAttestation Verify"]
        HASH["State Root Hash\nMerkle Compute"]
    end

    DAPPS -->|"Confidential TX requests"| RPC
    RPC -->|"Parsed TX data"| HOST
    HOST -->|"ECALL: confidential payload"| BRIDGE
    BRIDGE -->|"Enclave entry"| ENCLAVE
    ENCLAVE -->|"OCALL: host requests"| BRIDGE
    BRIDGE -->|"Host response"| HOST
    ENCLAVE ---|"Trust anchor:\nattestation artifacts"| SIG
    KEYSTORE ---|"Trust anchor:\nkey material"| SIG
    SIG -->|"Signed TX"| ENCLAVE
    ENCLAVE -->|"State updates"| CORE
    CORE -->|"Block validation"| CONSENSUS
    CORE -->|"State data"| HASH
    HASH -->|"Root hash"| CORE
    HOST -->|"Block propagation"| P2P
    P2P -->|"Peer blocks/headers"| HOST
    P2P -->|"Gossip messages"| PEERS
    HOST -->|"Forkchoice updates"| BEACON
    BEACON -->|"Consensus data"| HOST
    ENCLAVE -.->|"Attestation report"| ATTSVC

    classDef trusted fill:#d4edda,stroke:#28a745,color:#1a1a2e,font-weight:bold
    classDef untrusted fill:#f8d7da,stroke:#dc3545,color:#1a1a2e,font-weight:bold
    classDef extnet fill:#d1ecf1,stroke:#17a2b8,color:#1a1a2e
    classDef crypto fill:#e2d5f1,stroke:#6a4c93,color:#1a1a2e

    class ENCLAVE,KEYSTORE,CORE,CONSENSUS trusted
    class HOST,BRIDGE,P2P,BEACON untrusted
    class RPC,DAPPS,PEERS,ATTSVC extnet
    class SIG,HASH crypto
```

### Trust Boundary Narrative

The trust boundary separates enclave-side components (**SGX enclave confidential computation**, **Untrusted host process ← OCALL boundary ← SGX enclave awaiting external data**, **Remote SUAVE node ← Network attestation quote ← Local enclave confidential data release**, **SGX enclave key generation**, **report_data binding**) from host-side components (**Untrusted suave-geth host process**, **Remote verifier**, **Host filesystem storage**, **Host filesystem**, **Host processing**). Data and control flow across this boundary via the invariants listed below.

**Trust Paths Identified:**
- `INV-01`: Untrusted suave-geth host process → ECALL boundary → SGX enclave confidential computation — Untrusted host-provided ECALL parameters must be validated inside the enclave before influencing confidential transaction processing, auction ordering, or key derivation decisions.
- `INV-02`: Untrusted host process ← OCALL boundary ← SGX enclave awaiting external data — OCALL return values from the untrusted host must not be trusted by the enclave for security-critical decisions such as attestation status, peer identity, or sealed state freshness without independent verification.
- `INV-03`: Remote SUAVE node ← Network attestation quote ← Local enclave confidential data release — Remote peer attestation must be verified (quote validity, expected MRENCLAVE/MRSIGNER, TCB status) before the enclave releases any confidential transaction data or establishes a secure channel.
- `INV-04`: SGX enclave key generation → report_data binding → Attestation quote → Remote verifier → Secure channel — The attestation report_data field must cryptographically bind the enclave's public key or session key material to the quote, preventing man-in-the-middle substitution of keys after attestation.
- `INV-05`: SGX enclave sealed state → Host filesystem storage → SGX enclave unsealing on restart — Sealed data must be bound to enclave identity (MRENCLAVE or MRSIGNER) using SGX sealing so that only the expected enclave can unseal it, preventing a different or malicious enclave from accessing confidential auction state.
- `INV-06`: SGX enclave sealed state → Host filesystem → Enclave restart → State restoration — Sealed state must include a monotonically increasing epoch or version counter with anti-rollback protection, preventing the host from reverting enclave state to a previous version.
- `INV-07`: Dockerfile.suave build pipeline → SGX enclave signing → Production deployment → Enclave memory protection — SGX debug mode must be disabled in production builds so that enclave memory cannot be read via EDBGRD instructions, which would expose confidential transaction data and auction logic.
- `INV-08`: User transaction submission → RPC/p2p ingress → Host processing → (must enter) SGX enclave → Confidential computation — All code paths that handle confidential transaction data or MEV-sensitive computation must pass through the SGX enclave, with no bypass paths through the untrusted host that would expose secrets.
- `INV-09`: SGX enclave error path → OCALL error return → Untrusted host → RPC response to network — Error messages and response lengths from enclave operations must be normalized before reaching the untrusted host or network to prevent leakage of secret-dependent enclave state or processing paths.
- `INV-10`: SGX enclave confidential data → OCALL write to host → Host filesystem/database/logs — Confidential transaction data must not be written to the host filesystem or logged by the untrusted host process without encryption by the enclave, as the host is outside the TCB.
- `INV-11`: Local SGX enclave → Network attestation exchange → Remote SGX enclave → Secure channel key agreement — When establishing a secure channel between two SUAVE enclaves, the local enclave must verify that the remote enclave's attestation quote matches the expected MRENCLAVE measurement for the SUAVE protocol, preventing communication with unauthorized enclaves.
- `INV-12`: Intel attestation service → TCB collateral (CRL, TCB info) → Quote verification → Enclave trust decision — The enclave's attestation verification must check TCB status (not just quote signature validity) to ensure the quoting enclave is not running on a compromised SGX platform with known vulnerabilities.

### Data Flow Summary

Of 12 invariants, **8** involve data crossing the trust boundary between enclave and host.

**Host → Enclave** (1 flow)
_External data entering the TEE — highest validation burden_
- `INV-01`: **ECALL parameters from untrusted host** → **Confidential transaction processing logic**

**Enclave → Host** (2 flows)
_TEE outputs and secrets leaving the enclave — leakage risk_
- `INV-09`: **Enclave internal error conditions** → **OCALL error return values to host**
- `INV-10`: **Confidential transaction data inside enclave** → **Host filesystem write via OCALL**

**Bidirectional** (5 flows)
_Flows crossing the boundary in both directions_
- `INV-02`: **OCALL return values from untrusted host** → **Enclave policy decision**
- `INV-03`: **Attestation quote received from remote peer via network** → **Confidential transaction data release to peer**
- `INV-06`: **Previously sealed state blob from host filesystem** → **Enclave state restoration**
- `INV-08`: **Confidential transaction data from users via JSON-RPC/GraphQ** → **SGX enclave ECALL for confidential processing**
- `INV-11`: **Remote enclave attestation quote from network** → **Secure channel key agreement acceptance**

**Boundary Interface Summary:**
- **Enclave entry points** (1): data enters TEE via `INV-01`
- **Enclave exit points** (2): data leaves TEE via `INV-09`, `INV-10`

_Internal flows (4): `INV-04`, `INV-05`, `INV-07`, `INV-12` — these stay within a single zone and are covered by individual findings._

### Invariant Reference

| ID | Description | Trust Path |
| --- | --- | --- |
| INV-01 | Untrusted host-provided ECALL parameters must be validated inside the enclave before influencing confidential transaction processing, auction ordering, or key derivation decisions. | Untrusted suave-geth host process → ECALL boundary → SGX enclave confidential computation |
| INV-02 | OCALL return values from the untrusted host must not be trusted by the enclave for security-critical decisions such as attestation status, peer identity, or sealed state freshness without independent verification. | Untrusted host process ← OCALL boundary ← SGX enclave awaiting external data |
| INV-03 | Remote peer attestation must be verified (quote validity, expected MRENCLAVE/MRSIGNER, TCB status) before the enclave releases any confidential transaction data or establishes a secure channel. | Remote SUAVE node ← Network attestation quote ← Local enclave confidential data release |
| INV-04 | The attestation report_data field must cryptographically bind the enclave's public key or session key material to the quote, preventing man-in-the-middle substitution of keys after attestation. | SGX enclave key generation → report_data binding → Attestation quote → Remote verifier → Secure channel |
| INV-05 | Sealed data must be bound to enclave identity (MRENCLAVE or MRSIGNER) using SGX sealing so that only the expected enclave can unseal it, preventing a different or malicious enclave from accessing confidential auction state. | SGX enclave sealed state → Host filesystem storage → SGX enclave unsealing on restart |
| INV-06 | Sealed state must include a monotonically increasing epoch or version counter with anti-rollback protection, preventing the host from reverting enclave state to a previous version. | SGX enclave sealed state → Host filesystem → Enclave restart → State restoration |
| INV-07 | SGX debug mode must be disabled in production builds so that enclave memory cannot be read via EDBGRD instructions, which would expose confidential transaction data and auction logic. | Dockerfile.suave build pipeline → SGX enclave signing → Production deployment → Enclave memory protection |
| INV-08 | All code paths that handle confidential transaction data or MEV-sensitive computation must pass through the SGX enclave, with no bypass paths through the untrusted host that would expose secrets. | User transaction submission → RPC/p2p ingress → Host processing → (must enter) SGX enclave → Confidential computation |
| INV-09 | Error messages and response lengths from enclave operations must be normalized before reaching the untrusted host or network to prevent leakage of secret-dependent enclave state or processing paths. | SGX enclave error path → OCALL error return → Untrusted host → RPC response to network |
| INV-10 | Confidential transaction data must not be written to the host filesystem or logged by the untrusted host process without encryption by the enclave, as the host is outside the TCB. | SGX enclave confidential data → OCALL write to host → Host filesystem/database/logs |
| INV-11 | When establishing a secure channel between two SUAVE enclaves, the local enclave must verify that the remote enclave's attestation quote matches the expected MRENCLAVE measurement for the SUAVE protocol, preventing communication with unauthorized enclaves. | Local SGX enclave → Network attestation exchange → Remote SGX enclave → Secure channel key agreement |
| INV-12 | The enclave's attestation verification must check TCB status (not just quote signature validity) to ensure the quoting enclave is not running on a compromised SGX platform with known vulnerabilities. | Intel attestation service → TCB collateral (CRL, TCB info) → Quote verification → Enclave trust decision |

## TEE Usage Problems

### [MEDIUM] IV-INV-09: Unsanitized error leakage via RLP decode [Output & Metadata Leakage] (incorrect_usage) (CWE-209)

**Root Cause**: RLP decode errors carry specific semantic information about internal data structures and are propagated without sanitization toward the untrusted host.
**Impact**: An attacker can distinguish which confidential data structure was being processed inside the enclave by observing distinct error messages or response lengths, enabling inference of transaction types, bid amounts, or processing paths.
**Confidence**: Likely | **Invariant**: INV-09 | **Tier**: core

**Preconditions**:
- Code executes inside SGX enclave processing secret-dependent data.
- Errors from RLP decoding reach the OCALL boundary unmodified.

**Attack Scenario**:
  1. Enclave processes secret-dependent transaction data via RLP decoder. (`[ENCLAVE] rlp/decode.go:42`)
  2. RLP decoder returns specific error types revealing decoded structure. (`[ENCLAVE] rlp/decode.go:43`)
  3. Error propagates through trie iterator without sanitization. (`[ENCLAVE] rlp/decode.go:44`)
  4. Untrusted host observes distinct errors per input structure. (`[ENCLAVE] rlp/decode.go:45`)
  5. Attacker correlates error type/timing with transaction properties. (`[ENCLAVE] rlp/decode.go:108`)
  **Evidence**: `[ENCLAVE] trie/iterator.go:64`

### Code Evidence

**`rlp/decode.go:42 [ENCLAVE]`**
```
      32 | 	"github.com/holiman/uint256"
      33 | )
      34 | 
      35 | //lint:ignore ST1012 EOL is not an error.
      36 | 
      37 | // EOL is returned when the end of the current list
      38 | // has been reached during streaming.
      39 | var EOL = errors.New("rlp: end of list")
      40 | 
      41 | var (
>>>   42 | 	ErrExpectedString   = errors.New("rlp: expected String or Byte")
      43 | 	ErrExpectedList     = errors.New("rlp: expected List")
      44 | 	ErrCanonInt         = errors.New("rlp: non-canonical integer format")
      45 | 	ErrCanonSize        = errors.New("rlp: non-canonical size information")
      46 | 	ErrElemTooLarge     = errors.New("rlp: element is larger than containing list")
      47 | 	ErrValueTooLarge    = errors.New("rlp: value size exceeds available input length")
      48 | 	ErrMoreThanOneValue = errors.New("rlp: input contains more than one value")
      49 | 
      50 | 	// internal errors
      51 | 	errNotInList     = errors.New("rlp: call of ListEnd outside of any list")
      52 | 	errNotAtEOL      = errors.New("rlp: call of ListEnd not positioned at EOL")
```
Enclave processes secret-dependent transaction data via RLP decoder.

**`rlp/decode.go:43 [ENCLAVE]`**
```
      33 | )
      34 | 
      35 | //lint:ignore ST1012 EOL is not an error.
      36 | 
      37 | // EOL is returned when the end of the current list
      38 | // has been reached during streaming.
      39 | var EOL = errors.New("rlp: end of list")
      40 | 
      41 | var (
      42 | 	ErrExpectedString   = errors.New("rlp: expected String or Byte")
>>>   43 | 	ErrExpectedList     = errors.New("rlp: expected List")
      44 | 	ErrCanonInt         = errors.New("rlp: non-canonical integer format")
      45 | 	ErrCanonSize        = errors.New("rlp: non-canonical size information")
      46 | 	ErrElemTooLarge     = errors.New("rlp: element is larger than containing list")
      47 | 	ErrValueTooLarge    = errors.New("rlp: value size exceeds available input length")
      48 | 	ErrMoreThanOneValue = errors.New("rlp: input contains more than one value")
      49 | 
      50 | 	// internal errors
      51 | 	errNotInList     = errors.New("rlp: call of ListEnd outside of any list")
      52 | 	errNotAtEOL      = errors.New("rlp: call of ListEnd not positioned at EOL")
      53 | 	errUintOverflow  = errors.New("rlp: uint overflow")
```
RLP decoder returns specific error types revealing decoded structure.

**`rlp/decode.go:44 [ENCLAVE]`**
```
      34 | 
      35 | //lint:ignore ST1012 EOL is not an error.
      36 | 
      37 | // EOL is returned when the end of the current list
      38 | // has been reached during streaming.
      39 | var EOL = errors.New("rlp: end of list")
      40 | 
      41 | var (
      42 | 	ErrExpectedString   = errors.New("rlp: expected String or Byte")
      43 | 	ErrExpectedList     = errors.New("rlp: expected List")
>>>   44 | 	ErrCanonInt         = errors.New("rlp: non-canonical integer format")
      45 | 	ErrCanonSize        = errors.New("rlp: non-canonical size information")
      46 | 	ErrElemTooLarge     = errors.New("rlp: element is larger than containing list")
      47 | 	ErrValueTooLarge    = errors.New("rlp: value size exceeds available input length")
      48 | 	ErrMoreThanOneValue = errors.New("rlp: input contains more than one value")
      49 | 
      50 | 	// internal errors
      51 | 	errNotInList     = errors.New("rlp: call of ListEnd outside of any list")
      52 | 	errNotAtEOL      = errors.New("rlp: call of ListEnd not positioned at EOL")
      53 | 	errUintOverflow  = errors.New("rlp: uint overflow")
      54 | 	errNoPointer     = errors.New("rlp: interface given to Decode must be a pointer")
```
Error propagates through trie iterator without sanitization.

**`rlp/decode.go:45 [ENCLAVE]`**
```
      35 | //lint:ignore ST1012 EOL is not an error.
      36 | 
      37 | // EOL is returned when the end of the current list
      38 | // has been reached during streaming.
      39 | var EOL = errors.New("rlp: end of list")
      40 | 
      41 | var (
      42 | 	ErrExpectedString   = errors.New("rlp: expected String or Byte")
      43 | 	ErrExpectedList     = errors.New("rlp: expected List")
      44 | 	ErrCanonInt         = errors.New("rlp: non-canonical integer format")
>>>   45 | 	ErrCanonSize        = errors.New("rlp: non-canonical size information")
      46 | 	ErrElemTooLarge     = errors.New("rlp: element is larger than containing list")
      47 | 	ErrValueTooLarge    = errors.New("rlp: value size exceeds available input length")
      48 | 	ErrMoreThanOneValue = errors.New("rlp: input contains more than one value")
      49 | 
      50 | 	// internal errors
      51 | 	errNotInList     = errors.New("rlp: call of ListEnd outside of any list")
      52 | 	errNotAtEOL      = errors.New("rlp: call of ListEnd not positioned at EOL")
      53 | 	errUintOverflow  = errors.New("rlp: uint overflow")
      54 | 	errNoPointer     = errors.New("rlp: interface given to Decode must be a pointer")
      55 | 	errDecodeIntoNil = errors.New("rlp: pointer given to Decode must not be nil")
```
Untrusted host observes distinct errors per input structure.

**Remediation**: Wrap all RLP and trie errors in a single generic error before crossing the enclave boundary via OCALL. Normalize response lengths to a constant size regardless of error type.

## Dismissed Findings

_The following findings were dismissed during adversarial review._

### ~~V-01: Simulation adapter in p2p/simulations — not TEE-relevant~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Simulation/test code in p2p/simulations — not production attack surface. The attack path requires controlling simulation config, which is only accessible to the test operator. Non-finding.
- **Location(s)**: `p2p/simulations/adapters/exec.go:90`, `p2p/simulations/adapters/exec.go:64`

### ~~V-02: Ledger wallet driver not TEE-related~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. USB hardware wallet driver performing its intended function. The 'attack path' describes normal APDU construction and communication with a Ledger device — this is correct operation, not a vulnerability. No TEE relevance and no security issue.
- **Location(s)**: `accounts/usbwallet/ledger.go:493`, `accounts/usbwallet/ledger.go:496`

### ~~V-03: Hex Encode in trusted zone, no TEE boundary issue~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Explicitly states 'no TEE trust boundary is crossed' and 'no attacker-controlled data crosses enclave/host boundary.' A hex encoding utility function is not a vulnerability under any threat model. Pure non-finding.
- **Location(s)**: `common/hexutil/hexutil.go:85`

### ~~V-05: Faucet address extraction via regex on untrusted HTML~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. No vulnerability. The attacker creates their own social media post and can already choose any address to include. Placing a 'different address before the legitimate one' in your own post is meaningless — you already control the content. No exploitation scenario exists.
- **Location(s)**: `cmd/faucet/faucet.go:733`, `cmd/faucet/faucet.go:859`

### ~~V-06: No TEE usage problem in Trezor USB driver~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. The finding itself confirms 'No TEE primitives are used' and 'the code operates entirely within the trusted zone with no enclave boundary.' This is a self-refuting finding — it correctly identifies there is no issue.
- **Location(s)**: `accounts/usbwallet/trezor.go:288`, `accounts/usbwallet/trezor.go:335`

### ~~V-07: Logger context handling — not TEE-relevant~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. Weak confidence, not TEE-relevant, and the attack path literally says 'No TEE-relevant attack path exists.' Logger context handling with no demonstrated vulnerability. Pure noise.
- **Location(s)**: `log/logger.go:203`, `log/logger.go:281`

### ~~V-08: Non-TEE GraphQL input parsing flagged as trust boundary~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Describes normal GraphQL input parsing. The attack path is just 'input comes in, gets parsed' — there is no overflow, injection, or any demonstrated vulnerability. Standard input handling is not a security finding.
- **Location(s)**: `graphql/graphql.go:61`, `graphql/graphql.go:58`

### ~~V-09: SetFallbackUDP int-to-uint16 truncation in localnode~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Port configuration comes from CLI flags or config files, not from untrusted network input. An attacker cannot control the port parameter in any realistic deployment. Silent truncation of a config value is a code quality issue, not a security vulnerability.
- **Location(s)**: `p2p/enode/localnode.go:211`, `p2p/enode/localnode.go:212`

### ~~V-10: Simulation HTTP filter param parsing via strings.Split~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. Simulation code in p2p/simulations — not production attack surface. Weak confidence. Filter parameter parsing in a test harness has no security implications.
- **Location(s)**: `p2p/simulations/http.go:481`, `p2p/simulations/http.go:496`

### ~~V-11: Clef documentation output has no TEE trust boundary~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. The attack path explicitly states 'No TEE attack path exists' and 'No TEE primitives are present.' A fmt.Println for documentation generation is not a vulnerability. Self-refuting finding.
- **Location(s)**: `cmd/clef/main.go:1216`

### ~~V-12: CLI UI output in trusted zone — no TEE boundary issue~~
- **Original Severity**: Info
- **Dismissal Reason**: Adversarial review: false positive. CLI output to stdout from a signer UI. The finding confirms 'No TEE trust boundary is crossed; all output is within trusted zone.' Printing request details for user approval is the intended behavior. Non-finding.
- **Location(s)**: `signer/core/cliui.go:234`, `signer/core/cliui.go:228`

### ~~RV-U-INV-09: Trie errors leak enclave state~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. Weak confidence, no trust boundary trace, and no concrete evidence of output variation depending on secret data. The attack path is speculative ('an attacker triggers a trie operation... to infer which trie nodes exist'). Trie error messages are standard Ethereum client behavior and the finding fails to demonstrate how an external attacker reaches this code path through a TEE boundary or what actionable secret is leaked. Dismissed as speculative.
- **Location(s)**: `trie/proof.go:70`, `trie/iterator.go:41`, `trie/iterator.go:64`

### ~~RV-U-INV-08: P2P message handling bypasses enclave~~
- **Original Severity**: Low
- **Dismissal Reason**: Adversarial review: false positive. This finding describes intentional SUAVE architecture, not a vulnerability. P2P message handling in the untrusted host IS the designed pattern — confidential data is selectively passed to the enclave. Deserializing P2P messages in host memory before enclave routing is how the system is supposed to work. The finding is essentially 'the design should be different,' which is a design review comment, not a security finding. Weak confidence, no trust boundary trace.
- **Location(s)**: `p2p/server.go:56`, `interfaces.go:54`, `rlp/decode.go:82`

## Appendix

_Info-severity TEE findings, items requiring manual review, and non-TEE findings are included here for completeness._

### Items Requiring Manual Review

#### U-INV-01: ECALL boundary code not in provided scope

Trie sync, encoding, RLP decode, and interface definitions for ECALL parameter validation.
- **Why Uncertain**: No ECALL handler, enclave entry point, or parameter marshaling code was provided to inspect boundary guards.

Second-pass notes: The additional source code provided (rlp/decode.go, rlp/typecache.go, trie/iterator.go, trie/stacktrie.go, rlp/decode_test.go) consists entirely of standard go-ethereum library code for RLP encoding/decoding and trie data structure operations. While the RLP decoder implements input validation (canonical form checks at decode.go:44-48, size overflow checks, type validation), this is standard library-level deserialization validation, not enclave boundary input validation. No ECALL dispatch handler
- **Recommended Steps**: Provide enclave ECALL dispatch and parameter parsing source files, Audit suave-geth sgx/ or enclave/ directory for input validation, Check OCALL/ECALL interface definitions in EDL files

#### U-INV-02: No TEE enclave code present

Whether OCALL return values are verified before security-critical use in TEE enclave code.
- **Why Uncertain**: Provided source files are standard go-ethereum library code (trie sync, RLP decode, interfaces) with no SGX enclave, OCALL/ECALL, or attestation logic.

Second-pass notes: The additional source code provided (p2p/server.go, interfaces.go, rlp/decode.go, rlp/decode_test.go) remains standard go-ethereum library code with no SGX enclave logic, OCALL/ECALL handlers, attestation, or sealed state verification. No TEE-specific boundary code exists in any provided file. The invariant cannot be evaluated without enclave EDL files, trusted/untrusted bridge code, or OCALL handler implementations.
- **Recommended Steps**: Provide TEE enclave source files containing OCALL handlers, Include attestation or sealed state verification code, Supply enclave EDL files and trusted/untrusted bridge code

#### U-INV-03: No attestation code in provided files

interfaces.go, trie/sync.go, rlp/doc.go, rlp/decode.go for attestation verification logic.
- **Why Uncertain**: Provided files are standard go-ethereum library code (interfaces, trie sync, RLP encoding) with no TEE/SGX attestation, DCAP quote verification, or secure channel logic.

Second-pass notes: The additional source code (p2p/server.go, interfaces.go, trie files, rlp/doc.go, metrics README) is still standard go-ethereum library code with no SUAVE/TEE-specific attestation logic. While p2p/server.go shows a transport interface with doEncHandshake (line 236) and doProtoHandshake (line 237), these are standard Ethereum RLPx encryption handshakes using ECDSA keys, NOT SGX/TEE attestation verification. There is no DCAP quote verification, no MRENCLAVE/MRSIGNER checking, no TCB status validat
- **Recommended Steps**: Provide SUAVE enclave attestation and peer communication files, Search for files containing DCAP, quote, MRENCLAVE, or attestation, Check SUAVE-specific packages for remote peer handshake code

#### U-INV-04: Attestation key binding code absent

Searched for report_data construction, key binding, and quote generation logic in provided files.
- **Why Uncertain**: Provided source files are trie/RLP/interface code from go-ethereum; no TEE attestation or quote generation code present to evaluate.

Second-pass notes: The additional source code provided (trie/trie_reader.go, trie/iterator.go, trie/sync_test.go, trie/stacktrie.go, interfaces.go, metrics/README.md, swarm/README.md, log/README.md) consists entirely of go-ethereum library infrastructure (trie data structures, RLP encoding, logging, metrics). None of these files contain SGX/TEE attestation logic, quote generation, EREPORT calls, or any code that binds a public key or session key material to a report_data field. The invariant remains unverifiable w
- **Recommended Steps**: Provide SGX enclave attestation source files, Locate report_data binding in suave-geth tee package, Search for EREPORT or quote generation calls

#### U-INV-05: SGX sealing code not in provided scope

Searched provided source files for SGX seal/unseal functions and identity binding logic.
- **Why Uncertain**: Provided files are standard go-ethereum trie/iterator/interfaces code with zero SGX sealing or enclave identity references.

Second-pass notes: The additional source code provided (trie_reader.go, encoding.go, iterator.go, secure_trie.go, sync_test.go) and documentation files (metrics/README.md, swarm/README.md, log/README.md) contain zero references to SGX sealing, sgx_seal_data, sgx_unseal_data, MRENCLAVE, MRSIGNER, or any TEE-related functionality. All files are standard go-ethereum library trie package code and unrelated READMEs. The enclave sealing/unsealing source files, EDL definitions, and ECALL/OCALL interfaces needed to verify
- **Recommended Steps**: Locate and provide enclave sealing/unsealing source files, Search for sgx_seal_data, sgx_unseal_data, or seal_key usage, Review EDL or enclave ECALL/OCALL definitions for seal policy

#### U-INV-06: Sealed state anti-rollback not in scope

Searched provided trie/interface code for monotonic counters or version-gated seal/unseal logic.
- **Why Uncertain**: Provided files are standard go-ethereum trie/iterator/reader code with no TEE sealing, monotonic counters, or anti-rollback logic present.

Second-pass notes: The additional source code (trie/iterator.go, interfaces.go, trie/trie_reader.go, trie/sync_test.go, trie/trie.go, plus README files for metrics/swarm/log) contains no TEE sealing/unsealing logic, monotonic counters, anti-rollback protection, or SGX-specific functionality whatsoever. All files are standard go-ethereum library code for Merkle Patricia Tries, chain reader interfaces, and logging/metrics utilities. The invariant cannot be verified or falsified without enclave seal/unseal and state 
- **Recommended Steps**: Provide enclave seal/unseal and state serialization source files, Audit SGX monotonic counter or ISV SVN usage in sealing, Check for version field in sealed blob structs

#### U-INV-07: SGX debug mode enforcement unverifiable

SGX debug flag configuration and attestation debug attribute verification in provided source.
- **Why Uncertain**: No enclave signing config, Dockerfile.suave, or attestation quote verifier code provided; only application-level Go backends shown.

Second-pass notes: The additional source code (trie/database_wrap.go, p2p/server.go, interfaces.go, trie/trie_test.go, trie/proof.go) consists entirely of application-level Go code for trie management, P2P networking, and Ethereum interfaces. None of these files contain SGX enclave signing configuration, attestation quote verification logic, ATTRIBUTES.DEBUG checks, or any TEE-related build/signing pipeline. The README.md references a --suave.dev flag for local devnet and Docker-based deployment (make devnet-up), 
- **Recommended Steps**: Provide Dockerfile.suave and enclave signing XML config, Provide attestation verification code checking ATTRIBUTES.DEBUG, Search for sgx_sign, debug flag, or ATTRIBUTES in full codebase

#### U-INV-10: No TEE boundary code in provided files

Standard go-ethereum trie, interface, and RLP code for enclave data flow guards.
- **Why Uncertain**: Provided files are standard go-ethereum library code with no OCALL/ECALL, enclave boundary, or sealing logic to analyze against INV-10.

Second-pass notes: The additional source code provided (interfaces.go, rlp/decode.go, trie/hasher.go, p2p/server.go, rlp/decode_test.go) is still standard go-ethereum library code with no TEE integration layer. There are no OCALL/ECALL definitions, no enclave boundary logic, no sealing or encryption routines, and no host-side database write paths that accept enclave output. The recommended files from the first pass—TEE integration layer code, enclave-side sealing routines, and host-side database write paths—remain
- **Recommended Steps**: Provide TEE integration layer code containing OCALL/ECALL definitions, Provide enclave-side sealing and encryption routines, Provide host-side database write paths receiving enclave output

#### U-INV-11: MRENCLAVE quote verification absent

Searched provided source for attestation quote parsing and MRENCLAVE comparison logic.
- **Why Uncertain**: Provided files are go-ethereum core (trie, RLP, interfaces) with no enclave attestation or secure channel code.

Second-pass notes: The additional source code provided (interfaces.go, trie/secure_trie.go, trie/trie_reader.go, trie/preimages.go, trie/iterator.go) consists entirely of standard go-ethereum library components — chain reader interfaces, Merkle trie data structures, and preimage caching. The 'SecureTrie' in secure_trie.go is a type alias for StateTrie (keccak256-keyed trie), entirely unrelated to TEE secure channels. None of the files contain enclave attestation quote handling, MRENCLAVE measurement comparison, se
- **Recommended Steps**: Locate SUAVE enclave communication and quote verification files, Search for MRENCLAVE comparison in attestation handlers, Provide secure channel key agreement source for analysis

#### U-INV-12: Attestation code not in provided scope

Searched all provided files for attestation, TCB, quote verification, or SGX-related logic.
- **Why Uncertain**: Provided source files (interfaces.go, rlp/*, trie/preimages.go) contain no attestation or TEE verification code whatsoever.

Second-pass notes: The additional source code (secure_trie.go, node.go, database_wrap.go, rlp/decode_test.go) still contains no attestation, SGX, quote verification, or TCB-related logic. While the README confirms SUAVE uses confidential execution (implying TEE), no attestation verification source files were provided. Cannot confirm or deny the invariant without access to the enclave attestation/verification code paths (e.g., DCAP quote verification, TCB status checking, or any SGX-related integration points).
- **Recommended Steps**: Provide attestation/quote verification source files, Search for files referencing SGX, quote, TCB, or attestation, Check DCAP/quote verification library integration points

#### U-INV-08: Enclave routing absent from provided code

Trie operations, node definitions, and Ethereum interfaces for SGX enclave routing guards.
- **Why Uncertain**: Provided code covers base trie/interface layers only; no SGX entry points, enclave-bound routing, or confidential data handlers are present to evaluate.

Second-pass notes: The additional source code provided (interfaces.go, trie/trie_test.go, trie/iterator.go, trie/sync_test.go, trie/sync.go) consists entirely of base go-ethereum trie layer and interface definitions. None of these files contain SGX enclave entry points, EDL bridge definitions, confidential data handlers, transaction submission pipelines, or MEV orderflow processing logic. The README confirms SUAVE intends to provide confidential execution via dedicated execution nodes, but the actual enforcement m
- **Recommended Steps**: Provide RPC handler and transaction submission pipeline code, Provide MEV auction/orderflow processing code, Provide SGX enclave bridge/EDIL layer code

#### U-INV-01: ECALL boundary code not in scope

Whether ECALL parameter validation guards exist in provided trie, interface, and RLP files.
- **Why Uncertain**: Provided source files contain only host-side trie/encoding logic and test code; no ECALL handlers or enclave entry points are present.
- **Recommended Steps**: Provide enclave ECALL handler source files (eg crypto.go, ecall.go), Provide key derivation and auction ordering logic inside enclave, Provide SGX bridge/edl files defining ECALL interface

#### U-INV-02: No TEE boundary code present

Searched for OCALL/ECALL boundaries and host-returned data validation in provided files.
- **Why Uncertain**: Provided code is standard go-ethereum (trie sync, RLP decode, interfaces) with no SGX/TEE enclave boundaries, OCALLs, or attestation logic to analyze.
- **Recommended Steps**: Provide TEE enclave source with OCALL/ECALL definitions, Include attestation quote verification code, Include sealed state unsealing logic

#### U-INV-03: No attestation code in provided files

interfaces.go, trie/sync.go, rlp/doc.go, rlp/decode.go for attestation guards
- **Why Uncertain**: Provided source files contain only core go-ethereum library code (interfaces, trie sync, RLP encoding) with zero attestation or secure channel logic relevant to INV-03.
- **Recommended Steps**: Provide attestation/quote verification source files, Provide secure channel establishment code, Provide enclave confidential data release handlers

#### U-INV-04: Attestation key binding code not in scope

Searched provided files for report_data construction, quote generation, and key binding logic.
- **Why Uncertain**: Provided source files (trie/node.go, interfaces.go, trie/secure_trie.go, rlp/typecache.go, trie/iterator.go) contain no TEE/SGX attestation, quote generation, or report_data binding code.
- **Recommended Steps**: Provide enclave attestation and quote generation source files, Check files containing EREPORT or sgx_report_data usage, Review key generation and report_data population routines

#### U-INV-05: No SGX sealing code in provided sources

Searched provided source files for SGX seal/unseal APIs, MRENCLAVE/MRSIGNER binding, and seal policy enforcement.
- **Why Uncertain**: Provided files are standard go-ethereum trie/interface code with zero SGX sealing logic; cannot verify invariant without enclave source.
- **Recommended Steps**: Provide enclave sealing/unsealing source code for review, Search for sgx_seal_data / sgx_unseal_data calls in codebase, Check seal policy parameter (MRENCLAVE vs MRSIGNER flag)

#### U-INV-06: No sealed state anti-rollback code found

Searched for monotonic counters, epoch fields, and anti-rollback guards in sealed state paths.
- **Why Uncertain**: Provided code (interfaces.go, trie/sync.go, trie/iterator.go, trie/trie_reader.go) contains no TEE sealing/unsealing logic at all.
- **Recommended Steps**: Locate enclave sealing and unsealing functions in codebase, Check for monotonic counter or version field in sealed blob, Verify anti-rollback comparison on state restoration path

#### U-INV-07: SGX debug mode production enforcement

SGX debug flag configuration in enclave signing and attestation verification code.
- **Why Uncertain**: Provided source lacks Dockerfile.suave, enclave signing config, and attestation verification code needed to assess debug mode.
- **Recommended Steps**: Review Dockerfile.suave for enclave debug flag settings, Check attestation verifier for ATTRIBUTES.DEBUG field validation, Inspect enclave signing tool configuration in build pipeline

#### U-INV-08: Enclave routing guards absent from code

Interfaces, trie sync/iterator/node code for enclave boundary guards on confidential data paths.
- **Why Uncertain**: Provided code is base go-ethereum infrastructure; no enclave entry/exit, RPC handler, or confidential data routing code was included for review.
- **Recommended Steps**: Provide SGX enclave bridge/ECALL dispatch code for review, Provide RPC transaction submission handlers for review, Provide MEV auction/bid processing pipeline code

#### U-INV-10: No TEE boundary visible in code

Checked trie sync, interfaces, and iterator for encryption guards before host-side writes.
- **Why Uncertain**: Provided files are standard go-ethereum library code with no OCALL, enclave boundary, or sealing definitions to evaluate.
- **Recommended Steps**: Locate OCALL definitions and enclave bridge code, Trace data flow from enclave to host write calls, Check for sealing/encryption before OCALL data param

#### U-INV-11: No attestation code in provided files

Searched provided source files for enclave attestation quote verification and MRENCLAVE comparison logic.
- **Why Uncertain**: Provided files (interfaces.go, trie/sync.go, rlp/doc.go, trie/secure_trie.go, trie/preimages.go) are go-ethereum core library with no TEE/SGX attestation or secure channel code.
- **Recommended Steps**: Provide SUAVE enclave attestation verification source files, Search for files matching *attest*, *quote*, *mrenclave*, *sgx*, Check secure channel key agreement implementation files

#### U-INV-12: No attestation code in provided scope

Searched all provided files for quote verification, TCB status checks, CRL validation, and collateral freshness logic.
- **Why Uncertain**: Provided source files (interfaces.go, rlp/*, trie/preimages.go) contain no SGX/TEE attestation verification code whatsoever.
- **Recommended Steps**: Provide attestation/quote verification source files for analysis, Search codebase for files referencing SGX, quote, TCB, or CRL

### Non-TEE Findings

_The following findings are generic code issues that do not directly involve TEE trust boundaries._

### [MEDIUM] V-04: SSRF via insufficient URL validation in faucet auth (CWE-918)

**Root Cause**: URL validation checks only the path structure (presence of 'status' or 'posts' segments) but never validates the hostname, and the string replacement transformation is a no-op for non-matching domains.
**Impact**: An attacker can induce the faucet server to make arbitrary GET requests to internal network services, enabling network scanning and potential interaction with internal APIs.
**Confidence**: Confirmed | **Invariant**: UNMATCHED::cmd/faucet/faucet.go | **Tier**: peripheral

**Preconditions**:
- Faucet is running and accessible to the attacker
- Faucet is configured with Twitter or Facebook auth mode (no API tokens)

**Attack Scenario**:
  1. Attacker submits faucet request with crafted URL like http://internal-service/status/123 (`[ENCLAVE] cmd/faucet/faucet.go:715`)
  2. authTwitter splits URL by '/' and checks path structure but not hostname (`[ENCLAVE] cmd/faucet/faucet.go:849`)
  3. strings.Replace only transforms twitter.com URLs, leaving attacker URL intact (`[ENCLAVE] cmd/faucet/faucet.go:713`)
  4. http.Get on line 715 fetches the attacker-controlled URL from the server (`[ENCLAVE] cmd/faucet/faucet.go:847`)
  5. Server response body is read and parsed, confirming internal service reachability
  6. Attacker repeats with different internal hosts to map the network

### Code Evidence

**`cmd/faucet/faucet.go:715 [ENCLAVE]`**
```
     705 | 	case tokenV1 != "":
     706 | 		return authTwitterWithTokenV1(tweetID, tokenV1)
     707 | 	case tokenV2 != "":
     708 | 		return authTwitterWithTokenV2(tweetID, tokenV2)
     709 | 	}
     710 | 	// Twitter API token isn't provided so we just load the public posts
     711 | 	// and scrape it for the Ethereum address and profile URL. We need to load
     712 | 	// the mobile page though since the main page loads tweet contents via JS.
     713 | 	url = strings.Replace(url, "https://twitter.com/", "https://mobile.twitter.com/", 1)
     714 | 
>>>  715 | 	res, err := http.Get(url)
     716 | 	if err != nil {
     717 | 		return "", "", "", common.Address{}, err
     718 | 	}
     719 | 	defer res.Body.Close()
     720 | 
     721 | 	// Resolve the username from the final redirect, no intermediate junk
     722 | 	parts = strings.Split(res.Request.URL.String(), "/")
     723 | 	if len(parts) < 4 || parts[len(parts)-2] != "status" {
     724 | 		//lint:ignore ST1005 This error is to be displayed in the browser
     725 | 		return "", "", "", common.Address{}, errors.New("Invalid Twitter status URL")
```
Attacker submits faucet request with crafted URL like http://internal-service/status/123

**`cmd/faucet/faucet.go:849 [ENCLAVE]`**
```
     839 | 
     840 | 	// Facebook's Graph API isn't really friendly with direct links. Still, we don't
     841 | 	// want to do ask read permissions from users, so just load the public posts and
     842 | 	// scrape it for the Ethereum address and profile URL.
     843 | 	//
     844 | 	// Facebook recently changed their desktop webpage to use AJAX for loading post
     845 | 	// content, so switch over to the mobile site for now. Will probably end up having
     846 | 	// to use the API eventually.
     847 | 	crawl := strings.Replace(url, "www.facebook.com", "m.facebook.com", 1)
     848 | 
>>>  849 | 	res, err := http.Get(crawl)
     850 | 	if err != nil {
     851 | 		return "", "", common.Address{}, err
     852 | 	}
     853 | 	defer res.Body.Close()
     854 | 
     855 | 	body, err := io.ReadAll(res.Body)
     856 | 	if err != nil {
     857 | 		return "", "", common.Address{}, err
     858 | 	}
     859 | 	address := common.HexToAddress(string(regexp.MustCompile("0x[0-9a-fA-F]{40}").Find(body)))
```
authTwitter splits URL by '/' and checks path structure but not hostname

**`cmd/faucet/faucet.go:713 [ENCLAVE]`**
```
     703 | 	// but unlimited v1.1 apps).
     704 | 	switch {
     705 | 	case tokenV1 != "":
     706 | 		return authTwitterWithTokenV1(tweetID, tokenV1)
     707 | 	case tokenV2 != "":
     708 | 		return authTwitterWithTokenV2(tweetID, tokenV2)
     709 | 	}
     710 | 	// Twitter API token isn't provided so we just load the public posts
     711 | 	// and scrape it for the Ethereum address and profile URL. We need to load
     712 | 	// the mobile page though since the main page loads tweet contents via JS.
>>>  713 | 	url = strings.Replace(url, "https://twitter.com/", "https://mobile.twitter.com/", 1)
     714 | 
     715 | 	res, err := http.Get(url)
     716 | 	if err != nil {
     717 | 		return "", "", "", common.Address{}, err
     718 | 	}
     719 | 	defer res.Body.Close()
     720 | 
     721 | 	// Resolve the username from the final redirect, no intermediate junk
     722 | 	parts = strings.Split(res.Request.URL.String(), "/")
     723 | 	if len(parts) < 4 || parts[len(parts)-2] != "status" {
```
strings.Replace only transforms twitter.com URLs, leaving attacker URL intact

**`cmd/faucet/faucet.go:847 [ENCLAVE]`**
```
     837 | 	}
     838 | 	username := parts[len(parts)-3]
     839 | 
     840 | 	// Facebook's Graph API isn't really friendly with direct links. Still, we don't
     841 | 	// want to do ask read permissions from users, so just load the public posts and
     842 | 	// scrape it for the Ethereum address and profile URL.
     843 | 	//
     844 | 	// Facebook recently changed their desktop webpage to use AJAX for loading post
     845 | 	// content, so switch over to the mobile site for now. Will probably end up having
     846 | 	// to use the API eventually.
>>>  847 | 	crawl := strings.Replace(url, "www.facebook.com", "m.facebook.com", 1)
     848 | 
     849 | 	res, err := http.Get(crawl)
     850 | 	if err != nil {
     851 | 		return "", "", common.Address{}, err
     852 | 	}
     853 | 	defer res.Body.Close()
     854 | 
     855 | 	body, err := io.ReadAll(res.Body)
     856 | 	if err != nil {
     857 | 		return "", "", common.Address{}, err
```
http.Get on line 715 fetches the attacker-controlled URL from the server

**Remediation**: Validate the URL hostname against an allowlist (e.g., twitter.com, mobile.twitter.com, facebook.com, m.facebook.com) before making HTTP requests. Reject any URL whose parsed hostname is not on the allowlist.
