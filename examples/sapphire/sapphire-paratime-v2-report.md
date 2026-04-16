# oasis-sapphire-paratime TEE Security Audit Report V2

**Date:** 2026-04-16 | **Methodology:** Stage 5b Deep Verification (v1 findings + self-validation)
**Scope:** sapphire-paratime (EVM ParaTime, 2 Rust + 15 Solidity + Go/JS/Python clients) | **TEE Provider:** oasis-core (audited separately)

---

## Dashboard Summary Section

### Finding count by severity and trust-path tier

| Severity  | core | adjacent | peripheral | Total |
|-----------|------|----------|------------|-------|
| Critical  |  0   |    0     |     0      |   0   |
| High      |  1   |    0     |     0      |   1   |
| Medium    |  0   |    1     |     0      |   1   |
| Low       |  0   |    0     |     0      |   0   |
| Info      |  0   |    0     |     0      |   0   |
| **Total** |  1   |    1     |     0      |   2   |

### Total findings count

> Total findings: 2 (Critical: 0, High: 1, Medium: 1, Low: 0, Info: 0)

### Executive risk statement

The project's core client-side calldata encryption path has a High-severity vulnerability (V-01) that allows a malicious RPC provider to substitute the runtime's X25519 public key, breaking the fundamental confidentiality guarantee of Sapphire. Users connecting to untrusted RPC endpoints cannot rely on end-to-end encryption. A Medium-severity usability issue (V-02) causes transaction failures when switching chains, but does not compromise confidentiality due to Deoxys-II authentication.

### Grade history: v1 to v2 transition

| v1 ID | v1 Severity | v2 ID | v2 Severity | Change    | Reason |
|-------|-------------|-------|-------------|-----------|--------|
| F-10  | High        | V-01  | High        | Unchanged  | Confirmed - no client-side validation found |
| F-09  | Informational | V-02  | Medium      | Upgraded   | Realistic attack scenario with user impact |
| F-01  | Informational | PG-01 | -           | Removed    | Verified as complete positive guard |
| F-02  | Informational | PG-02 | -           | Removed    | Verified as complete positive guard |
| F-03  | Informational | PG-03 | -           | Removed    | Verified as complete positive guard |
| F-04  | Informational | PG-04 | -           | Removed    | Verified as complete positive guard |
| F-05  | Informational | PG-05 | -           | Removed    | Verified as complete positive guard |
| F-06  | Informational | PG-06 | -           | Removed    | Verified as complete positive guard |
| F-07  | Informational | PG-07 | -           | Removed    | Verified as complete positive guard |
| F-08  | Informational | PG-08 | -           | Removed    | Verified as complete positive guard |
| F-04 re-grade | - | AO-01 | -           | Removed    | Architectural observation, not vulnerability |

---

## Severity Rubric

| Severity    | Criteria |
|-------------|----------|
| **Critical** | Core trust path, directly exploitable, no mitigation required beyond the vulnerability itself. Compromise of the fundamental TEE security guarantee. |
| **High**     | Core trust path, likely exploitable; OR adjacent trust path with straightforward exploitation. |
| **Medium**   | Adjacent trust path, exploitable under specific conditions; OR core trust path with significant mitigating factors already in place. |
| **Low**      | Peripheral trust path, difficult to exploit, or requires an unusual deployment configuration. |
| **Info**     | Architectural observation, hardening recommendation, or configuration best practice. No direct exploitability. |

---

## Trust-Path Tier Definitions

| Tier          | Definition |
|---------------|------------|
| **core**      | Directly on the primary trust path. Compromise breaks the TEE's fundamental security guarantee. |
| **adjacent**  | Supports the trust path. Compromise weakens but may not directly break the guarantee. |
| **peripheral** | Operational or deployment concern. Compromise impacts availability or operations, not the trust guarantee itself. |

---

## Findings

### V-01: Client-Side Calldata Public Key Not Authenticated

| Field                | Value |
|----------------------|-------|
| **ID**               | V-01 |
| **Severity**         | High |
| **Trust-Path Tier**  | core |
| **Confidence**       | high |
| **Evidence Basis**   | Manual path trace |
| **Invariant Ref(s)** | INV-07 (Calldata key derivation), INV-08 (Deoxys-II AEAD) |

#### Attack Scenario (POC)

1. **Prerequisites**: Attacker controls or compromises an RPC endpoint that a Sapphire client connects to (e.g., via DNS poisoning, compromised gateway, or malicious browser extension).

2. **Entry point**: Client calls `KeyFetcher.cipher()` in JS or `GetRuntimePublicKey()` in Go to fetch the runtime's calldata public key.

3. **Steps**:
   - `clients/js/src/calldatapublickey.ts:92-138` - `fetchRuntimePublicKey()` makes an `eth_call` to the runtime
   - `clients/js/src/calldatapublickey.ts:130-137` - Response is decoded into `key`, `checksum`, `signature`, and `epoch`
   - `clients/js/src/calldatapublickey.ts:173-179` - `cipher()` method destructures only `key` and `epoch`, **ignoring** `checksum` and `signature`
   - `clients/js/src/cipher.ts:226-263` - `X25519DeoxysII.ephemeral()` uses the unverified public key to derive a shared secret
   - `clients/js/src/cipher.ts:266-274` - `encrypt()` uses this shared secret to encrypt calldata
   - Encrypted transaction is submitted to the network

4. **Trust boundary crossed**: At line 173 of `calldatapublickey.ts`, untrusted data from the RPC provider is directly used for cryptographic operations without any validation.

5. **Impact**: The attacker can decrypt all "confidential" calldata encrypted by the victim client. This completely breaks Sapphire's core confidentiality guarantee. The attacker learns:
   - Function calls and arguments
   - Private data sent to smart contracts
   - Transaction parameters that should be confidential

The attacker then forwards the original encrypted transaction to the real network (or re-encrypts with the correct key), making the attack undetectable to the legitimate runtime.

#### Code Path

- `clients/js/src/calldatapublickey.ts:130-137` - Fetches key, checksum, signature from RPC
- `clients/js/src/calldatapublickey.ts:173-179` - **Missing validation**: Only extracts key and epoch
- `clients/js/src/cipher.ts:226-263` - Derives shared secret with unverified key
- `clients/js/src/cipher.ts:266-274` - Encrypts calldata with compromised key
- `clients/go/cipher.go:263-274` - Same issue in Go client: only returns PublicKey and Epoch

#### What This Means for Sapphire

Sapphire is marketed as a confidential smart contract platform where "all state is encrypted" and "transactions and calls are optionally end-to-end encrypted." This finding reveals that the client-side encryption path has no authentication of the runtime's public key.

For Web3 applications using Sapphire:
- **Private key operations become public**: If a dApp uses Sapphire for private key management (e.g., HSM contracts), an attacker controlling the RPC can extract private keys sent to the contract.
- **Confidential DeFi is compromised**: Private swap parameters, trading strategies, and sensitive financial data can be intercepted.
- **Private state queries are exposed**: When querying private contract state, the query parameters are sent unencrypted to the attacker.

This is particularly dangerous because:
- Users often trust public RPC endpoints (e.g., Infura, Alchemy) without verifying their integrity
- Browser extensions can intercept RPC calls
- The attack is completely passive (no active network manipulation needed)

#### Remediation

1. **Verify the signature** before using the public key:
   ```typescript
   // In clients/js/src/calldatapublickey.ts:173
   const { key, checksum, signature, epoch } = await this.fetch(upstream);
   // VERIFY the signature against the known keymanager public key
   if (!verifyKeyManagerSignature(key, checksum, signature, KEYMANAGER_PUBKEY)) {
     throw new Error('Invalid key manager signature');
   }
   return X25519DeoxysII.ephemeral(key, epoch);
   ```

2. **Pin the keymanager's signing key** in the client libraries:
   - Hardcode or securely distribute the keymanager's public key
   - Provide a mechanism for users to verify they're connecting to a trusted RPC

3. **Add chain ID validation** to prevent cross-chain key substitution (see V-02)

4. **Document the trust assumption** clearly: "Clients MUST verify the keymanager's signature before using the public key. Connecting to an untrusted RPC endpoint breaks confidentiality."

5. **Consider certificate pinning** or TLS certificate verification for RPC endpoints

**Reference**: Key signature format is documented in the keymanager-paratime repository. The signature context is `b"oasis-core/keymanager: pk signature"`.

#### V1 to V2 Grade History

| Version | Severity | Notes |
|---------|----------|-------|
| v1      | High     | Original finding from Codex Round 1 |
| v2      | High     | **Confirmed** - No client-side validation found. Direct code path to encryption key. |

---

### V-02: JS Client Key Cache Cross-Chain Confusion

| Field                | Value |
|----------------------|-------|
| **ID**               | V-02 |
| **Severity**         | Medium |
| **Trust-Path Tier**  | adjacent |
| **Confidence**       | high |
| **Evidence Basis**   | Manual path trace |
| **Invariant Ref(s)** | INV-07 (Calldata key derivation) |

#### Attack Scenario (POC)

1. **Prerequisites**: User switches their dApp's RPC provider from one Sapphire network to another (e.g., from testnet to mainnet, or between different ParaTimes).

2. **Entry point**: Application calls `KeyFetcher.fetch()` after switching chains.

3. **Steps**:
   - `clients/js/src/calldatapublickey.ts:162-168` - Cache check compares only expiration time, **not chain ID**
   - Line 166 comment explicitly identifies the issue: "XXX: if provider switch chain, may return cached key for wrong chain"
   - If cache is valid (within 5 minutes), the cached key from the previous chain is returned
   - `clients/js/src/cipher.ts:226-263` - Client encrypts calldata with the wrong chain's public key
   - Encrypted transaction is submitted to the new chain

4. **Trust boundary crossed**: At line 166, the cache returns data for a different security domain without validation.

5. **Impact**: Two possible outcomes:

   **Scenario A (Deoxys-II auth failure)**: Transaction fails with authentication error. This is a **usability issue** - the user's transaction is rejected and they must retry after cache expiration or manual cache clearing.

   **Scenario B (Key collision)**: If the two chains happen to have the same public key (extremely unlikely but possible), the transaction is encrypted with the wrong key. The runtime on the new chain cannot decrypt it, and the transaction fails.

The impact is **not** a confidentiality breach because:
- Deoxys-II is an authenticated encryption scheme
- Decryption fails with auth tag mismatch if the wrong key is used
- The attacker does not gain access to the calldata

#### Code Path

- `clients/js/src/calldatapublickey.ts:14` - Cache expiration: 5 minutes (300,000ms)
- `clients/js/src/calldatapublickey.ts:96-102` - `eth_chainId` is fetched but **not used** for cache validation
- `clients/js/src/calldatapublickey.ts:162-168` - **Missing validation**: Cache check ignores chain ID
- `clients/js/src/calldatapublickey.ts:170` - New fetch only happens after cache expires

#### What This Means for Sapphire

For Web3 applications that support multi-chain deployments:
- **Transaction failures on chain switch**: Users who switch networks will experience failed transactions for up to 5 minutes
- **Poor UX**: No clear error message linking the failure to cache invalidation
- **Development friction**: Developers must manually clear the cache when testing cross-chain scenarios

This is an **adjacent trust-path** issue because:
- It doesn't break the fundamental confidentiality guarantee (Deoxys-II auth prevents decryption with wrong keys)
- It impacts availability and usability, not data protection
- The attack requires user action (switching chains), not just network position

#### Remediation

1. **Validate chain ID in cache check**:
   ```typescript
   // In clients/js/src/calldatapublickey.ts:162-168
   if (this.pubkey) {
     const pk = this.pubkey;
     const expiry = Date.now() - this.timeoutMilliseconds;
     if (pk.fetched && pk.fetched.valueOf() >= expiry && pk.chainId === chainId) {
       return pk;  // Only return cached key if chain ID matches
     }
   }
   ```

2. **Clear cache on provider chain change**:
   ```typescript
   // Add a method to explicitly clear the cache
   public clearCache(): void {
     this.pubkey = undefined;
   }
   ```

3. **Reduce cache expiration** for multi-chain scenarios or make it configurable

4. **Add error handling** with clear messaging when Deoxys-II auth fails, suggesting a cache refresh

**Note**: This mitigation becomes more important after fixing V-01, because once signature verification is added, a cross-chain key substitution would fail verification (the keymanager signing keys differ per chain).

#### V1 to V2 Grade History

| Version | Severity | Notes |
|---------|----------|-------|
| v1      | Informational | Original observation with developer XXX comment |
| v2      | Medium | **Upgraded from Informational** - Realistic attack scenario with user impact. Deoxys-II prevents confidentiality breach, but transaction failures are a real UX issue. |

---

## Positive Guards

### PG-01: Debug-Mock-SGX Disabled in Production

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-01 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | The `debug-mock-sgx` feature is properly gated and production builds do not enable mock SGX mode |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/lib.rs:6,224-238` - Feature-gated implementation:
  - `#[cfg(feature = "debug-mock-sgx")]` (line 224): When enabled, uses `TrustedSigners::unsafe_mock()`
  - `#[cfg(not(feature = "debug-mock-sgx"))]` (line 229): When disabled (production), uses `keymanager::trusted_policy_signers()`
- `runtime/Cargo.toml:37` - Feature definition: `debug-mock-sgx = ["oasis-runtime-sdk/debug-mock-sgx"]`
- No production builds enable this feature (verified by absence of `debug-mock-sgx` in release profiles)

#### Completeness Status

**complete** - The feature gate covers all paths that would use mock SGX. All required fields are validated. No temporal properties affected. Smart contracts cannot bypass this guard.

---

### PG-02: TrustRoot Correctly Hardcoded

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-02 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | TrustRoot values are correctly hardcoded for both testnet and mainnet |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/lib.rs:240-263` - Hardcoded TrustRoots:
  - Testnet (lines 243-251): Height 26000000, specific hash, runtime_id, chain_context
  - Mainnet (lines 254-261): Different height, hash, runtime_id, chain_context
  - Selection logic: `is_testnet()` function (lines 26-28) checks for pre-release version component

#### Completeness Status

**complete** - All required TrustRoot fields are present. TrustRoot is enforced at the consensus layer. Values are immutable constants. Smart contracts inherit this protection.

---

### PG-03: TrustedSigners Properly Configured

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-03 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Keymanager trusted signers are properly configured in production builds |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/lib.rs:229-238` - Production path:
  - Line 231: `keymanager::trusted_policy_signers()` fetches the real policy signers
  - Lines 234-236: Conversion between oasis-core versions (SDK compatibility)
- `runtime/src/lib.rs:225-226` - Debug path (gated): `TrustedSigners::unsafe_mock()` only available with `debug-mock-sgx` feature

#### Completeness Status

**complete** - The `TrustedSigners` struct includes all required fields. Key rotation is handled by the keymanager-paratime (external TEE). Smart contracts cannot influence this configuration.

---

### PG-04: Confidential EVM Flag Enabled

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-04 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | The `CONFIDENTIAL` flag is always set to `true` for the EVM module |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/lib.rs:77` - Constant definition: `const CONFIDENTIAL: bool = true;`
- `runtime/src/lib.rs:70-78` - EVM config implementation:
  - Line 73: `const CHAIN_ID: u64 = chain_id();`
  - Line 77: `const CONFIDENTIAL: bool = true;` - Always enabled
- No conditional logic or feature gates affect this setting

#### Completeness Status

**complete** - The flag is enforced by oasis-core's EVM module. All contract state encryption and decryption respects this setting. No temporal properties affected.

---

### PG-05: SGX Build Config: Debug=False

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-05 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | SGX enclave is built in non-debug mode with secure configuration |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/Cargo.toml:18` - SGX configuration:
  - `debug = false` - Non-debug mode
  - `heap-size = 536870912` (512 MiB)
  - `stack-size = 2097152` (2 MiB)
  - `threads = 26`
- `runtime/Cargo.toml:31-33` - Release profile:
  - `codegen-units = 1` - Single codegen unit for better optimization
  - `lto = "thin"` - Link-time optimization enabled

#### Completeness Status

**complete** - All critical parameters are set. These settings are enforced by the Fortanix SGX toolchain at build time. No runtime rotation needed.

---

### PG-06: Curve25519 Scalar Clamping (RFC 7748)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-06 |
| **Trust-Path Tier**     | adjacent |
| **What Was Verified**   | Curve25519 scalar clamping is correctly implemented per RFC 7748 section 5 |
| **Completeness Status** | complete |

#### Code Evidence

- `contracts/contracts/Sapphire.sol:149-153` - Scalar clamping in `generateCurve25519KeyPair()`:
  ```solidity
  scalar[0] &= 0xf8;  // Clear bits 0,1,2 (make multiple of 8)
  scalar[31] &= 0x7f; // Clear bit 255 (clamp to < 2^255 - 19)
  scalar[31] |= 0x40; // Set bit 254 (clamp to >= 2^254)
  ```
- `clients/js/src/munacl.ts:570-572` - Same clamping in JS client:
  ```typescript
  z[0] &= 248;
  z[31] = (n[31] & 127) | 64;
  ```

#### Completeness Status

**complete** - All code paths that generate Curve25519 keypairs apply clamping. All three clamping operations from RFC 7748 §5 are implemented. No temporal properties affected.

---

### PG-07: Calldata Key Derivation Uses Domain Separator

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-07 |
| **Trust-Path Tier**     | adjacent |
| **What Was Verified**   | Key derivation uses a domain separator to prevent key confusion |
| **Completeness Status** | complete |

#### Code Evidence

- `clients/js/src/cipher.ts:254-260` - JS client key derivation:
  ```typescript
  const keyBytes = hmac
    .create(sha512_256, new TextEncoder().encode('MRAE_Box_Deoxys-II-256-128'))
    .update(naclScalarMult(keypair.secretKey, peerPublicKey))
    .digest().buffer;
  ```
- `clients/go/cipher.go:135` - Go client key derivation:
  ```go
  mrae.Box.DeriveSymmetricKey(sharedKey[:], peerPublicKey, &keypair.SecretKey)
  ```

#### Completeness Status

**complete** - All client libraries use domain-separated key derivation. The domain separator is a constant string. No temporal properties affected. The TEE-side uses the same derivation.

---

### PG-08: Deoxys-II AEAD Used (Authenticated Encryption)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-08 |
| **Trust-Path Tier**     | adjacent |
| **What Was Verified**   | All encryption paths use Deoxys-II AEAD with authentication |
| **Completeness Status** | complete |

#### Code Evidence

- `contracts/contracts/Sapphire.sol:228-238` - Encrypt precompile uses Deoxys-II
- `contracts/contracts/Sapphire.sol:272-282` - Decrypt precompile reverts on auth failure
- `clients/js/src/cipher.ts:266-274` - JS client encrypt method
- `clients/go/cipher.go:152-158` - Go client encrypt method

#### Completeness Status

**complete** - All encryption paths use Deoxys-II. Deoxys-II is an AEAD cipher with automatic authentication tag verification. No temporal properties affected. The misuse-resistant property is particularly valuable in blockchain contexts.

---

## Agent-Validated Unknowns

None. All v1 findings were either confirmed as issues or verified as complete positive guards. No items required manual validation after self-validation.

---

## Architectural Observations

### AO-01: Confidentiality Guarantees Weaker Than Stated

The Sapphire documentation states "all state is encrypted," but the project's own documentation clarifies that confidentiality is not absolute:

**Documented limitations** (from `docs/develop/concept.mdx` and `docs/ethereum.mdx`):
1. **Access patterns leak**: Storage access patterns are observable to the compute node
2. **Logs/events are public**: Solidity events emitted via `emit` are not encrypted
3. **Immutable/constant data is exposed**: Variables declared as `immutable` or `constant` are in unencrypted bytecode
4. **Gas usage leaks information**: Different code paths have different gas costs
5. **Transaction size is public**: Calldata length is not hidden

**What This Means for Web3 Developers**:

Developers using Sapphire for confidential applications must:
- Avoid using `immutable`/`constant` for private data
- Fork and modify base contracts (like OpenZeppelin) to remove event emissions
- Consider ORAM or other obfuscation for sensitive access patterns
- Use gas padding to equalize execution costs across branches
- Pad variable-length inputs to fixed sizes before encryption

**Recommendation**:

Update marketing and documentation to clarify:
- "State is encrypted" → "Contract state is encrypted, but access patterns and events are observable"
- Add a prominent "Confidentiality Limitations" section in developer docs
- Provide a security checklist for confidential dApp development

---

## Appendix: Full Invariant Cross-Reference Index

### Finding ID to Invariant ID Mapping

| Finding ID | Invariant ID(s) |
|------------|----------------|
| V-01       | INV-07, INV-08 |
| V-02       | INV-07 |
| PG-01      | INV-01 |
| PG-02      | INV-02 |
| PG-03      | INV-03 |
| PG-04      | INV-04 |
| PG-05      | INV-05 |
| PG-06      | INV-06 |
| PG-07      | INV-07 |
| PG-08      | INV-08 |

### Invariant ID to Finding ID Mapping

| Invariant ID | Finding ID(s) |
|--------------|---------------|
| INV-01       | PG-01 |
| INV-02       | PG-02 |
| INV-03       | PG-03 |
| INV-04       | PG-04 |
| INV-05       | PG-05 |
| INV-06       | PG-06 |
| INV-07       | V-01, V-02, PG-07 |
| INV-08       | V-01, PG-08 |
| INV-09       | AO-01 (architectural observation) |

---

## Methodology

### Stage 5b Verification Protocol

This v2 report was produced through Stage 5b deep verification, which involved:

1. **Code reading**: ±50 lines around each v1 finding location
2. **Lower-layer guard search**: Checked called functions, parent modules, and platform SDKs for validation logic
3. **Conditional compilation check**: Looked for `#[cfg(feature = ...)]` and `#ifdef` directives
4. **Test-only path analysis**: Verified no test-only paths leak to production
5. **Deployment mitigation check**: Searched documentation for deployment-level mitigations
6. **Completeness assessment**: Evaluated each finding across 4 dimensions:
   - Cross-boundary: Does the guard reach all runtime operations?
   - Field-level: Are all required fields validated?
   - Lifecycle: Are temporal properties handled correctly?
   - Web3 composability: Are smart contract interactions safe?

### Evidence Grading

Following the evidence grading reference:
- **Confirmed issue**: Concrete violated property + concrete live-path enforcement gap + concrete code evidence
- **Likely issue**: Strong code-level gap + important trust path + one open semantic question
- **Weak signal**: Suspicious pattern but could be explained by wrappers or lower-layer guards
- **Positive guard**: Confirmed defense with completeness status

---

## Summary

| ID | Severity | Tier | Status | v1 ID |
|----|----------|------|--------|-------|
| V-01 | High | core | Confirmed | F-10 |
| V-02 | Medium | adjacent | Confirmed | F-09 |
| PG-01 | - | core | Complete | F-01 |
| PG-02 | - | core | Complete | F-02 |
| PG-03 | - | core | Complete | F-03 |
| PG-04 | - | core | Complete | F-04 |
| PG-05 | - | core | Complete | F-05 |
| PG-06 | - | adjacent | Complete | F-06 |
| PG-07 | - | adjacent | Complete | F-07 |
| PG-08 | - | adjacent | Complete | F-08 |
| AO-01 | - | - | Observation | F-04 re-grade |

**Total**: 2 issues (1 High, 1 Medium), 8 complete positive guards, 1 architectural observation

The most critical finding (V-01) requires immediate remediation as it breaks the core confidentiality guarantee of Sapphire. The medium finding (V-02) impacts usability but not confidentiality. All 8 positive guards are complete and provide strong security foundations.
