# Rust TEE Benchmark Sources

This inventory tracks Rust-based TEE projects separately from the C CVE set.
An entry is not a benchmark case until vulnerable and fixed source snapshots,
an exact patch, and a reviewed oracle are available.

## Projects and candidates

| Project | TEE role | Language | Candidate status |
| --- | --- | --- | --- |
| Apache Teaclave SGX SDK | Rust SDK/runtime for Intel SGX | Rust | Public source; `CVE-2021-24117` exists but is a side-channel and is excluded from the ordinary source benchmark |
| Occlum | Rust-heavy SGX library OS | Rust | `CVE-2021-44421` is source-backed and already represented in `datasets`; the vulnerability is classified as a side-channel/confused-deputy issue |
| Fortanix Enclave Development Platform / EnclaveOS | Rust SGX runtime and platform | Rust | `CVE-2023-38021` and `CVE-2023-38022` describe pointer-validation flaws, but the affected platform source and fixed pair are not publicly confirmed |
| Rust-SGX SDK / `sgx_tstd` | Rust SGX standard-library layer | Rust | Public source; the strongest CVE lead is `CVE-2021-24117`, which is side-channel-only |
| Keystone Rust SDK | Rust SDK for Keystone enclaves | Rust | Public research/software project; no verified CVE with a public vulnerable/fixed pair found in this pass |

## Evidence

- [Apache Teaclave SGX SDK](https://github.com/apache/teaclave-sgx-sdk) is a
  Rust SDK for Intel SGX applications.
- [CVE-2021-24117](https://nvd.nist.gov/vuln/detail/CVE-2021-24117) affects
  Teaclave/Rust SGX 1.1.3, but is explicitly a controlled-channel side-channel
  in base64 PEM decoding.
- [CVE-2021-44421](https://nvd.nist.gov/vuln/detail/CVE-2021-44421) points to
  `src/libos/src/util/mem_util.rs` and a fixed Occlum commit.
- [CVE-2023-38021](https://nvd.nist.gov/vuln/detail/CVE-2023-38021) and
  [CVE-2023-38022](https://nvd.nist.gov/vuln/detail/CVE-2023-38022) describe
  Fortanix EnclaveOS pointer-validation issues, but public source-pair
  provenance still needs confirmation.

## Ten real Rust/TEE vulnerability records

These are real vulnerability records, not synthetic TWE cases. Their status is
deliberately separated because a real advisory does not automatically imply
that a source benchmark can be constructed.

| ID | Affected Rust/TEE relationship | Benchmark disposition |
| --- | --- | --- |
| `CVE-2020-5499` | Baidu Rust SGX SDK; race can produce duplicate enclave global IDs | **Source candidate**; public exploit reference, needs vulnerable/fixed SDK snapshots |
| `CVE-2021-24117` | Apache Teaclave/Rust SGX SDK 1.1.3; base64 PEM side channel | Real, but **side-channel track only** |
| `CVE-2021-44421` | Occlum Rust-heavy SGX LibOS; missing pointer validation | **Source-backed**, already in `datasets` |
| `CVE-2021-0186` | Intel SGX SDK used by the Rust SGX SDK; exception-handler reentrancy | Real dependency vulnerability; source is Intel SDK, not a Rust-originated flaw |
| `CVE-2023-38021` | Fortanix EnclaveOS used with the Rust EDP ecosystem; alignment validation | Real, but affected platform source is not publicly confirmed |
| `CVE-2023-38022` | Fortanix EnclaveOS; insufficient validation in `strlen`/`sgx_is_within_user` | Real, but affected platform source is not publicly confirmed |
| `CVE-2024-25371` | Gramine SGX runtime, which can host Rust applications; SIGY signal injection | Real runtime issue, but Gramine is primarily C and needs its own language label |
| `CVE-2024-29970` | Fortanix EnclaveOS; SIGY-induced state corruption | Real, but affected platform source is not public |
| `CVE-2024-29971` | SIGY disclosure for an affected SGX runtime/library OS | Real disclosure record; affected source and fixed commit still need attribution |
| `CVE-2020-0561` | Intel SGX SDK used underneath Rust SGX applications; improper initialization | Real dependency vulnerability; not a Rust-source case until the exact source pair is verified |

The records are supported by NVD, Intel's advisory, Apache Teaclave's security
notice, and the SIGY disclosure. `CVE-2020-5499` is explicitly assigned to
the Baidu Rust SGX SDK; `CVE-2021-44421` has both vulnerable and fixed Occlum
commit references. The three SIGY identifiers are listed by the researchers'
disclosure page rather than inferred from a generic Rust dependency advisory.

## Current conclusion

The ten records above satisfy the requirement of being real vulnerability
records, but they do **not** yet represent ten source benchmark cases. Only
`CVE-2021-44421` is currently source-backed in this repository, while
`CVE-2020-5499` is the next source candidate to verify. The remaining records
must stay out of the ordinary source benchmark until exact vulnerable and fixed
source snapshots, patches, and oracles are available.
