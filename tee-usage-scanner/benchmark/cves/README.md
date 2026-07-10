# TEE CVE Corpus

This directory contains one Markdown record per public CVE associated with a
Trusted Execution Environment technology, implementation, firmware component,
SDK, trusted OS, or confidential-computing integration.

See [CATALOG.md](CATALOG.md) for the complete index.
See [COLLECTION.md](COLLECTION.md) for collection queries, filtering rules, and
known coverage limits.
See [BENCHMARK-SPEC.md](BENCHMARK-SPEC.md) for fixture and scoring requirements.
`MANIFEST.jsonl` exposes the normalized status of every record to scripts and
future benchmark runners.

## Coverage

The current collection includes records discovered through NVD keyword queries
and authoritative vendor/project advisories for:

- Intel SGX, SGX SDK/DCAP, and SGX-based runtimes.
- Intel TDX processors, firmware, and TDX Module software.
- AMD SEV, SEV-ES, and SEV-SNP.
- OP-TEE and Linux OP-TEE integration.
- Arm TrustZone implementations.
- Qualcomm QSEE and Samsung TEEGRIS/TrustZone trustlets.
- Trustonic Kinibi.
- Microsoft Open Enclave SDK.
- Trusted Firmware-M.

The corpus is broad by design, but it is not claimed to be mathematically
complete. CVE descriptions are inconsistently tagged, and proprietary mobile
TEEs often lack public source, patches, stable product names, or enough technical
detail for a useful benchmark. Completeness here means systematic coverage of
the documented sources and queries, followed by explicit triage.

## Inclusion Rules

A record is included when a public CVE description or authoritative advisory
explicitly connects the issue to a TEE technology or secure/non-secure boundary.
Ordinary CPU, kernel, or firmware CVEs are excluded when the TEE relationship is
only inferred.

Unassigned research findings and TEECheck's own disclosure drafts remain outside
this directory until a CVE is published.

## Quality Levels

| Status | Meaning |
|---|---|
| `reviewed` | Manually checked against a vendor or project advisory and enriched for benchmark use. |
| `needs_vendor_review` | Collected from NVD with original references, but not yet benchmark ground truth. |

Only `reviewed` records should enter scored benchmark suites.
Review alone does not make a case scoreable: the positive fixture, negative
fixture, and human-reviewed oracle must also exist.

## Benchmark Roles

| Role | Meaning |
|---|---|
| `source_fixture` | Vulnerable and patched source revisions are identified. |
| `source_fixture_candidate` | Likely source-reproducible, but versions/patch/oracle still need review. |
| `policy_fixture` | Motivates an attestation, TCB, or configuration fixture; the underlying hardware bug is not statically detectable. |
| `knowledge_only` | Useful threat-model context but unsuitable for ordinary CI reproduction. |
| `needs_triage` | Layer and benchmark role have not yet been assigned. |

## Per-CVE Record

Each Markdown file keeps:

- Platform and likely implementation layer.
- Publication and modification dates when supplied by NVD.
- Public vulnerability description.
- TEE relevance and tentative benchmark role.
- NVD, CVE.org, vendor, project, and patch references when available.
- Reproduction/oracle work still required before scoring.

Use [_TEMPLATE.md](_TEMPLATE.md) when manually adding or promoting a record.

## Promotion Workflow

```text
NVD/vendor candidate
  -> verify authoritative advisory
  -> identify vulnerable version and fix
  -> classify TWE and benchmark role
  -> build vulnerable/fixed fixture pair
  -> human-review oracle
  -> add to scored benchmark suite
```

Hardware and firmware CVEs must not be presented as directly detectable source
bugs. They are useful for testing whether relying-party code enforces TCB,
advisory, SVN, debug, and mitigation policy.
