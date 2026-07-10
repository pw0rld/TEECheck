# Collection Methodology

## Snapshot

- Last refreshed: 2026-07-10
- Primary machine-readable source: NVD CVE API 2.0
- Identity cross-check: CVE.org
- Confirmation sources: vendor advisories, project security advisories, and
  public patch references linked by the CVE record

The corpus stores one Markdown file per CVE. NVD candidates are retained with
`needs_vendor_review`; this status is deliberately weaker than confirmation.

## Search Families

The collection was built from exact and product-oriented searches covering:

- Intel SGX, Intel TDX, SGX SDK, and DCAP
- AMD SEV, SEV-ES, and SEV-SNP
- OP-TEE and Arm TrustZone
- Qualcomm QSEE
- Samsung TEEGRIS and Samsung TrustZone
- Trustonic Kinibi
- Microsoft Open Enclave
- Trusted Firmware-M
- Gramine, Google Trusty, AWS Nitro Enclaves, and Keystone

Zero-result searches are still useful coverage evidence. At this snapshot,
exact NVD keyword searches for Gramine, Google Trusty, AWS Nitro Enclaves,
Keystone, and Arm CCA did not produce records under those names. This does not
prove that the projects have never been affected; records may use dependency,
hardware, firmware, or vendor-specific terminology instead.

## Inclusion Filter

Include a record when its CVE description, affected product, or authoritative
advisory explicitly ties the vulnerability to a TEE implementation, enclave,
trusted OS, trustlet, secure-world boundary, confidential VM technology, or TEE
attestation/TCB policy.

Exclude records when TEE terminology is incidental. Examples include a normal
application that merely stores data through a Secure Enclave API, or a platform
exploit whose description explicitly says Secure Enclave protections are not
breached. Generic firmware, hypervisor, kernel, and CPU vulnerabilities are not
included solely because they could coexist with a TEE.

## Deduplication And Refresh

The CVE identifier is the corpus key. Results from overlapping queries are
merged into one file. Refreshes must preserve manually reviewed records and add
new candidates without downgrading their review status.

For each refresh:

1. Query NVD and vendor/project advisory indexes.
2. Normalize and deduplicate CVE identifiers.
3. Apply the explicit TEE-relevance filter.
4. Add new records as `needs_vendor_review`.
5. Verify authoritative references before promotion to `reviewed`.
6. Regenerate `CATALOG.md` and run structural checks.

## Known Blind Spots

- Vendor bulletins that do not assign CVEs.
- Android security issues described only by internal bug IDs.
- Withdrawn, rejected, reserved, or embargoed CVE records.
- Hardware attacks published as papers without CVE assignments.
- Proprietary trustlets whose advisory omits the TEE product name.
- Vulnerabilities inherited only through dependencies unless the TEE impact is
  explicitly documented.

These blind spots should be tracked separately from the scored benchmark. A
large candidate corpus is useful for recall and taxonomy work, while only
reviewed, reproducible fixtures should determine scanner accuracy.
