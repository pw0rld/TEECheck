# CVE-YYYY-NNNN: Short title

## Metadata

- Platform:
- Component:
- Layer: `hardware | firmware | trusted_os | sdk | application`
- Impact:
- Severity:
- Disclosure date:
- Benchmark role: `source_fixture | policy_fixture | knowledge_only`
- Benchmark readiness: `candidate | specified | fixture_ready | scored`
- Scoring status: `excluded | eligible`

## Summary

Concise description based on an authoritative advisory.

## TEE Relevance

Explain how the issue crosses or weakens the TEE threat boundary.

## Threat Model and Impact

- Attacker position:
- Required privileges:
- Security property affected:

## Mitigation

Record the vendor mitigation and affected/patched versions when available.

## Benchmark Use

- Source reproducible:
- Suggested vulnerable fixture:
- Suggested negative control:
- Expected TEECheck behavior:

## Benchmark Specification

- Detection surface: `source | attestation_policy | configuration | knowledge_only`
- Positive fixture: exact vulnerable revision or intentionally vulnerable minimal case
- Negative fixture: exact patched revision or minimal case containing the required guard
- Trigger/input: attacker-controlled input or policy evidence that reaches the defect
- Oracle: expected vulnerability location, evidence path, and verdict
- Required evidence: advisory, affected version, fix, and source/behavior correspondence
- Scoring status: excluded until all required evidence and both fixtures are reviewed
- Exclusion reason: state the concrete missing artifact; never use an implicit placeholder

## Ground-Truth Checklist

- [ ] Authoritative advisory verified
- [ ] Affected and fixed revisions pinned
- [ ] Positive fixture reproduces the vulnerable behavior or code pattern
- [ ] Negative fixture differs only by the security-relevant fix
- [ ] Oracle reviewed independently of scanner output
- [ ] Expected vulnerability evidence and acceptable alternate paths recorded
- [ ] Build/run instructions are deterministic

## Sources

- Vendor advisory:
- CVE record: https://www.cve.org/CVERecord?id=CVE-YYYY-NNNN
