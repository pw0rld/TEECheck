# TEE-Standard Review (2026-07)

Every executable CVE case was re-reviewed against a strict question: **is this a
defect inside the TEE?** (trusted OS, secure world, enclave, trusted app — not
the untrusted host or normal world). All CVE IDs were confirmed real (NVD +
vendor/project advisory + fix commit); none were fabricated. The 2026 OP-TEE
entries verify on NVD (e.g. CVE-2026-33317, published 2026-04-24).

## Grading rubric

- **A — core TEE weakness**: exists *because of* the TEE trust model
  (attestation soundness, sealing/rollback, secure/normal-world boundary
  validation of untrusted input, cross-client or secure-world isolation, TCB
  confidentiality/integrity). Would not be a vuln outside a TEE.
- **B — generic bug inside the TEE TCB**: a memory/arithmetic/crypto/resource/
  concurrency bug located in the trusted OS / secure world / enclave. It is in
  the TCB (so it matters) but the bug class is generic.
- **C — host / normal-world**: the code is in the untrusted host or normal
  world (Linux KVM/SEV hypervisor, Linux OP-TEE kernel driver, guest kernel).
  **Not a weakness in a TEE.**
- **D — questionable**: hardening-only / incidental TEE relevance / mislabeled.

## Removed (7) — not inside the TEE

| CVE | Where the code lives | Why removed |
|---|---|---|
| CVE-2021-47389 | Linux KVM `svm/sev.c` | untrusted hypervisor managing an SEV VM |
| CVE-2022-0171 | Linux KVM `svm/sev.c` | host cache-coherency fix; oracle also mislabeled it as SEV attestation |
| CVE-2022-48853 | Linux `kernel/dma/swiotlb.c` | normal-world DMA leak; confidential-VM relevance incidental |
| CVE-2025-21871 | Linux `drivers/tee/optee/supp.c` | normal-world OP-TEE kernel driver |
| CVE-2025-38374 | Linux `drivers/tee/optee/ffa_abi.c` | normal-world OP-TEE kernel driver |
| CVE-2025-71300 | `zynqmp.dtsi` device tree | normal-world boot config regression |
| CVE-2026-45851 | Linux guest EFI | guest-kernel arithmetic bug; TDX relevance incidental |

Their case directories and `cves/*.md` records were deleted; `MANIFEST.jsonl`,
`CATALOG.md`, and the benchmark counts were updated (research records 186→179,
executable cases 52→45).

## Kept (45 executable) — all inside the TEE

- **A — core TEE weakness (18)**: CVE-2019-0876, 2019-1010292, 2019-1010293,
  2019-1010294, 2019-1010295, 2020-15107, 2020-15224, 2020-16273, 2021-40327,
  2021-43619, 2021-44421, 2022-46152, 2023-37479, 2024-25742, 2024-45746,
  2025-46733, 2026-44362, 2026-45702. Plus the 2 synthetic (Binding, Config).
- **B — generic bug in the TCB (22)**: CVE-2016-6129, 2019-1010296/297/298,
  2019-25052, 2021-27562, 2021-32032, 2023-40271, 2023-41325, 2023-51712,
  2025-53022, 2026-33317, 2026-33662, 2026-40257, 2026-40290, 2026-41434,
  2026-41514, 2026-41515, 2026-41516, 2026-42546, 2026-45614, 2026-53763.
- **D — hardening, kept because in-TEE (3)**: CVE-2017-1000412 (RSA CRT
  fault-injection hardening), CVE-2017-1000413 (Montgomery-ladder timing),
  CVE-2021-24117 (rust-base64 SGX side channel). All are `case_kind: hardening`
  or should be; they live in the TEE but are defense-in-depth, not clear
  exploitable vulns.

The A vs B split matters: only the 18 A (plus 2 synthetic) are the TEE-*trust*
weaknesses the TWE pipeline targets; the 22 B are generic bugs that merely live
in the TCB. Report in-scope capability against the A set, not all 45.

## Known data defects still to fix (in kept cases)

- **CVE-2021-24117** — oracle labels it CWE-119 OOB, but the real issue is a
  data-dependent-table side channel fixed behind an off-by-default
  `slow_but_safe` feature flag. Relabel or drop.
- **CVE-2020-16273** — the fixture "fix" only adds `tfm_core_panic()`; it does
  not reproduce the documented stack-sealing mitigation. Re-pin the fix commit.
- **CVE-2026-41434** — oracle `primary_function` (`get_attribute`) does not
  match the real sink (`sanitize_indirect_attr`).
- **CVE-2021-27562** — CWE-367 (TOCTOU) label is questionable; it is a
  privileged-mode/context-check flaw.
