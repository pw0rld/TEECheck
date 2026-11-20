# Oracle and fixture review — 2026-11-21

This review uses the checked-in vulnerable/fixed source and `fix.patch`. It did
not query CVE services, execute exploits, or run an LLM benchmark. TWE scope is a
source-backed classification inference, recorded separately from CVE existence.
The source site and excerpt supporting each annotation live in
`oracle_review.scope_review` in its oracle.

## Fixture corrections

- `CVE-2023-42811` and `CVE-2026-33662` had reversed local variants: all relevant
  patch old-text hunks matched `fixed/` and new-text hunks matched `vulnerable/`.
  Their file contents were swapped and SHA-256 fields recalculated. Recorded
  upstream revisions were retained, not guessed or remotely reverified.
- `CVE-2019-1010297` has a key-generation fix hunk absent from both stored
  variants. Its derivation hunk matches, which is insufficient to certify the
  full pair. It is explicitly `requires_review` and excluded from evaluation.
- The validator now checks every fix hunk for included fixture files against
  its expected old/new source, independently of hashes. Upstream patch files
  outside the intentionally included fixture subset are not required.

## Scope and scoring

25 pairs are in scope and executable. Of 19 out-of-scope pairs, 18 are
executable and one requires review. Pure integer/memory defects, physical fault
injection, low-level timing side channels, and non-TEE library controls are
not counted as TWE capability targets. The reviewed in-scope families are Flow
13, Guard 7, State 3, Binding 1, Leakage 1; Config and Design remain uncovered.

All 44 have an explicit scope reason and source location. Symbols supplement
lines when exact line information is absent. Same-symbol findings elsewhere
than ±12 lines from a pinned target do not count. Explicit `related_twes` is
preferred to guessing class from an opaque finding identifier. Incidental
non-target findings are counted separately; a target-specific TN does not
mean the scanner produced no other warning.

## Per-pair review

| Pair | Scope | Fixture status | Primary site in vulnerable source |
|---|---|---|---|
| CVE-2016-6129 | Guard | ready | `src/pk/rsa/rsa_verify_hash.c:149` |
| CVE-2017-1000412 | out of scope | ready | `core/lib/libtomcrypt/sub.mk:122` |
| CVE-2017-1000413 | out of scope | ready | `lib/libmpa/mpa_expmod.c:67` |
| CVE-2019-0876 | Flow | ready | `enclave/core/sgx/report.c:403` |
| CVE-2019-1010292 | Flow | ready | `core/arch/arm/tee/entry_std.c:113` |
| CVE-2019-1010293 | Guard | ready | `core/arch/arm/mm/tee_mmu.c:778` |
| CVE-2019-1010294 | Leakage | ready | `core/arch/arm/kernel/user_ta.c:201` |
| CVE-2019-1010295 | Flow | ready | `core/tee/tee_svc.c:497` |
| CVE-2019-1010296 | out of scope | ready | `core/tee/tee_svc_cryp.c:1553` |
| CVE-2019-1010297 | out of scope | requires_review | `core/tee/tee_svc_cryp.c:2341` |
| CVE-2019-1010298 | out of scope | ready | `core/tee/tee_svc_cryp.c:3100` |
| CVE-2019-25052 | State | ready | `core/tee/tee_svc_cryp.c:2259` |
| CVE-2020-15107 | Flow | ready | `enclave/core/sgx/enter.S:177` |
| CVE-2020-15224 | Flow | ready | `syscall/devices/hostsock/hostsock.c:352` |
| CVE-2020-16273 | Guard | ready | `secure_fw/spm/cmsis_func/arch.c:22` |
| CVE-2021-27562 | Guard | ready | `secure_fw/spm/cmsis_psa/tfm_core_svcalls_ipc.c:132` |
| CVE-2021-32032 | out of scope | ready | `secure_fw/partitions/crypto/crypto_hash.c:103` |
| CVE-2021-40327 | Binding | ready | `secure_fw/partitions/crypto/crypto_key.c:87` |
| CVE-2021-43619 | Flow | ready | `secure_fw/partitions/firmware_update/tfm_fwu_req_mngr.c:286` |
| CVE-2021-44421 | Flow | ready | `src/libos/src/util/mem_util.rs:134` |
| CVE-2022-24713 | out of scope | ready | `src/compile.rs:263` |
| CVE-2022-46152 | Flow | ready | `core/tee/entry_std.c:257` |
| CVE-2023-37479 | Flow | ready | `enclave/core/sgx/enter.S:315` |
| CVE-2023-40271 | Guard | ready | `lib/ext/cryptocell-312-runtime/codesafe/src/psa_driver_api/src/cc3xx_internal_chacha20_poly1305.c:445` |
| CVE-2023-41325 | out of scope | ready | `lib/libmbedtls/core/rsa.c:188` |
| CVE-2023-42811 | out of scope | ready | `src/lib.rs:303` |
| CVE-2023-51712 | Guard | ready | `secure_fw/spm/core/tfm_svcalls.c:216` |
| CVE-2024-25742 | out of scope | ready | `arch/x86/kernel/sev-shared.c:581` |
| CVE-2024-45746 | Flow | ready | `secure_fw/partitions/ns_agent_mailbox/tfm_spe_mailbox.c:164` |
| CVE-2025-46733 | State | ready | `core/kernel/tee_ta_manager.c:504` |
| CVE-2025-53022 | Flow | ready | `secure_fw/partitions/firmware_update/bootloader/mcuboot/tfm_mcuboot_fwu.c:257` |
| CVE-2026-33317 | Flow | ready | `ta/pkcs11/src/object.c:839` |
| CVE-2026-33662 | out of scope | ready | `core/drivers/crypto/crypto_api/acipher/rsassa.c:48` |
| CVE-2026-40257 | out of scope | ready | `core/lib/libtomcrypt/sha3_accel.c:151` |
| CVE-2026-40290 | out of scope | ready | `core/arch/arm/mm/sp_mem.c:299` |
| CVE-2026-41434 | out of scope | ready | `ta/pkcs11/src/sanitize_object.c:225` |
| CVE-2026-41514 | out of scope | ready | `core/drivers/crypto/hisilicon/hpre_rsa.c:895` |
| CVE-2026-41515 | out of scope | ready | `core/drivers/crypto/caam/acipher/caam_rsa.c:970` |
| CVE-2026-41516 | out of scope | ready | `core/drivers/crypto/hisilicon/hpre_rsa.c:780` |
| CVE-2026-42546 | out of scope | ready | `core/tee/entry_std.c:270` |
| CVE-2026-44362 | State | ready | `core/crypto/signed_hdr.c:320` |
| CVE-2026-45614 | Guard | ready | `core/tee/tee_svc_cryp.c:3847` |
| CVE-2026-45702 | Flow | ready | `core/arch/arm/kernel/thread_spmc.c:964` |
| CVE-2026-53763 | out of scope | ready | `core/crypto/aes-gcm.c:151` |
