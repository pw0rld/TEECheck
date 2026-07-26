# Dev/Holdout Split for OP-TEE CVE Benchmark

This document describes the frozen dev/holdout split for the 44 OP-TEE CVE cases in `teecheck-benchmark/datasets/`.

## Source of Truth

The canonical partition is defined in `split.v1.json` with:
- **Seed**: 20260724
- **Method**: stratified by (twe_family, cwe) with alternating start side per stratum; twe_family recovered from commit c3e3e28^ and used for stratification only, never as scoring truth
- **Frozen at**: 2026-07-26

## Split Composition

| Split | Count | Coverage |
|-------|-------|----------|
| **Dev**   | 23 | Working set for playbook authoring |
| **Holdout** | 21 | Reserved for unbiased evaluation |
| **Total** | 44 | |

## Per-Family Distribution

| TWE Family | Dev | Holdout | Total |
|------------|-----|---------|-------|
| Flow       | 8   | 6       | 14    |
| Guard      | 2   | 2       | 4     |
| Leakage    | 5   | 4       | 9     |
| State      | 2   | 3       | 5     |
| Out-of-scope | 6 | 6       | 12    |
| **Total**  | **23** | **21** | **44** |

## Contamination Note

**CVE-2019-1010292** was moved from holdout to dev on 2026-07-24. Its fix.patch and oracle.yaml were displayed during design exploration before the split was frozen, and the 2026-07-24 end-to-end probe ran against its fixture. Therefore, it is treated as contaminated with respect to holdout-side evaluation.

## Discipline

**Holdout case material (patches, oracles, sources) must not be read while authoring playbooks.** This constraint ensures that evaluation on holdout cases provides meaningful measurement of out-of-distribution generalization.

## Measurement Ceiling

The benchmark's theoretical recall ceiling is **32/44 = 73%**, because 12 cases are outside TWE (Trusted Execution Environment Weakness) scope and cannot be correctly diagnosed by a TWE-specific threat model.

## References

- Machine-readable partition: `split.v1.json`
- OP-TEE CVE fixture directory: `teecheck-benchmark/datasets/`
