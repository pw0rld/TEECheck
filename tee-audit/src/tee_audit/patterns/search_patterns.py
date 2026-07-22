"""General search patterns — ported from search-patterns.md reference."""

from __future__ import annotations

# Platform detection patterns
PLATFORM_PATTERNS: dict[str, list[str]] = {
    "sgx": [
        r"isv_svn|isvprodid",
        r"mr_enclave|mr_signer|MRENCLAVE|MRSIGNER",
        r"sgx_quote|quote3|dcap",
        r"enclave.*sign|sgx_sign",
        r"aesm|launch.*token",
    ],
    "tdx": [
        r"tdx|TDX",
        r"mrtd|mr_td",
        r"td.?quote|tdx.?quote",
        r"td.?report|tdx.?report",
    ],
    "nitro": [
        r"PCR[0-9]|pcr[0-9]",
        r"attestation.?document",
        r"nitro|Nitro",
        r"kms.?policy|aws.?kms",
    ],
    "sev_snp": [
        r"SEV|sev",
        r"SNP|snp",
        r"guest.?report|launch.?digest",
        r" AttestationReport",
    ],
}

# Attestation-related patterns
ATTESTATION_PATTERNS: list[str] = [
    r"verify.*quote|verify.*attestation|verify.*report",
    r"generate.*quote|generate.*attestation|generate.*report",
    r"collateral|verification.*report",
    r"certificate.*chain|root.*ca",
]

# Simulation/debug patterns (security-relevant)
SIMULATION_PATTERNS: list[str] = [
    r"sgx.*sim|simulation.*mode|debug.*enclave",
    r"cfg\(test\)|#\[cfg\(test\)\]",
    r"feature\s*=\s*\"debug\"",
    r"DEBUG_ENCLAVE|_SIMULATION",
]

# Guard patterns — security checks that should be present
GUARD_PATTERNS: list[str] = [
    r"verify|validate|check|assert",
    r"authenticate|authorize",
    r"compare|match|equals",
    r"expected.*measurement|expected.*mr",
]

# State/flow patterns — data crossing trust boundaries
FLOW_PATTERNS: list[str] = [
    r"seal|unseal|encrypt|decrypt",
    r"send|receive|write|read",
    r"ecall|ocall|entrypoint",
    r"ioctl|mailbox|channel",
]
