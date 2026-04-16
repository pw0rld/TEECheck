"""TEE platform signal patterns — ported from collect_tee_signals.sh."""

from __future__ import annotations

# TEE platform signal patterns: label -> regex
TEE_PLATFORM_PATTERNS: dict[str, str] = {
    "SGX": r"SGX|sgx|MRENCLAVE|MRSIGNER|report_data|quote3|dcap|isv_svn",
    "TDX": r"TDX|tdx|td.?quote|mrtd",
    "Nitro": r"Nitro|PCR[0-9]|attestation.?document|kms.?policy",
    "SEV_SNP": r"SEV|SNP|guest.?report|launch.?digest",
}

# Web3 role signal patterns: role -> regex
WEB3_ROLE_PATTERNS: dict[str, str] = {
    "validator_or_consensus": r"validator|consensus|scp|quorum|paratime|runtime",
    "key_manager_or_signer": r"key.?manager|signer|signing|mint|release.*key",
    "oracle_bridge_offchain": r"oracle|bridge|relayer|worker|coprocessor|offchain",
}

# Trust artifact signal patterns: type -> regex
TRUST_ARTIFACT_PATTERNS: dict[str, str] = {
    "attestation_artifacts": (
        r"attest|attestation|quote|report|evidence|verification.?report|collateral"
    ),
    "identity_artifacts": (
        r"measurement|MRENCLAVE|MRSIGNER|PCR|report_data|public.?key|mr_signer|mr_enclave"
    ),
    "state_and_continuity": (
        r"seal|sealed|unseal|restore|recovery|migrate|rollback|clone|epoch|counter|"
        r"sequence|version"
    ),
}

# Build flag signal patterns: type -> regex
BUILD_FLAG_PATTERNS: dict[str, str] = {
    "simulation_or_debug": r"sgx-sim|simulation|debug|DEBUG_ENCLAVE|cfg\(test\)|feature\s*=",
    "environment_trust_inputs": (
        r"env::var|std::env|read_to_string|SystemTime|timestamp|fs::|std::fs"
    ),
}

# Critical path directory names
CRITICAL_PATH_DIRS: list[str] = [
    "attest", "attestation", "consensus", "enclave", "fog", "sgx",
    "runtime", "worker", "sign", "key", "policy", "bridge", "oracle",
    "client", "server", "ledger",
]

# File extension to CodeQL language mapping
EXTENSION_LANGUAGE_MAP: dict[str, str] = {
    "rs": "rust",
    "go": "go",
    "c": "cpp",
    "cc": "cpp",
    "cpp": "cpp",
    "cxx": "cpp",
    "h": "cpp",
    "hpp": "cpp",
    "java": "java",
    "js": "javascript",
    "ts": "javascript",
    "py": "python",
}
