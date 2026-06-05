"""TEE platform signal patterns — ported from collect_tee_signals.sh."""

from __future__ import annotations

# TEE platform signal patterns: label -> regex
TEE_PLATFORM_PATTERNS: dict[str, str] = {
    "SGX": r"SGX|sgx|MRENCLAVE|MRSIGNER|report_data|quote3|dcap|isv_svn|aesm|sgx_arch|sgx_types|sgx_urts|sgx_uae|enclave_sign|Edger8r",
    "TDX": r"TDX|tdx|td.?quote|mrtd|tdx.?attest|tdx.?report",
    "Nitro": r"Nitro|PCR[0-9]|attestation.?document|kms.?policy|nitro.*enclave|aws.*enclave",
    "SEV_SNP": r"SEV|SNP|guest.?report|launch.?digest|sev.*es|amd.*snp|snp.*cert",
    "ARM_TZ": r"TrustZone|trustzone|OP-TEE|optee|tz.?os|secure.?world|normal.?world|smc.?call",
    "CVM": r"confidential.?vm|cvm|azure.?cvm|gcp.?cvm",
}

# Web3 role signal patterns: role -> regex
WEB3_ROLE_PATTERNS: dict[str, str] = {
    "validator_or_consensus": r"validator|consensus|scp|quorum|paratime|runtime|tendermint|cometbft|poa|pos",
    "key_manager_or_signer": r"key.?manager|signer|signing|mint|release.*key|threshold.?sign|multisig|kms|HSM|hsm",
    "oracle_bridge_offchain": r"oracle|bridge|relayer|worker|coprocessor|offchain|cross.?chain|light.?client",
    "defi_or_amm": r"liquidity.?pool|amm|yield.?farm|yield.?vault|staking.?contract|defi|dex|swap.?pair|liquidity.?mining|automated.?market",
    "governance_or_dao": r"governance|dao|proposal|vote.?power|delegate.?reward|council.?member|committee.?vote",
    "privacy_or_zk": r"zk.?proof|zero.?knowledge|snark|stark|groth16|plonk|private.?transaction",
}

# Trust artifact signal patterns: type -> regex
TRUST_ARTIFACT_PATTERNS: dict[str, str] = {
    "attestation_artifacts": (
        r"attest|attestation|quote|report|evidence|verification.?report|collateral|tee.?evidence"
    ),
    "identity_artifacts": (
        r"measurement|MRENCLAVE|MRSIGNER|PCR|report_data|public.?key|mr_signer|mr_enclave|merkle"
    ),
    "state_and_continuity": (
        r"seal|sealed|unseal|restore|recovery|migrate|rollback|clone|epoch|counter|"
        r"sequence|version|snapshot|journal"
    ),
    "crypto_operations": (
        r"encrypt|decrypt|cipher|aes|rsa|ecdsa|ed25519|secp256k1|hash|hmac|kdf|"
        r"sign|verify|key.?gen|tls|ssl|x509"
    ),
}

# Build flag signal patterns: type -> regex
BUILD_FLAG_PATTERNS: dict[str, str] = {
    "simulation_or_debug": r"sgx-sim|simulation|debug|DEBUG_ENCLAVE|cfg\(test\)|feature\s*=|SGX_MODE|SGX_DEBUG",
    "environment_trust_inputs": (
        r"env::var.*SECRET|env::var.*KEY|std::env.*PRIVATE|read_to_string.*key|dotenv.*secret"
    ),
    "tee_build_flags": (
        r"SGX_MODE|SGX_DEBUG|ENCLAVE_MODE|EDGER8R|sgx_edger8r|cargo.*sgx|sgx_build|"
        r"oe.*host|oe.*enclave|open.*enclave"
    ),
}

# Critical path directory names
CRITICAL_PATH_DIRS: list[str] = [
    "attest", "attestation", "consensus", "enclave", "fog", "sgx",
    "runtime", "worker", "sign", "key", "policy", "bridge", "oracle",
    "client", "server", "ledger",
    "tee", "cca", "realm", "crypto", "tls", "rpc", "gateway", "proxy", "relay",
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
