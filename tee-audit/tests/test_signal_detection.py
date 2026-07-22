"""Tests for expanded TEE/Web3 signal detection patterns."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tee_audit.patterns.tee_signals import (
    BUILD_FLAG_PATTERNS,
    CRITICAL_PATH_DIRS,
    TEE_PLATFORM_PATTERNS,
    TRUST_ARTIFACT_PATTERNS,
    WEB3_ROLE_PATTERNS,
)
from tee_audit.stages.fingerprint import run_fingerprint


class TestTEEPlatformPatterns:
    def test_sgx_patterns(self):
        pattern = re.compile(TEE_PLATFORM_PATTERNS["SGX"], re.IGNORECASE)
        assert pattern.search("use sgx_types::*;")
        assert pattern.search("#include <sgx.h>")
        assert pattern.search("SGX_ENCLAVE")

    def test_tdx_patterns(self):
        pattern = re.compile(TEE_PLATFORM_PATTERNS["TDX"], re.IGNORECASE)
        assert pattern.search("tdx_attest")
        assert pattern.search("TDX_MODULE")

    def test_nitro_patterns(self):
        pattern = re.compile(TEE_PLATFORM_PATTERNS["Nitro"], re.IGNORECASE)
        assert pattern.search("aws_nitro_enclave")
        assert pattern.search("PCR0")

    def test_sev_snp_patterns(self):
        pattern = re.compile(TEE_PLATFORM_PATTERNS["SEV_SNP"], re.IGNORECASE)
        assert pattern.search("sev_snp")
        assert pattern.search("SEV_SNP_LAUNCH")

    def test_arm_tz_patterns(self):
        pattern = re.compile(TEE_PLATFORM_PATTERNS["ARM_TZ"], re.IGNORECASE)
        assert pattern.search("trustzone")
        assert pattern.search("OP-TEE")

    def test_cvm_patterns(self):
        pattern = re.compile(TEE_PLATFORM_PATTERNS["CVM"], re.IGNORECASE)
        assert pattern.search("confidential_vm")
        assert pattern.search("azure_cvm")


class TestWeb3RolePatterns:
    def test_defi_compound_patterns(self):
        pattern = re.compile(WEB3_ROLE_PATTERNS["defi_or_amm"], re.IGNORECASE)
        assert pattern.search("liquidity_pool")
        assert pattern.search("automated_market_maker")
        assert pattern.search("yield_farming")

    def test_governance_patterns(self):
        pattern = re.compile(WEB3_ROLE_PATTERNS["governance_or_dao"], re.IGNORECASE)
        assert pattern.search("dao_proposal")
        assert pattern.search("governance_vote")

    def test_privacy_patterns(self):
        pattern = re.compile(WEB3_ROLE_PATTERNS["privacy_or_zk"], re.IGNORECASE)
        assert pattern.search("zero_knowledge")
        assert pattern.search("zk_proof")
        assert pattern.search("groth16")


class TestTrustArtifactPatterns:
    def test_crypto_operations(self):
        pattern = re.compile(TRUST_ARTIFACT_PATTERNS["crypto_operations"], re.IGNORECASE)
        assert pattern.search("secp256k1")
        assert pattern.search("ed25519_sign")
        assert pattern.search("aes_256_gcm")

    def test_state_continuity(self):
        pattern = re.compile(TRUST_ARTIFACT_PATTERNS["state_and_continuity"], re.IGNORECASE)
        assert pattern.search("snapshot")
        assert pattern.search("journal_entry")
        assert pattern.search("rollback")


class TestBuildFlagPatterns:
    def test_tee_build_flags(self):
        pattern = re.compile(BUILD_FLAG_PATTERNS["tee_build_flags"], re.IGNORECASE)
        assert pattern.search("SGX_MODE=SIM")
        assert pattern.search("cargo sgx build")
        assert pattern.search("EDGER8R")

    def test_environment_trust_compound(self):
        pattern = re.compile(BUILD_FLAG_PATTERNS["environment_trust_inputs"], re.IGNORECASE)
        assert pattern.search("env::var('SECRET_KEY')")
        assert pattern.search("dotenv secret")


class TestCriticalPathDirs:
    def test_tee_dirs(self):
        assert "tee" in CRITICAL_PATH_DIRS

    def test_crypto_dirs(self):
        assert "crypto" in CRITICAL_PATH_DIRS

    def test_network_dirs(self):
        assert "rpc" in CRITICAL_PATH_DIRS
        assert "gateway" in CRITICAL_PATH_DIRS


class TestSignalIntegration:
    def test_arm_tz_detected_in_repo(self, tmp_path: Path):
        repo = tmp_path / "tz-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        src = repo / "src"
        src.mkdir()
        (src / "main.c").write_text('#include <trustzone.h>\nTEEC_Result res;')
        output = run_fingerprint(repo)
        assert "ARM_TZ" in output.fingerprint.tee_platforms

    def test_defi_detected_in_repo(self, tmp_path: Path):
        repo = tmp_path / "defi-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        src = repo / "src"
        src.mkdir()
        (src / "pool.rs").write_text('fn liquidity_pool_add() {}')
        output = run_fingerprint(repo)
        assert "defi_or_amm" in output.fingerprint.web3_roles

    def test_crypto_operations_detected(self, tmp_path: Path):
        repo = tmp_path / "crypto-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        src = repo / "src"
        src.mkdir()
        (src / "sig.rs").write_text('use ed25519_dalek;')
        output = run_fingerprint(repo)
        assert "crypto_operations" in output.fingerprint.trust_artifacts
