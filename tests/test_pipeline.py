"""Tests for pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tee_audit.config import AuditConfig
from tee_audit.pipeline import run_pipeline, PipelineError, STAGE_NAMES, HALT_ON_FAILURE_STAGES


# Mock get_commit_hash for all pipeline tests since fake repos don't have real git
@pytest.fixture(autouse=True)
def mock_commit_hash():
    with patch("tee_audit.pipeline.get_commit_hash", return_value="abc12345"):
        yield


class TestStageNames:
    def test_all_stages_present(self):
        for i in range(7):
            assert i in STAGE_NAMES

    def test_halt_stages_subset(self):
        assert HALT_ON_FAILURE_STAGES.issubset(set(STAGE_NAMES.keys()))


class TestRunPipeline:
    def test_stage0_only(self, tmp_repo: Path):
        config = AuditConfig(artifact_root=str(tmp_repo / "results"))
        ctx = run_pipeline(config, str(tmp_repo), stages=[0])
        assert ctx.get_last_completed() >= 0

    def test_nonexistent_repo_raises(self, tmp_path: Path):
        config = AuditConfig(artifact_root=str(tmp_path / "results"))
        with pytest.raises(FileNotFoundError):
            run_pipeline(config, str(tmp_path / "nonexistent"), stages=[0])

    def test_llm_stage_without_key_raises(self, tmp_repo: Path):
        config = AuditConfig(artifact_root=str(tmp_repo / "results"), llm_api_key="")
        with pytest.raises(PipelineError, match="API key"):
            run_pipeline(config, str(tmp_repo), stages=[1])

    def test_codeql_stage_without_binary(self, tmp_repo: Path):
        config = AuditConfig(artifact_root=str(tmp_repo / "results"))
        with patch("tee_audit.pipeline.find_codeql", return_value=None):
            with pytest.raises(PipelineError, match="CodeQL"):
                run_pipeline(config, str(tmp_repo), stages=[4])

    def test_missing_prerequisite_raises(self, tmp_path: Path):
        config = AuditConfig(
            artifact_root=str(tmp_path / "results"),
            llm_api_key="fake-key",
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        with pytest.raises(PipelineError, match="Stage 0"):
            run_pipeline(config, str(repo), stages=[1])

    def test_non_critical_failure_continues(self, tmp_repo: Path):
        config = AuditConfig(artifact_root=str(tmp_repo / "results"))
        # Stage 3 (matrix) is non-critical — needs stage 2 output which doesn't exist
        # Should not halt the pipeline
        ctx = run_pipeline(config, str(tmp_repo), stages=[0, 3])
        assert ctx.get_last_completed() >= 0


class TestPipelineResume:
    def test_resume_from_saved_stage(self, tmp_repo: Path, sample_fingerprint):
        config = AuditConfig(artifact_root=str(tmp_repo / "results"))
        results_dir = tmp_repo / "results"
        results_dir.mkdir()

        from tee_audit.audit_context import AuditContext
        from tee_audit.contracts import Stage0Output

        ctx = AuditContext(results_dir=results_dir, repo_path=tmp_repo, repo_commit_hash="")
        ctx.save_stage(0, Stage0Output(fingerprint=sample_fingerprint))

        # Running stage 0 again should work (re-fingerprint)
        ctx2 = run_pipeline(config, str(tmp_repo), stages=[0])
        assert ctx2.get_last_completed() >= 0
