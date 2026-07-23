"""Tests for stage-aware temperature strategy."""

from __future__ import annotations

import inspect

from tee_audit.pipeline import STAGE_TEMPERATURES
from tee_audit.stages.dossier import run_dossier
from tee_audit.stages.invariants import run_invariants
from tee_audit.stages.deep_verify import run_deep_verify, _verify_cluster
from tee_audit.stages.report import run_report
from tee_audit.llm.response_parser import parse_with_retry


class TestStageTemperatures:
    def test_structured_stages_use_zero(self):
        assert STAGE_TEMPERATURES[1] == 0.0
        assert STAGE_TEMPERATURES[2] == 0.0
        assert STAGE_TEMPERATURES[6] == 0.0

    def test_discovery_stage_uses_nonzero(self):
        assert STAGE_TEMPERATURES[5] == 0.5

    def test_only_llm_stages_present(self):
        assert set(STAGE_TEMPERATURES.keys()) == {1, 2, 4, 5, 6, 7}


class TestStageFunctionSignatures:
    """Verify all LLM stage functions accept a temperature parameter."""

    def test_run_dossier_has_temperature(self):
        sig = inspect.signature(run_dossier)
        assert "temperature" in sig.parameters
        assert sig.parameters["temperature"].default == 0.0

    def test_run_invariants_has_temperature(self):
        sig = inspect.signature(run_invariants)
        assert "temperature" in sig.parameters
        assert sig.parameters["temperature"].default == 0.0

    def test_run_deep_verify_has_temperature(self):
        sig = inspect.signature(run_deep_verify)
        assert "temperature" in sig.parameters
        assert sig.parameters["temperature"].default == 0.5

    def test_verify_cluster_has_temperature(self):
        sig = inspect.signature(_verify_cluster)
        assert "temperature" in sig.parameters
        assert sig.parameters["temperature"].default == 0.0

    def test_run_report_has_temperature(self):
        sig = inspect.signature(run_report)
        assert "temperature" in sig.parameters
        assert sig.parameters["temperature"].default == 0.0

    def test_parse_with_retry_has_temperature(self):
        sig = inspect.signature(parse_with_retry)
        assert "temperature" in sig.parameters
        assert sig.parameters["temperature"].default == 0.0
