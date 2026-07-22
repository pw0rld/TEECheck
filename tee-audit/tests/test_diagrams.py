"""Tests for Mermaid diagram generation in Stage 6."""

from __future__ import annotations

import pytest

from tee_audit.models.finding import (
    CodeLocation,
    Confidence,
    Finding,
    Severity,
    TrustPathTier,
)
from tee_audit.models.fingerprint import Fingerprint
from tee_audit.models.invariant import Invariant, InvariantFamily
from tee_audit.models.report import DiagramType, MermaidDiagram, Report
from tee_audit.stages.report import (
    _build_architecture_diagram,
    _build_attack_path_diagrams,
    _build_data_flow_diagram,
    _build_trust_path_diagram,
    _render_markdown_report,
    _sanitize_id,
    _sanitize_label,
)


@pytest.fixture
def fp() -> Fingerprint:
    return Fingerprint(
        repo_root="/test/repo",
        top_extensions={".rs": 10},
        codeql_languages=["rust"],
        tee_platforms={"SGX": ["main.rs:10"], "TDX": ["lib.rs:5"]},
        web3_roles={"defi_or_amm": ["swap.rs:1"]},
        trust_artifacts={
            "attestation_artifacts": ["attest.rs"],
            "crypto_operations": ["sig.rs"],
            "identity_artifacts": ["id.rs"],
        },
        build_flags={},
        critical_paths=["src/enclave/", "src/host/"],
    )


@pytest.fixture
def fp_empty() -> Fingerprint:
    return Fingerprint(
        repo_root="/empty",
        top_extensions={},
        codeql_languages=[],
        tee_platforms={},
        web3_roles={},
        trust_artifacts={},
        build_flags={},
        critical_paths=[],
    )


class TestArchitectureDiagram:
    def test_produces_flowchart_td(self, fp: Fingerprint):
        d = _build_architecture_diagram(["TEE Enclave", "Host"], fp)
        assert d.diagram_type == DiagramType.ARCHITECTURE
        assert d.mermaid_code.startswith("flowchart TD")

    def test_key_components_become_nodes(self, fp: Fingerprint):
        d = _build_architecture_diagram(["Enclave", "Host", "Verifier"], fp)
        for comp in ["Enclave", "Host", "Verifier"]:
            assert comp in d.mermaid_code

    def test_tee_platforms_with_styles(self, fp: Fingerprint):
        d = _build_architecture_diagram(["App"], fp)
        assert "SGX" in d.mermaid_code
        assert "TDX" in d.mermaid_code
        assert "fill:#ff6b6b" in d.mermaid_code  # SGX color
        assert "fill:#4ecdc4" in d.mermaid_code  # TDX color

    def test_critical_paths_subgraph(self, fp: Fingerprint):
        d = _build_architecture_diagram(["App"], fp)
        assert "subgraph" in d.mermaid_code
        assert "src/enclave/" in d.mermaid_code

    def test_empty_inputs_produces_no_data(self, fp_empty: Fingerprint):
        d = _build_architecture_diagram([], fp_empty)
        assert "No architecture data available" in d.mermaid_code

    def test_components_chained(self, fp: Fingerprint):
        d = _build_architecture_diagram(["A", "B", "C"], fp)
        assert "-->" in d.mermaid_code


class TestTrustPathDiagram:
    def test_produces_graph_lr(self, fp: Fingerprint):
        inv = Invariant(
            id="INV-01", description="t", trust_path="host -> enclave",
            family=InvariantFamily.FLOW, sources=[], sinks=[],
            guards=[], failure_modes=[], codeql_expressible=True,
        )
        d = _build_trust_path_diagram([inv], fp)
        assert d.diagram_type == DiagramType.TRUST_PATH
        assert d.mermaid_code.startswith("graph LR")

    def test_invariant_chain_edges(self, fp: Fingerprint):
        inv = Invariant(
            id="INV-01", description="t", trust_path="host -> enclave -> verifier",
            family=InvariantFamily.FLOW, sources=[], sinks=[],
            guards=[], failure_modes=[], codeql_expressible=True,
        )
        d = _build_trust_path_diagram([inv], fp)
        assert "INV-01" in d.mermaid_code
        assert "-->" in d.mermaid_code

    def test_core_tier_coloring(self, fp: Fingerprint):
        inv = Invariant(
            id="INV-01", description="t", trust_path="a -> b",
            family=InvariantFamily.FLOW, sources=["src/enclave/"], sinks=[],
            guards=[], failure_modes=[], codeql_expressible=True,
        )
        d = _build_trust_path_diagram([inv], fp)
        assert "fill:#d4edda" in d.mermaid_code  # core color

    def test_empty_invariants(self, fp_empty: Fingerprint):
        d = _build_trust_path_diagram([], fp_empty)
        assert "No invariant data available" in d.mermaid_code


class TestDataFlowDiagram:
    def test_produces_flowchart_lr(self, fp: Fingerprint):
        d = _build_data_flow_diagram({}, fp)
        assert d.diagram_type == DiagramType.DATA_FLOW
        assert d.mermaid_code.startswith("flowchart LR")

    def test_trust_artifact_categories_as_nodes(self, fp: Fingerprint):
        d = _build_data_flow_diagram({}, fp)
        assert "attestation_artifacts" in d.mermaid_code
        assert "crypto_operations" in d.mermaid_code

    def test_dossier_keywords_as_edge_labels(self, fp: Fingerprint):
        d = _build_data_flow_diagram(
            {"section1": "The enclave seals data via attestation"}, fp,
        )
        assert "enclave" in d.mermaid_code or "attestation" in d.mermaid_code

    def test_empty_data_produces_no_data(self, fp_empty: Fingerprint):
        d = _build_data_flow_diagram({}, fp_empty)
        assert "No data flow data available" in d.mermaid_code

    def test_fallback_to_tee_platforms(self):
        fp = Fingerprint(
            repo_root="/t", top_extensions={}, codeql_languages=[],
            tee_platforms={"Nitro": ["a.rs"]}, web3_roles={},
            trust_artifacts={}, build_flags={}, critical_paths=[],
        )
        d = _build_data_flow_diagram({}, fp)
        assert "Nitro" in d.mermaid_code


class TestAttackPathDiagrams:
    def test_one_diagram_per_finding(self):
        f = Finding(
            id="V-01", invariant_id="INV-01", severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED, title="Leak",
            attack_path=["Step 1", "Step 2", "Step 3"],
            code_locations=[], remediation="Fix", trust_path_tier=TrustPathTier.CORE,
        )
        diagrams = _build_attack_path_diagrams([f])
        assert len(diagrams) == 1
        assert diagrams[0].diagram_type == DiagramType.ATTACK_PATH

    def test_skip_finding_with_single_step(self):
        f = Finding(
            id="V-02", invariant_id="INV-01", severity=Severity.LOW,
            confidence=Confidence.WEAK, title="Minor",
            attack_path=["Only step"],
            code_locations=[], remediation="Fix", trust_path_tier=TrustPathTier.PERIPHERAL,
        )
        diagrams = _build_attack_path_diagrams([f])
        assert len(diagrams) == 0

    def test_severity_coloring(self):
        f = Finding(
            id="V-03", invariant_id="INV-01", severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED, title="Critical issue",
            attack_path=["A", "B"],
            code_locations=[], remediation="Fix", trust_path_tier=TrustPathTier.CORE,
        )
        diagrams = _build_attack_path_diagrams([f])
        assert "fill:#ff0000" in diagrams[0].mermaid_code  # Critical red

    def test_code_location_annotations(self):
        f = Finding(
            id="V-04", invariant_id="INV-01", severity=Severity.MEDIUM,
            confidence=Confidence.LIKELY, title="Issue",
            attack_path=["Step A", "Step B"],
            code_locations=[CodeLocation(file="src/main.rs", line=42)],
            remediation="Fix", trust_path_tier=TrustPathTier.ADJACENT,
        )
        diagrams = _build_attack_path_diagrams([f])
        assert "src/main.rs:42" in diagrams[0].mermaid_code

    def test_empty_findings(self):
        diagrams = _build_attack_path_diagrams([])
        assert diagrams == []

    def test_multiple_findings(self):
        findings = [
            Finding(
                id=f"V-{i:02d}", invariant_id="INV-01",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                title=f"Issue {i}", attack_path=["A", "B"],
                code_locations=[], remediation="Fix",
                trust_path_tier=TrustPathTier.CORE,
            )
            for i in range(3)
        ]
        diagrams = _build_attack_path_diagrams(findings)
        assert len(diagrams) == 3


class TestReportDiagramRendering:
    def test_diagrams_in_markdown(self, sample_fingerprint, sample_invariants):
        diag = MermaidDiagram(
            diagram_type=DiagramType.ARCHITECTURE,
            title="Test Diagram",
            mermaid_code="flowchart TD\n  A-->B",
        )
        report = Report(
            project_name="test", fingerprint=sample_fingerprint,
            invariants=sample_invariants, diagrams=[diag],
        )
        md = _render_markdown_report(report)
        assert "## Architecture Diagrams" in md
        assert "```mermaid" in md
        assert "flowchart TD" in md

    def test_no_diagrams_section_when_empty(self, sample_fingerprint):
        report = Report(project_name="test", fingerprint=sample_fingerprint)
        md = _render_markdown_report(report)
        assert "Architecture Diagrams" not in md


class TestSanitization:
    def test_sanitize_id_normal(self):
        assert _sanitize_id("my node") == "my_node"

    def test_sanitize_id_special_chars(self):
        assert _sanitize_id('a"b[c]d') == "a_b_c_d"

    def test_sanitize_id_empty(self):
        assert _sanitize_id("") == "node"

    def test_sanitize_id_only_special(self):
        assert _sanitize_id("---") == "node"

    def test_sanitize_label_quotes(self):
        assert _sanitize_label('say "hello"') == "say 'hello'"

    def test_sanitize_label_brackets(self):
        assert _sanitize_label("arr[0]") == "arr(0)"

    def test_sanitize_label_braces(self):
        assert _sanitize_label("{key}") == "(key)"

    def test_special_chars_in_components(self, fp: Fingerprint):
        d = _build_architecture_diagram(['Enclave "main"', 'Host [app]'], fp)
        assert '"' not in d.mermaid_code.split('flowchart TD')[1] or "'" in d.mermaid_code

    def test_special_chars_in_attack_path(self):
        f = Finding(
            id="V-05", invariant_id="INV-01", severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED, title='Key "leak" via [shared] memory',
            attack_path=['Step "one"', 'Step [two]'],
            code_locations=[], remediation="Fix", trust_path_tier=TrustPathTier.CORE,
        )
        diagrams = _build_attack_path_diagrams([f])
        assert len(diagrams) == 1
        assert "'" in diagrams[0].mermaid_code  # Quotes converted to single quotes
        assert "(" in diagrams[0].mermaid_code  # Brackets converted to parens
