"""Tests for report syntax validation."""

from tee_audit.stages.report import _validate_report_syntax


def test_validate_report_syntax_table_alignment():
    """Validator fixes misaligned table columns."""
    report = (
        "# Test Report\n\n"
        "## Trust Boundary Analysis\n\n"
        "| Actor | Component | Context | Boundary Type |\n"
        "| --- | --- | --- | --- |\n"
        "| Host | Enclave | Input | ECALL |\n"
        "| Untrusted | Handler | Missing | Short\n"  # missing trailing pipe
    )
    result = _validate_report_syntax(report)
    lines = result.split("\n")
    # The short row should be padded
    for line in lines:
        if "Short" in line:
            assert line.endswith("|")


def test_validate_report_syntax_mermaid_label_truncation():
    """Validator truncates Mermaid node labels > 80 chars."""
    long_label = "A" * 90
    report = (
        "```mermaid\n"
        f'flowchart TD\n    A["{long_label}"] --> B["ok"]\n'
        "```\n"
    )
    result = _validate_report_syntax(report)
    # Should truncate the long label
    assert "..." in result
    # Count chars in the label (between quotes after A[)
    import re
    labels = re.findall(r'\["([^"]+)"\]', result)
    for label in labels:
        assert len(label) <= 83  # 80 + "..."


def test_validate_report_syntax_passes_clean_report():
    """Clean report passes through unchanged."""
    report = (
        "# Test Report\n\n"
        "| A | B | C |\n"
        "| --- | --- | --- |\n"
        "| 1 | 2 | 3 |\n"
    )
    result = _validate_report_syntax(report)
    assert result == report


def test_validate_report_syntax_preserves_mermaid_block():
    """Mermaid blocks are preserved as code blocks."""
    report = (
        "```mermaid\n"
        "flowchart TD\n"
        '    A["Short"] --> B["Label"]\n'
        "```\n"
    )
    result = _validate_report_syntax(report)
    assert "```mermaid" in result
    assert "```" in result
