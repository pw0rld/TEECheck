"""Stage 3: Analysis Matrix — convert invariants to TSV and Markdown.

Pure Python port of generate_analysis_matrix.sh.
"""

from __future__ import annotations

import logging

from tee_audit.contracts import Stage3Input, Stage3Output
from tee_audit.models.invariant import Invariant

logger = logging.getLogger(__name__)


def _invariant_to_tsv_row(inv: Invariant) -> str:
    """Convert an invariant to a 6-column TSV row."""
    proof = f"{inv.family.value} analysis"
    fp_conditions = "See analysis-families.md"
    return "\t".join([
        inv.id,
        inv.trust_path,
        inv.family.value,
        "CodeQL" if inv.codeql_expressible else "Manual",
        proof,
        fp_conditions,
    ])


def generate_matrix_tsv(invariants: list[Invariant]) -> str:
    """Generate a 6-column TSV from invariants."""
    lines = ["invariant_id\ttrust_path\tanalysis_family\tprimary_tool\trequired_proof\tlikely_fp_conditions"]
    for inv in invariants:
        lines.append(_invariant_to_tsv_row(inv))
    return "\n".join(lines)


def render_markdown_table(tsv: str) -> str:
    """Convert TSV string to a Markdown table."""
    lines = tsv.strip().splitlines()
    if not lines:
        return ""

    header_parts = lines[0].split("\t")
    if len(header_parts) != 6:
        logger.warning("Expected 6 TSV columns, got %d", len(header_parts))

    def escape_pipe(s: str) -> str:
        return s.replace("|", "\\|")

    rows: list[str] = []
    rows.append("| " + " | ".join(escape_pipe(h) for h in header_parts) + " |")
    rows.append("| " + " | ".join("---" for _ in header_parts) + " |")

    for line in lines[1:]:
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            rows.append(f"| INVALID_ROW | Expected 6 columns, got: {escape_pipe(line)} |")
            continue
        rows.append("| " + " | ".join(escape_pipe(p) for p in parts) + " |")

    return "\n".join(rows)


def run_matrix(input_data: Stage3Input) -> Stage3Output:
    """Run Stage 3: Generate analysis family matrix from invariants."""
    logger.info("Stage 3: Generating analysis matrix for %d invariants", len(input_data.invariants))

    tsv = generate_matrix_tsv(input_data.invariants)
    markdown = render_markdown_table(tsv)

    # Prepend title
    markdown = "# Analysis family matrix\n\n" + markdown

    logger.info("Stage 3 complete: %d-row matrix generated", len(input_data.invariants))
    return Stage3Output(matrix_markdown=markdown, matrix_tsv=tsv)
