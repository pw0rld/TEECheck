"""Secondary comparison: reconcile existing tee-audit reports with TrustIR findings (US-011).

The existing tee-audit reports are prose Markdown. This module parses their
structured markers (``### [SEVERITY] IV-INV-NN: title [Family]``, confidence
lines, Positive Guards, Dismissed Findings) and reconciles them, by taxonomy
family, with the TrustIR finding statuses to show how ambiguous/low-confidence
findings refine into ``confirmed``/``delegated``/``out_of_scope`` etc.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tee_audit.trustir.models import TaxonomyFamily

_SEVERITY = r"CRITICAL|HIGH|MEDIUM|LOW|INFO"
# e.g. "### [HIGH] IV-INV-06: title [Configuration Integrity] (incorrect_usage) (CWE-1188)"
_FINDING_RE = re.compile(
    rf"^###\s*\[({_SEVERITY})\]\s+([A-Z]+-[A-Z]+-\d+):\s*(.+?)\s*\[([^\]]+)\]"
)
_CONFIDENCE_RE = re.compile(r"\*\*Confidence\*\*:\s*(\w+)")
_POSITIVE_RE = re.compile(r"^###\s+(PG[-A-Z0-9-]+):\s*(.+)")
_DISMISSED_RE = re.compile(r"^###\s+~~(.+?)~~")
_DISMISSED_SEV_RE = re.compile(r"\*\*Original Severity\*\*:\s*(\w+)", re.IGNORECASE)

_FAMILY_KEYWORDS = [
    ("Flow", TaxonomyFamily.FLOW),
    ("Leakage", TaxonomyFamily.LEAKAGE),
    ("Metadata", TaxonomyFamily.LEAKAGE),
    ("Binding", TaxonomyFamily.BINDING),
    ("State", TaxonomyFamily.STATE),
    ("Verification", TaxonomyFamily.GUARD),
    ("Guard", TaxonomyFamily.GUARD),
    ("Config", TaxonomyFamily.CONFIG),
    ("Design", TaxonomyFamily.DESIGN),
]


def map_family(label: str) -> TaxonomyFamily | None:
    for kw, fam in _FAMILY_KEYWORDS:
        if kw.lower() in label.lower():
            return fam
    return None


def parse_existing_report(path: str | Path) -> dict[str, Any]:
    """Parse a tee-audit Markdown report into structured findings."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    active: list[dict[str, Any]] = []
    positives: list[dict[str, str]] = []
    dismissed: list[dict[str, Any]] = []

    section = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("## "):
            heading = stripped.lower()
            if "positive guard" in heading:
                section = "positives"
            elif "dismiss" in heading:
                section = "dismissed"
            elif "tee usage problem" in heading or "finding" in heading:
                section = "findings"
            else:
                section = ""
            i += 1
            continue

        if section == "findings":
            m = _FINDING_RE.match(stripped)
            if m:
                sev, fid, title, fam_label = m.groups()
                # Look ahead (up to 8 lines) for a confidence marker.
                confidence = None
                for j in range(i + 1, min(i + 9, len(lines))):
                    cm = _CONFIDENCE_RE.search(lines[j])
                    if cm:
                        confidence = cm.group(1)
                        break
                active.append(
                    {
                        "id": fid,
                        "severity": sev,
                        "title": title.strip(),
                        "family_label": fam_label.strip(),
                        "family": (map_family(fam_label) or TaxonomyFamily.FLOW).value,
                        "confidence": confidence,
                    }
                )
        elif section == "positives":
            pm = _POSITIVE_RE.match(stripped)
            if pm:
                positives.append({"id": pm.group(1), "title": pm.group(2).strip()})
        elif section == "dismissed":
            dm = _DISMISSED_RE.match(stripped)
            if dm:
                sev = None
                for j in range(i + 1, min(i + 6, len(lines))):
                    sm = _DISMISSED_SEV_RE.search(lines[j])
                    if sm:
                        sev = sm.group(1)
                        break
                dismissed.append({"id": dm.group(1).strip(), "severity": sev})
        i += 1

    return {
        "active_findings": active,
        "positive_guards": positives,
        "dismissed": dismissed,
        "counts": {
            "active": len(active),
            "positive_guards": len(positives),
            "dismissed": len(dismissed),
        },
    }


def _family_status_index(trustir_findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    idx: dict[str, list[str]] = {}
    for f in trustir_findings:
        fam = (f.get("family") or "").strip()
        idx.setdefault(fam, []).append(f.get("status", "unresolved"))
    return idx


def build_comparison(
    project: str,
    trustir_findings: list[dict[str, Any]],
    existing: dict[str, Any],
) -> dict[str, Any]:
    """Reconcile existing findings with TrustIR statuses, by family."""
    fam_idx = _family_status_index(trustir_findings)

    rows: list[dict[str, Any]] = []
    for ef in existing.get("active_findings", []):
        fam = ef["family"]
        statuses = fam_idx.get(fam, [])
        if not statuses:
            trustir_status = "not_reexamined"
            refinement = "TrustIR did not produce a finding in this family for this run"
        elif any(s == "confirmed" for s in statuses):
            trustir_status = "confirmed"
            refinement = "Corroborated — TrustIR confirms a violation in this family"
        elif any(s == "violated_candidate" for s in statuses):
            trustir_status = "violated_candidate"
            refinement = "Partially corroborated — candidate violation, needs full-layer analysis"
        elif any(s in {"delegated", "guarded_elsewhere"} for s in statuses):
            trustir_status = "delegated/guarded"
            refinement = "TrustIR refines to a non-issue (enforced elsewhere)"
        elif any(s == "out_of_scope" for s in statuses):
            trustir_status = "out_of_scope"
            refinement = "TrustIR classifies as out of TEE scope"
        else:
            trustir_status = "unresolved"
            refinement = "TrustIR could not resolve enough facts"
        rows.append(
            {
                "existing_finding": ef["id"],
                "existing_severity": ef["severity"],
                "existing_confidence": ef.get("confidence"),
                "family": fam,
                "trustir_status": trustir_status,
                "refinement": refinement,
            }
        )

    trustir_status_counts: dict[str, int] = {}
    for f in trustir_findings:
        trustir_status_counts[f.get("status", "unresolved")] = (
            trustir_status_counts.get(f.get("status", "unresolved"), 0) + 1
        )

    return {
        "project": project,
        "existing_counts": existing.get("counts", {}),
        "trustir_status_counts": trustir_status_counts,
        "delta_rows": rows,
    }


def write_comparison_md(comparison: dict[str, Any], path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    p = comparison["project"]
    ec = comparison["existing_counts"]
    tc = comparison["trustir_status_counts"]
    lines = [
        f"# TrustIR vs tee-audit Comparison — {p}",
        "",
        "## Counts",
        "",
        "| Source | Metric | Value |",
        "| --- | --- | ---: |",
        f"| tee-audit | active findings | {ec.get('active', 0)} |",
        f"| tee-audit | positive guards | {ec.get('positive_guards', 0)} |",
        f"| tee-audit | dismissed (FP) | {ec.get('dismissed', 0)} |",
    ]
    for status, n in sorted(tc.items()):
        lines.append(f"| TrustIR | `{status}` | {n} |")
    lines += ["", "## Per-finding reconciliation", "",
              "| Existing finding | Severity | Confidence | Family | TrustIR status | Refinement |",
              "| --- | --- | --- | --- | --- | --- |"]
    for r in comparison["delta_rows"]:
        lines.append(
            f"| {r['existing_finding']} | {r['existing_severity']} | "
            f"{r['existing_confidence'] or '—'} | {r['family']} | "
            f"`{r['trustir_status']}` | {r['refinement']} |"
        )
    if not comparison["delta_rows"]:
        lines.append("| (no existing active findings to reconcile) | | | | | |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


__all__ = ["parse_existing_report", "map_family", "build_comparison", "write_comparison_md"]
