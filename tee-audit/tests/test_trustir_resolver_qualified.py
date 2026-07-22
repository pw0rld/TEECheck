"""Qualified-name resolution: LLMs emit package-qualified Go names (``pkg.Func``)
that must resolve to the bare identifier in the symbol index."""
from __future__ import annotations

from pathlib import Path

from tee_audit.trustir.annotations import AnnotationKind, TrustAnnotation, TrustAnnotationSet
from tee_audit.trustir.resolver import resolve_set


def test_package_qualified_go_name_resolves(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "v.go").write_text("package pkg\n\nfunc NewVerifier() int { return 1 }\n", encoding="utf-8")
    ann = TrustAnnotationSet(repo="r", annotations=[
        TrustAnnotation(id="v", kind=AnnotationKind.VERIFIER, role="measurement",
                        name="pkg.NewVerifier", file="pkg/v.go", line=3),
    ])
    out = resolve_set(ann, repo)
    a = out["resolved"].annotations[0]
    assert a.resolution_status.value in ("accepted", "repaired"), a.resolution_note
    assert a.resolved_file.endswith("v.go")
    assert out["stats"]["rejected"] == 0
