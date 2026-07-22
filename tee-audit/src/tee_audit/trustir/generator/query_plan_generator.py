"""Query-plan generator: map a TWE + language to the prewritten CodeQL modules.

The TWE -> query-module mapping mirrors ``twe_catalog.yml`` so the runner knows
which ``.ql`` files to execute for a given candidate. Hardcoded for stability and
self-containment (the catalog is small and stable).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# TWE id -> relative query-module path within a language pack.
_TWE_QUERY: dict[str, str] = {
    "TWE-FLOW-001": "flow/HostToEnclaveSecurityDecision.ql",
    "TWE-FLOW-002": "flow/SecretBoundaryExit.ql",
    "TWE-GUARD-001": "guard/ValidityOnlyConsumption.ql",
    "TWE-GUARD-002": "guard/StatusAppraisalIgnored.ql",
    "TWE-GUARD-003": "guard/MissingFreshnessCheck.ql",
    "TWE-BIND-001": "binding/MissingSubjectBinding.ql",
    "TWE-BIND-002": "binding/ReportDataKeyBinding.ql",
    "TWE-BIND-003": "binding/ContextFreeOutputAcceptance.ql",
    "TWE-STATE-001": "state/SealedStateRestoreWithoutVersion.ql",
    "TWE-STATE-002": "state/ReplayableAuthorization.ql",
    "TWE-CONFIG-001": "config/WeakModeReachesAuthority.ql",
    "TWE-CONFIG-002": "config/DevKeyReachesRuntime.ql",
    "TWE-DESIGN-001": "design/BypassAuthorityPath.ql",
    "TWE-DESIGN-002": "design/ProtectedWrongComponent.ql",
    "TWE-LEAK-001": "leakage/SecretToLogOrError.ql",
    "TWE-LEAK-002": "leakage/SecretDependentOutputShape.ql",
}


def query_module_for(twe_id: str) -> str:
    if twe_id not in _TWE_QUERY:
        raise KeyError(f"unknown TWE id: {twe_id}")
    return _TWE_QUERY[twe_id]


def all_twe_ids() -> list[str]:
    return list(_TWE_QUERY)


def build_query_plan(
    candidate_id: str,
    twe_id: str,
    language: str,
    pack_root: str | Path,
) -> dict[str, Any]:
    """Build a query-plan dict for running one TWE against one language pack.

    ``pack_root`` is the language pack dir (e.g. ``.../codeql/trustir/go``).
    """
    module = query_module_for(twe_id)
    root = Path(pack_root)
    return {
        "candidate_id": candidate_id,
        "twe_id": twe_id,
        "language": language,
        "pack_root": str(root),
        "generated_facts": "common/GeneratedTrustFacts.qll",
        "queries": [str(root / module)],
    }


__all__ = ["build_query_plan", "query_module_for", "all_twe_ids"]
