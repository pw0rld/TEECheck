"""Suppressor fact aggregation.

Each suppressor is a free-form dict produced by the binder / LLM with at least a
``kind`` string. This module maps the various kind spellings onto the three
boolean suppressor flags consumed by :func:`status_classifier.classify`.
"""

from __future__ import annotations


# kind aliases -> suppressor flag
_TEST_ONLY_KINDS = {"test_only", "test_only_path", "mock", "example_only"}
_DELEGATED_KINDS = {"delegated", "checked_inside_verifier"}
_GUARDED_ELSEWHERE_KINDS = {
    "guarded_elsewhere",
    "registry_enforces",
    "contract_enforces",
}


def evaluate(suppressors_list: list[dict]) -> dict:
    """Reduce a list of suppressor dicts to the three boolean flags.

    Unknown kinds are ignored. Returns ``{"test_only", "delegated",
    "guarded_elsewhere"}``.
    """
    result = {
        "test_only": False,
        "delegated": False,
        "guarded_elsewhere": False,
    }
    for suppressor in suppressors_list:
        kind = suppressor.get("kind")
        if not isinstance(kind, str):
            continue
        if kind in _TEST_ONLY_KINDS:
            result["test_only"] = True
        elif kind in _DELEGATED_KINDS:
            result["delegated"] = True
        elif kind in _GUARDED_ELSEWHERE_KINDS:
            result["guarded_elsewhere"] = True
    return result


__all__ = ["evaluate"]
