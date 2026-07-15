"""TWE-id -> taxonomy family mapping (shared by the solver + generators).

``derive_family`` maps a ``TWE-<TOKEN>-<NUM>`` id to its :class:`TaxonomyFamily`.
It is the only piece of the retired iteration-1/2 LLM extractor that the
iteration-3 pipeline still depends on, so it lives here as a pure function
rather than in the deleted ``extractor`` package.
"""

from __future__ import annotations

from tee_audit.trustir.models import TaxonomyFamily

_FAMILY_BY_TOKEN: dict[str, TaxonomyFamily] = {
    "FLOW": TaxonomyFamily.FLOW,
    "GUARD": TaxonomyFamily.GUARD,
    "BIND": TaxonomyFamily.BINDING,
    "STATE": TaxonomyFamily.STATE,
    "CONFIG": TaxonomyFamily.CONFIG,
    "DESIGN": TaxonomyFamily.DESIGN,
    "LEAK": TaxonomyFamily.LEAKAGE,
}


def derive_family(twe_id: str) -> TaxonomyFamily:
    """Map a ``TWE-<TOKEN>-<NUM>`` id to its :class:`TaxonomyFamily`.

    Unknown tokens fall back to :attr:`TaxonomyFamily.DESIGN`.
    """
    parts = twe_id.split("-")
    token = parts[1].upper() if len(parts) >= 2 else ""
    return _FAMILY_BY_TOKEN.get(token, TaxonomyFamily.DESIGN)


__all__ = ["derive_family"]
