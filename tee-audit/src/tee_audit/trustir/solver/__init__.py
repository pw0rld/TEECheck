"""TrustIR obligation solver.

Classifies CodeQL obligation-check results against a resolved TrustIR, applying
suppressor and coverage modifiers and the State/Design manual-review cap from
design section 10.
"""

from __future__ import annotations

from tee_audit.trustir.models import FindingStatus
from tee_audit.trustir.solver.obligation_solver import solve
from tee_audit.trustir.solver.status_classifier import classify

__all__ = ["FindingStatus", "classify", "solve"]
