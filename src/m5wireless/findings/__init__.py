"""Motor de hallazgos (Fase A, paso 2).

Reglas puras: `evaluate(contexto) -> [FindingDraft]`. No acceden a red, a disco
ni al store; solo a los datos que el pipeline ya tiene. Si un dato no existe,
la regla no se escribe (regla de oro del plan).
"""

from __future__ import annotations

from .base import ClientFact, FindingDraft, NetworkFact, RuleContext
from .engine import evaluate_session
from .registry import CATALOG_VERSION, RULES

__all__ = [
    "CATALOG_VERSION",
    "RULES",
    "ClientFact",
    "FindingDraft",
    "NetworkFact",
    "RuleContext",
    "evaluate_session",
]
