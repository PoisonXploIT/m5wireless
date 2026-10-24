"""Contexto del informe: sesion + hallazgos + anexo tecnico, ya ordenado.

El orden de los hallazgos es determinista (severidad, luego rule_id, luego id),
de modo que dos ejecuciones sobre los mismos datos producen el mismo informe.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..findings.base import ClientFact, NetworkFact
from ..findings.engine import network_facts
from ..models import Finding, Session, utc_now
from ..store import AbstractStore
from ..store.base import ObservationRow

SEVERITY_ORDER: tuple[str, ...] = ("critica", "alta", "media", "baja", "info")
SEVERITY_LABEL: dict[str, str] = {
    "critica": "Critica",
    "alta": "Alta",
    "media": "Media",
    "baja": "Baja",
    "info": "Informativo",
}


def _severity_key(finding: Finding) -> tuple[int, str, str]:
    return (SEVERITY_ORDER.index(finding.severidad), finding.rule_id, finding.id)


@dataclass(frozen=True)
class ReportContext:
    session: Session
    findings: tuple[Finding, ...]
    networks: tuple[NetworkFact, ...]
    clients: tuple[ClientFact, ...]
    observations: tuple[ObservationRow, ...]
    catalog_version: int
    generated_at: datetime

    def ordered_findings(self) -> tuple[Finding, ...]:
        """Hallazgos en orden determinista, independientemente del orden de entrada."""
        return tuple(sorted(self.findings, key=_severity_key))

    def by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {sev: [] for sev in SEVERITY_ORDER}
        for finding in self.ordered_findings():
            grouped[finding.severidad].append(finding)
        return grouped

    def open_findings(self) -> list[Finding]:
        return [f for f in self.ordered_findings() if f.estado == "abierto"]


def build_context(
    store: AbstractStore,
    session_id: str,
    *,
    generated_at: datetime | None = None,
) -> ReportContext:
    """Cargar sesion, hallazgos y anexo tecnico desde el store."""
    session = store.get_session(session_id)
    if session is None:
        raise KeyError(f"sesion no encontrada: {session_id}")
    findings = tuple(sorted(store.list_findings(session_id=session_id), key=_severity_key))
    networks = network_facts(store)
    clients = tuple(
        ClientFact(mac=c.mac, bssid=c.bssid, first_seen=c.first_seen, last_seen=c.last_seen)
        for c in store.get_clients()
    )
    from ..findings.registry import CATALOG_VERSION

    return ReportContext(
        session=session,
        findings=findings,
        networks=networks,
        clients=clients,
        observations=tuple(store.iter_observations()),
        catalog_version=CATALOG_VERSION,
        generated_at=generated_at or utc_now(),
    )
