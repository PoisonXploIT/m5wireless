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
    previous_sessions: int = 0
    gaps: tuple[dict[str, str], ...] = ()

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


def _data_gaps(
    networks: tuple[NetworkFact, ...],
    fired_rule_ids: set[str],
    previous_sessions: int,
) -> tuple[dict[str, str], ...]:
    """Reglas del catalogo que NO se pudieron evaluar por falta de dato.

    El informe debe decirlo: la ausencia de un hallazgo no es un aprobado. Solo
    se listan las reglas que no dispararon y cuya entrada no existia en la sesion.
    """
    gaps: list[dict[str, str]] = []
    if not any(net.security for net in networks):
        for rule_id in ("WIFI-OPEN", "WIFI-WEP", "WIFI-CLIENT-OPEN"):
            if rule_id not in fired_rule_ids:
                gaps.append(
                    {
                        "rule_id": rule_id,
                        "motivo": "la fuente de datos no aporta el campo de seguridad de la red",
                    }
                )
    if "WIFI-WPS" not in fired_rule_ids and not any(net.wps for net in networks):
        gaps.append(
            {
                "rule_id": "WIFI-WPS",
                "motivo": "ningun parser de firmware entrega el flag WPS; no se puede afirmar "
                "que no exista",
            }
        )
    if "WIFI-CONFIG-DRIFT" not in fired_rule_ids and previous_sessions == 0:
        gaps.append(
            {
                "rule_id": "WIFI-CONFIG-DRIFT",
                "motivo": "no hay sesiones cerradas anteriores con las que comparar",
            }
        )
    return tuple(gaps)


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

    previous_sessions = sum(
        1 for other in store.list_sessions() if other.id != session_id and other.estado == "cerrada"
    )
    return ReportContext(
        session=session,
        findings=findings,
        networks=networks,
        clients=clients,
        observations=tuple(store.iter_observations()),
        catalog_version=CATALOG_VERSION,
        generated_at=generated_at or utc_now(),
        previous_sessions=previous_sessions,
        gaps=_data_gaps(networks, {f.rule_id for f in findings}, previous_sessions),
    )
