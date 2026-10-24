"""Tipos del motor de hallazgos: entrada (contexto) y salida (borrador).

`NetworkFact` es la proyeccion que las reglas necesitan. No es el `Network` del
store: el store no sabe de seguridad ni de WPS porque ningun parser de log la
entrega. Un hallazgo solo puede evaluarse sobre datos que existen, asi que la
seguridad se rellena cuando la fuente la aporta (pcap, importacion de un
inventario, fixture de pruebas) y queda `None` en el resto de casos.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..models import Severity
from ..store.base import ObservationRow

OPEN_SECURITY = frozenset({"open", "none"})
KNOWN_SECURITY = frozenset({"open", "none", "wep", "wpa", "wpa2", "wpa3"})


@dataclass(frozen=True)
class NetworkFact:
    """Una red, tal y como la ven las reglas."""

    bssid: str
    ssid: str | None
    channel: int | None
    rssi: int | None
    security: str | None = None
    wps: bool = False
    seen_count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def is_open(self) -> bool:
        return (self.security or "").lower() in OPEN_SECURITY


@dataclass(frozen=True)
class ClientFact:
    """Un cliente observado y la red a la que esta asociado."""

    mac: str
    bssid: str | None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass(frozen=True)
class RuleContext:
    """Todo lo que una regla puede mirar. Nada mas."""

    session_id: str
    networks: tuple[NetworkFact, ...] = ()
    clients: tuple[ClientFact, ...] = ()
    observations: tuple[ObservationRow, ...] = ()
    # Redes de sesiones anteriores (cerradas), para reglas de comparacion.
    previous_networks: tuple[NetworkFact, ...] = ()


@dataclass(frozen=True)
class FindingDraft:
    """Hallazgo antes de asignarle id, sesion y estado de triaje."""

    rule_id: str
    rule_version: int
    severidad: Severity
    titulo: str
    activo: dict[str, str | None]
    evidencia: dict[str, Any] = field(default_factory=dict)
    recomendacion: str = ""


@dataclass(frozen=True)
class Rule:
    """Una regla registrada: identificador, version y funcion pura."""

    rule_id: str
    rule_version: int
    evaluate: Callable[[RuleContext], list[FindingDraft]]


def draft(
    rule_id: str,
    rule_version: int,
    severidad: Severity,
    titulo: str,
    activo: dict[str, str | None],
    evidencia: dict[str, Any],
    recomendacion: str,
) -> FindingDraft:
    return FindingDraft(
        rule_id=rule_id,
        rule_version=rule_version,
        severidad=severidad,
        titulo=titulo,
        activo=activo,
        evidencia=evidencia,
        recomendacion=recomendacion,
    )
