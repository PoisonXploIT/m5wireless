"""Modelos de datos normalizados (Fase 1).

Notas de diseño:
- `Network` es mutable y no frozen: el store lo actualiza con cada observacion.
- `Observation` es la base frozen de los eventos; NO lleva campos por defecto
  porque las subclases (`NetworkSeen`, `ClientAssociated`) anaden campos sin
  default, y dataclass no permite un campo sin default despues de uno con
  default en la jerarquia de herencia.
- Todo datetime es aware (UTC). Prohibido `datetime.utcnow` (deprecated).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

SourceType = Literal["serial", "file", "sdcard"]

# Fuente de una sesion de evaluacion. Es mas amplia que `SourceType` (la de los
# eventos), porque una sesion puede abrirse desde Bruce o su WebUI sin que
# exista un parser por linea para ello.
SessionSource = Literal["serial", "file", "sdcard", "bruce", "bruce-web"]
SessionStatus = Literal["abierta", "cerrada"]
Severity = Literal["critica", "alta", "media", "baja", "info"]
FindingStatus = Literal["abierto", "aceptado", "falso_positivo", "corregido"]

SEVERITIES: tuple[str, ...] = ("critica", "alta", "media", "baja", "info")
FINDING_STATUSES: tuple[str, ...] = ("abierto", "aceptado", "falso_positivo", "corregido")
SESSION_STATUSES: tuple[str, ...] = ("abierta", "cerrada")
SESSION_SOURCES: tuple[str, ...] = ("serial", "file", "sdcard", "bruce", "bruce-web")


def utc_now() -> datetime:
    """Instante actual en UTC, aware."""
    return datetime.now(UTC)


_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def normalize_mac(mac: str) -> str:
    """Normaliza una MAC a minúsculas y con separador ':'.

    Acepta 'AA-BB-CC-DD-EE-FF', 'AABB.CC.DD.EE.FF' o 'AABBCCDDEEFF'.
    Lanza ValueError si no es una MAC de 6 octetos hexadecimales.
    """
    cleaned = mac.strip().lower()
    if not _MAC_RE.match(cleaned):
        compact = re.sub(r"[-:. ]", "", cleaned)
        if len(compact) == 12 and all(c in "0123456789abcdef" for c in compact):
            cleaned = ":".join(compact[i : i + 2] for i in range(0, 12, 2))
        else:
            raise ValueError(f"MAC invalida: {mac!r}")
    return cleaned


@dataclass(slots=True, frozen=True)
class Client:
    """Un cliente (dispositivo) observado asociado a una red."""

    mac: str
    bssid: str | None = None  # red a la que esta asociado
    first_seen: datetime = field(default_factory=utc_now)
    last_seen: datetime = field(default_factory=utc_now)


@dataclass(slots=True)
class Network:
    """Estado actual de una red, deduplicada por BSSID."""

    bssid: str
    ssid: str | None
    channel: int | None
    rssi: int | None
    n_clients: int = 0
    clients: set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=utc_now)
    last_seen: datetime = field(default_factory=utc_now)


@dataclass(slots=True, frozen=True)
class Observation:
    """Evento base emitido por un parser tras leer una linea.

    Los eventos concretos son `NetworkSeen`, `ClientAssociated` y
    `StatusEvent` (ciclo de vida del firmware, sin persistencia).
    """

    timestamp: datetime
    firmware: str
    source: SourceType
    raw_line: str


@dataclass(slots=True, frozen=True)
class NetworkSeen(Observation):
    """Una red fue detectada en esta linea."""

    network: Network


@dataclass(slots=True, frozen=True)
class ClientAssociated(Observation):
    """Un cliente fue observado asociado a una red en esta linea."""

    client: Client


@dataclass(slots=True, frozen=True)
class StatusEvent(Observation):
    """Evento de estado/ciclo de vida del firmware (no es una observacion).

    Ejemplo: consola Bruce (`Selected: Sniffer`, `Sniffer started!`, errores
    de montaje SD). NO se persiste en el historico del store ni en Splunk;
    fluye solo a los observadores en vivo (SSE) para visibilidad en el dashboard.
    """

    message: str


# Union discriminada: cada evento sabe que tipo de dato transporta.
ObservationEvent = NetworkSeen | ClientAssociated | StatusEvent


# ---------------------------------------------------------------------------
# Fase A: sesiones y hallazgos (contrato de datos del plan 2026-10-24)
# ---------------------------------------------------------------------------

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _require_aware(dt: datetime, field_name: str) -> None:
    if dt.tzinfo is None:
        raise ValueError(f"{field_name} debe ser un datetime aware (UTC): {dt!r}")


def make_session_id(nombre: str, inicio: datetime) -> str:
    """Slug de sesion: `YYYYMMDD-lugar` a partir del nombre y la fecha.

    'Auditoria WiFi oficina B' + 2026-10-24 -> '20261024-auditoria-wifi-oficina-b'
    """
    slug = _SLUG_RE.sub("-", nombre.strip().lower()).strip("-") or "sesion"
    return f"{inicio:%Y%m%d}-{slug}"


@dataclass(slots=True, frozen=True)
class Artifact:
    """Fichero de evidencia de una sesion, con su hash SHA-256."""

    nombre: str
    ruta: str  # ruta relativa a la carpeta de la sesion
    sha256: str
    bytes: int


@dataclass(slots=True, frozen=True)
class Session:
    """Un run de evaluacion: quien, donde, que alcance legal y que evidencia."""

    id: str
    nombre: str
    cliente: str = ""
    operador: str = ""
    lugar: str = ""
    alcance: str = ""
    dispositivo: str = ""
    source: SessionSource = "file"
    inicio: datetime = field(default_factory=utc_now)
    fin: datetime | None = None
    estado: SessionStatus = "abierta"
    version_app: str = ""
    artifacts: tuple[Artifact, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("la sesion necesita un id")
        if self.estado not in SESSION_STATUSES:
            raise ValueError(f"estado de sesion invalido: {self.estado!r}")
        if self.source not in SESSION_SOURCES:
            raise ValueError(f"source invalido: {self.source!r}")
        _require_aware(self.inicio, "inicio")
        if self.fin is not None:
            _require_aware(self.fin, "fin")
            if self.fin < self.inicio:
                raise ValueError("fin no puede ser anterior a inicio")
        if self.estado == "cerrada" and self.fin is None:
            raise ValueError("una sesion cerrada necesita fecha de cierre (fin)")


@dataclass(slots=True, frozen=True)
class Active:
    """El 'activo' de un hallazgo: a quien apunta (los campos que apliquen).

    Es la clave de deduplicacion: dos hallazgos de la misma regla sobre el mismo
    activo son el mismo hallazgo, aunque cambie la evidencia.
    """

    bssid: str | None = None
    ssid: str | None = None
    client_mac: str | None = None

    def key(self) -> str:
        parts = [v for v in (self.bssid, self.ssid, self.client_mac) if v is not None]
        return "|".join(parts)


@dataclass(slots=True, frozen=True)
class Finding:
    """Hallazgo evaluable, estable entre ejecuciones.

    `id` = rule_id + hash del activo, lo que permite re-evaluar una sesion sin
    duplicar hallazgos ni perder el triaje ya decidido.
    """

    id: str
    session_id: str
    rule_id: str
    rule_version: int
    severidad: Severity
    titulo: str
    activo: Active
    evidencia: dict[str, Any] = field(default_factory=dict)
    recomendacion: str = ""
    estado: FindingStatus = "abierto"
    creado: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.severidad not in SEVERITIES:
            raise ValueError(f"severidad invalida: {self.severidad!r}")
        if self.estado not in FINDING_STATUSES:
            raise ValueError(f"estado invalido: {self.estado!r}")
        if self.rule_version < 1:
            raise ValueError("rule_version debe ser >= 1")
        _require_aware(self.creado, "creado")


def make_finding_id(rule_id: str, activo: Active) -> str:
    """Id determinista de hallazgo: regla + hash del activo."""
    digest = hashlib.sha256(activo.key().encode("utf-8")).hexdigest()[:12]
    return f"{rule_id}-{digest}"
