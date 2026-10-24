"""Webhooks de evaluacion (Paso 6): `session.closed` y `finding.created`.

Seguridad (misma filosofia que el resto del proyecto):

- `http://` solo se admite para loopback (127.0.0.1 / localhost): un webhook
  en claro solo tiene sentido en la misma maquina o en un proxy local.
- `https://` se admite; si `M5W_WEBHOOK_ALLOWED_HOSTS` declara una allowlist,
  el host debe estar en ella. Sin allowlist, cualquier host https vale.
- La URL del webhook **nunca se hardcodea**: sale de `--webhook`,
  `M5W_WEBHOOK_URL` o `M5W_DISCORD_WEBHOOK`. Si aparece una clave en un fichero,
  se sustituye por `${NOMBRE}`.

Formatos:

- `generic`: JSON `{"event": ..., "session": ..., "findings": [...]}`.
- `discord`: `{"content": ..., "embeds": [...]}` con un embed por severidad,
  respetando los limites de Discord (2000 chars de content, 4000 de
  descripcion, 25 campos por embed).

El envio es sincrono y tolerante: un fallo no rompe el cierre de la sesion,
devuelve `{"ok": False, ...}` y se registra como aviso.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from ..models import Finding, Session

logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
EVENTS = ("session.closed", "finding.created")

SEVERITY_COLORS = {
    "alta": 0xE5534B,
    "media": 0xD9A021,
    "baja": 0x4C8DFF,
    "info": 0x8B98AB,
}


class WebhookConfigError(ValueError):
    """Configuracion de webhook invalida (esquema, host o URL vacia)."""


@dataclass(frozen=True)
class WebhookConfig:
    """Configuracion de un destino de webhook."""

    url: str
    kind: str = "generic"  # generic | discord
    events: tuple[str, ...] = EVENTS
    verify: bool = True
    timeout: float = 10.0
    retries: int = 2
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.kind not in ("generic", "discord"):
            raise WebhookConfigError(f"kind de webhook no soportado: {self.kind!r}")
        validate_url(self.url, self.allowed_hosts)


def validate_url(url: str, allowed_hosts: frozenset[str] = frozenset()) -> str:
    """Comprobar esquema y host antes de enviar nada."""
    if not url or not url.strip():
        raise WebhookConfigError("la URL del webhook esta vacia")
    parsed = httpx.URL(url.strip())
    if parsed.scheme == "http":
        if parsed.host not in LOOPBACK_HOSTS:
            raise WebhookConfigError(
                f"webhook http no permitido fuera de loopback: {parsed.host} (usa https)"
            )
    elif parsed.scheme == "https":
        if allowed_hosts and parsed.host not in allowed_hosts:
            raise WebhookConfigError(
                f"host {parsed.host} no esta en la allowlist de webhooks "
                f"(M5W_WEBHOOK_ALLOWED_HOSTS)"
            )
    else:
        raise WebhookConfigError(f"esquema de webhook no soportado: {parsed.scheme}")
    return url.strip()


def detect_kind(url: str) -> str:
    """Discord si la URL tiene pinta de webhook de Discord; si no, generic."""
    parsed = httpx.URL(url)
    if parsed.host.endswith("discord.com") and parsed.path.startswith("/api/webhooks/"):
        return "discord"
    return "generic"


def resolve_webhook_config(
    url: str | None = None,
    kind: str | None = None,
    allowed_hosts: frozenset[str] = frozenset(),
) -> WebhookConfig | None:
    """Resolver la configuracion desde CLI, entorno o nada (devuelve None)."""
    import os

    target = url or os.environ.get("M5W_WEBHOOK_URL") or os.environ.get("M5W_DISCORD_WEBHOOK")
    if not target:
        return None
    env_hosts = os.environ.get("M5W_WEBHOOK_ALLOWED_HOSTS", "")
    hosts = set(allowed_hosts) | {host.strip() for host in env_hosts.split(",") if host.strip()}
    return WebhookConfig(
        url=target,
        kind=kind or os.environ.get("M5W_WEBHOOK_KIND") or detect_kind(target),
        allowed_hosts=frozenset(hosts),
    )


def session_payload(session: Session) -> dict[str, Any]:
    return {
        "id": session.id,
        "nombre": session.nombre,
        "cliente": session.cliente,
        "operador": session.operador,
        "lugar": session.lugar,
        "alcance": session.alcance,
        "dispositivo": session.dispositivo,
        "source": session.source,
        "inicio": session.inicio.isoformat(),
        "fin": session.fin.isoformat() if session.fin else None,
        "estado": session.estado,
    }


def finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "severidad": finding.severidad,
        "titulo": finding.titulo,
        "activo": {
            key: value for key, value in asdict(finding.activo).items() if value is not None
        },
        "evidencia": finding.evidencia,
        "recomendacion": finding.recomendacion,
        "estado": finding.estado,
        "creado": finding.creado.isoformat(),
    }


def build_generic_payload(
    event: str, session: Session, findings: list[Finding], catalog_version: int = 1
) -> dict[str, Any]:
    return {
        "event": event,
        "source": "m5wireless",
        "catalog_version": catalog_version,
        "session": session_payload(session),
        "findings": [finding_payload(finding) for finding in findings],
        "counts": {
            "total": len(findings),
            "alta": sum(1 for finding in findings if finding.severidad == "alta"),
            "media": sum(1 for finding in findings if finding.severidad == "media"),
            "baja": sum(1 for finding in findings if finding.severidad == "baja"),
            "info": sum(1 for finding in findings if finding.severidad == "info"),
        },
    }


def build_discord_payload(
    event: str, session: Session, findings: list[Finding], catalog_version: int = 1
) -> dict[str, Any]:
    """Payload de Discord: un embed por hallazgo, ordenado por severidad."""
    order = {"alta": 0, "media": 1, "baja": 2, "info": 3}
    ordered = sorted(
        findings, key=lambda finding: (order.get(finding.severidad, 9), finding.rule_id)
    )
    summary = (
        f"Sesion `{session.id}` cerrada: {len(ordered)} hallazgo(s) "
        f"[{session.cliente or 'sin cliente'} / {session.operador or 'sin operador'}]"
    )
    content = summary[:2000]
    embeds: list[dict[str, Any]] = []
    for finding in ordered[:25]:
        fields = [
            {
                "name": "Regla",
                "value": f"{finding.rule_id} v{finding.rule_version}",
                "inline": True,
            },
            {"name": "Severidad", "value": finding.severidad, "inline": True},
            {"name": "Estado", "value": finding.estado, "inline": True},
        ]
        activo_map = asdict(finding.activo)
        activo = ", ".join(f"{key}: {value}" for key, value in activo_map.items() if value)
        if activo:
            fields.append({"name": "Activo", "value": activo[:1000], "inline": False})
        if finding.recomendacion:
            fields.append(
                {"name": "Recomendacion", "value": finding.recomendacion[:1000], "inline": False}
            )
        embeds.append(
            {
                "title": finding.titulo[:250],
                "description": json.dumps(finding.evidencia, ensure_ascii=False)[:4000],
                "color": SEVERITY_COLORS.get(finding.severidad, 0x8B98AB),
                "fields": fields,
            }
        )
    return {
        "content": content,
        "embeds": embeds,
        "event": event,
        "catalog_version": catalog_version,
    }


def build_payload(
    config: WebhookConfig,
    event: str,
    session: Session,
    findings: list[Finding],
    catalog_version: int = 1,
) -> dict[str, Any]:
    if config.kind == "discord":
        return build_discord_payload(event, session, findings, catalog_version)
    return build_generic_payload(event, session, findings, catalog_version)


class WebhookNotifier:
    """Enviar eventos de evaluacion a un webhook. Sincrono y tolerante a fallos."""

    def __init__(self, config: WebhookConfig, client: httpx.Client | None = None) -> None:
        self.config = config
        self._client = client or httpx.Client(verify=config.verify, timeout=config.timeout)
        self.sent: list[dict[str, Any]] = []

    def send(self, event: str, session: Session, findings: list[Finding]) -> dict[str, Any]:
        if event not in self.config.events:
            return {"ok": False, "detail": f"evento no habilitado: {event}"}
        payload = build_payload(self.config, event, session, findings)
        last: dict[str, Any] = {"ok": False, "detail": "sin intentos"}
        for attempt in range(self.config.retries + 1):
            try:
                response = self._client.post(
                    self.config.url,
                    json=payload,
                    headers={"Content-Type": "application/json", "User-Agent": "m5wireless"},
                )
                last = {
                    "ok": response.status_code < 300,
                    "status": response.status_code,
                    "detail": response.text[:200],
                    "attempt": attempt,
                }
                if last["ok"]:
                    break
            except httpx.HTTPError as exc:
                last = {"ok": False, "detail": str(exc), "attempt": attempt}
            if attempt < self.config.retries:
                time.sleep(min(2.0, 0.5 * (attempt + 1)))
        if not last["ok"]:
            logger.warning("webhook %s fallo: %s", self.config.url, last["detail"])
        self.sent.append({"event": event, "result": last})
        return last

    def notify_session_closed(
        self, session: Session, findings: list[Finding], catalog_version: int = 1
    ) -> dict[str, Any]:
        return self.send("session.closed", session, findings)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
