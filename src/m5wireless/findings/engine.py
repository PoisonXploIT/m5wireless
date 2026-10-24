"""Ejecucion del catalogo: recorre las reglas, deduplica y persiste.

Deduplicacion por `(rule_id, activo)`: el id del hallazgo es determinista, de
modo que reevaluar la misma sesion no crea duplicados ni borra el triaje ya
decidido (el store conserva `estado` y `creado` en el upsert).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..models import Active, Finding, make_finding_id
from ..store import AbstractStore
from ..store.base import ObservationRow
from .base import ClientFact, FindingDraft, NetworkFact, RuleContext
from .registry import RULES


def evaluate_session(store: AbstractStore, ctx: RuleContext) -> list[Finding]:
    """Evaluar todas las reglas sobre una sesion y guardar los hallazgos."""
    seen: set[str] = set()
    created: list[Finding] = []
    for rule in RULES:
        for item in rule.evaluate(ctx):
            finding = _to_finding(item, ctx.session_id)
            if finding.id in seen:
                continue
            seen.add(finding.id)
            store.save_finding(finding)
            created.append(store.get_finding(finding.id) or finding)
    return created


def _to_finding(item: FindingDraft, session_id: str) -> Finding:
    activo = Active(
        bssid=item.activo.get("bssid"),
        ssid=item.activo.get("ssid"),
        client_mac=item.activo.get("client_mac"),
        canal=item.activo.get("canal"),
    )
    return Finding(
        id=make_finding_id(item.rule_id, activo),
        session_id=session_id,
        rule_id=item.rule_id,
        rule_version=item.rule_version,
        severidad=item.severidad,
        titulo=item.titulo,
        activo=activo,
        evidencia=item.evidencia,
        recomendacion=item.recomendacion,
    )


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    dt = datetime.fromisoformat(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def network_facts(store: AbstractStore) -> tuple[NetworkFact, ...]:
    """Redes con el numero de veces vistas, calculado del historico.

    La seguridad no existe en los logs de firmware: queda `None`.
    """
    observations = tuple(store.iter_observations())
    seen: dict[str, int] = {}
    for row in observations:
        if row.bssid and row.event_type == "network_seen":
            seen[row.bssid] = seen.get(row.bssid, 0) + 1
    return tuple(
        NetworkFact(
            bssid=n.bssid,
            ssid=n.ssid,
            channel=n.channel,
            rssi=n.rssi,
            security=None,
            wps=False,
            seen_count=max(seen.get(n.bssid, 1), 1),
            first_seen=n.first_seen,
            last_seen=n.last_seen,
        )
        for n in store.get_networks()
    )


def context_from_store(
    store: AbstractStore,
    session_id: str,
    *,
    previous_networks: tuple[NetworkFact, ...] = (),
) -> RuleContext:
    """Contexto a partir de lo que el store sabe.

    La seguridad no existe en los logs de firmware: queda `None` y las reglas
    que dependen de ella (open, WEP, gemelo) no disparan. Es honesto: no se
    inventa lo que el dispositivo no midio.
    """
    observations = tuple(store.iter_observations())
    networks = network_facts(store)
    clients = tuple(
        ClientFact(mac=c.mac, bssid=c.bssid, first_seen=c.first_seen, last_seen=c.last_seen)
        for c in store.get_clients()
    )
    return RuleContext(
        session_id=session_id,
        networks=networks,
        clients=clients,
        observations=observations,
        previous_networks=previous_networks,
    )


def context_from_fixture(path: str | Path) -> RuleContext:
    """Contexto desde un fixture de pruebas (redes + clientes + observaciones)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    networks = tuple(
        NetworkFact(
            bssid=n["bssid"],
            ssid=n.get("ssid"),
            channel=n.get("channel"),
            rssi=n.get("rssi"),
            security=n.get("security"),
            wps=bool(n.get("wps", False)),
            seen_count=int(n.get("seen_count", 1)),
            first_seen=_parse_dt(n.get("first_seen")),
            last_seen=_parse_dt(n.get("last_seen")),
        )
        for n in data["networks"]
    )
    clients = tuple(
        ClientFact(
            mac=c["mac"],
            bssid=c.get("bssid"),
            first_seen=_parse_dt(c.get("first_seen")),
            last_seen=_parse_dt(c.get("last_seen")),
        )
        for c in data.get("clients", [])
    )
    observations = tuple(
        ObservationRow(
            timestamp=_parse_dt(o["timestamp"]) or datetime.now(UTC),
            firmware=o.get("firmware", "marauder"),
            source=o.get("source", "file"),
            event_type=o["event_type"],
            bssid=o.get("bssid"),
            rssi=o.get("rssi"),
            client_mac=o.get("client_mac"),
            raw_line=o.get("raw_line", ""),
        )
        for o in data.get("observations", [])
    )
    return RuleContext(
        session_id=data.get("session_id", "fixture"),
        networks=networks,
        clients=clients,
        observations=observations,
    )
