"""WIFI-EVILTWIN (alta): mismo SSID, distinto BSSID y comportamiento distinto.

Logica: dos o mas BSSID comparten SSID (no vacio) y difieren en seguridad o en
canal. Se emite UN hallazgo por SSID, atribuido al BSSID sospechoso: el que
tiene la seguridad mas debil (o, a igualdad, el visto mas tarde).

Umbral: diferencia de seguridad o de canal. Mismo SSID, mismo BSSID... no hay
duplicado. Mismo SSID, distinto BSSID, misma seguridad y mismo canal: se
registra como red duplicada pero no se dispara (puede ser un AP dual real).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..base import FindingDraft, NetworkFact, RuleContext, draft

RULE_ID = "WIFI-EVILTWIN"
RULE_VERSION = 1

# Fuerza decreciente: open < wep < wpa < wpa2 < wpa3.
_STRENGTH = {"open": 0, "none": 0, "wep": 1, "wpa": 2, "wpa2": 3, "wpa3": 4}


def _strength(net: NetworkFact) -> int:
    return _STRENGTH.get((net.security or "").lower(), -1)


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    by_ssid: dict[str, list[NetworkFact]] = defaultdict(list)
    for net in ctx.networks:
        if net.ssid:
            by_ssid[net.ssid].append(net)

    findings = []
    for ssid, nets in sorted(by_ssid.items()):
        if len(nets) < 2:
            continue
        bssids = {n.bssid for n in nets}
        if len(bssids) < 2:
            continue
        if len({n.security for n in nets}) == 1 and len({n.channel for n in nets}) == 1:
            continue
        sospechosa = min(nets, key=lambda n: (_strength(n), n.first_seen or n.last_seen or 0))
        legitima = max(nets, key=lambda n: (_strength(n), n.first_seen or n.last_seen or 0))
        evidencia: dict[str, Any] = {
            "ssid_duplicado": ssid,
            "bssids": sorted(bssids),
            "sospechoso": sospechosa.bssid,
            "variantes": [
                {"bssid": n.bssid, "seguridad": n.security, "canal": n.channel, "rssi": n.rssi}
                for n in sorted(nets, key=lambda n: n.bssid)
            ],
            "referencia": legitima.bssid,
        }
        findings.append(
            draft(
                RULE_ID,
                RULE_VERSION,
                "alta",
                f"Posible gemelo malicioso de '{ssid}' (BSSID {sospechosa.bssid})",
                # El activo se clavea por SSID + el BSSID minimo del grupo: asi la
                # misma pareja de APs da el mismo hallazgo aunque se evalue desde
                # un contexto con datos de seguridad o desde el store puro.
                {"bssid": min(bssids), "ssid": ssid},
                evidencia,
                "Verificar fisicamente el punto de acceso. Un SSID legitimo con otro "
                "BSSID y seguridad distinta es la firma de un AP falso: los clientes "
                "conectados a el salen de la red corporativa.",
            )
        )
    return findings
