"""WIFI-CLIENT-OPEN (alta): un cliente asociado a una red abierta.

Logica: existe un cliente con `bssid` cuya red tiene seguridad open/none.
Combina dos datos que el pipeline ya tiene (red + asociacion), no infiere nada.
"""

from __future__ import annotations

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-CLIENT-OPEN"
RULE_VERSION = 1


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    open_by_bssid = {n.bssid: n for n in ctx.networks if n.is_open()}
    findings = []
    for client in ctx.clients:
        net = open_by_bssid.get(client.bssid) if client.bssid else None
        if net is None:
            continue
        findings.append(
            draft(
                RULE_ID,
                RULE_VERSION,
                "alta",
                f"Cliente {client.mac} asociado a una red abierta ({net.ssid or '(sin SSID)'})",
                {"bssid": net.bssid, "ssid": net.ssid, "client_mac": client.mac},
                {
                    "canal": net.channel,
                    "seguridad": net.security,
                    "primera_vez": client.first_seen.isoformat() if client.first_seen else None,
                    "ultima_vez": client.last_seen.isoformat() if client.last_seen else None,
                },
                "Ese dispositivo esta traficando sin cifrado. Localizarlo y conectarlo "
                "a una red con WPA2/WPA3, o apagar la red abierta que usa.",
            )
        )
    return findings
