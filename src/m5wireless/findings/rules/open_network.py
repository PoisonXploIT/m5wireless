"""WIFI-OPEN (alta): red sin autenticacion.

Logica: `security` en {open, none}. No se infiere: si la fuente no aporta la
seguridad, la red no se evalua.
"""

from __future__ import annotations

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-OPEN"
RULE_VERSION = 1


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    findings = []
    for net in ctx.networks:
        if net.is_open():
            findings.append(
                draft(
                    RULE_ID,
                    RULE_VERSION,
                    "alta",
                    f"Red abierta: {net.ssid or '(sin SSID)'}",
                    {"bssid": net.bssid, "ssid": net.ssid},
                    {
                        "canal": net.channel,
                        "seguridad": net.security,
                        "rssi": net.rssi,
                        "primera_vez": net.first_seen.isoformat() if net.first_seen else None,
                        "ultima_vez": net.last_seen.isoformat() if net.last_seen else None,
                    },
                    "Activar WPA2/WPA3 en la red o eliminar la red abierta. "
                    "Una red sin clave cualquiera puede leerse y asociarse a ella.",
                )
            )
    return findings
