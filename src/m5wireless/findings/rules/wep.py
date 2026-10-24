"""WIFI-WEP (alta): red con WEP, cifrado roto desde hace una decada.

Logica: `security == 'wep'`.
"""

from __future__ import annotations

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-WEP"
RULE_VERSION = 1


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    findings = []
    for net in ctx.networks:
        if (net.security or "").lower() == "wep":
            findings.append(
                draft(
                    RULE_ID,
                    RULE_VERSION,
                    "alta",
                    f"Red con WEP: {net.ssid or '(sin SSID)'}",
                    {"bssid": net.bssid, "ssid": net.ssid},
                    {
                        "canal": net.channel,
                        "seguridad": net.security,
                        "rssi": net.rssi,
                        "primera_vez": net.first_seen.isoformat() if net.first_seen else None,
                        "ultima_vez": net.last_seen.isoformat() if net.last_seen else None,
                    },
                    "Migrar a WPA2/WPA3. WEP se rompe en minutos con herramientas "
                    "de auditoria y no admite parches.",
                )
            )
    return findings
