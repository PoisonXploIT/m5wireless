"""WIFI-HIDDEN (info): SSID oculto pero BSSID visible en el aire.

Logica: SSID vacio o None con un BSSID valido. Es informativa: un SSID oculto
no es un fallo en si mismo, pero cambia el metodo de evaluacion (hay que
identificar la red por BSSID).
"""

from __future__ import annotations

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-HIDDEN"
RULE_VERSION = 1


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    findings = []
    for net in ctx.networks:
        if not net.ssid:
            findings.append(
                draft(
                    RULE_ID,
                    RULE_VERSION,
                    "info",
                    f"Red con SSID oculto (BSSID {net.bssid})",
                    {"bssid": net.bssid},
                    {
                        "canal": net.channel,
                        "seguridad": net.security,
                        "rssi": net.rssi,
                        "primera_vez": net.first_seen.isoformat() if net.first_seen else None,
                        "ultima_vez": net.last_seen.isoformat() if net.last_seen else None,
                    },
                    "Confirmar quien es esa red por BSSID. Un SSID oculto no es un "
                    "hallazgo de seguridad, pero si una red sin identificar en el alcance.",
                )
            )
    return findings
