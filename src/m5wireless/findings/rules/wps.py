"""WIFI-WPS (media): red con WPS activado.

Logica: el flag `wps` aportado por la fuente. Ningun parser de log de Marauder,
Evil-M5Project, Bruce o Hash Monster entrega WPS hoy, por lo que la regla esta
registrada pero nunca dispara con datos de firmware: se activa solo cuando la
fuente (un inventario importado o un pcap con beacon con el campo WPS) lo da.
Regla de oro: no se infiere lo que el dispositivo no mide.
"""

from __future__ import annotations

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-WPS"
RULE_VERSION = 1


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    findings = []
    for net in ctx.networks:
        if net.wps:
            findings.append(
                draft(
                    RULE_ID,
                    RULE_VERSION,
                    "media",
                    f"Red con WPS activado: {net.ssid or '(sin SSID)'}",
                    {"bssid": net.bssid, "ssid": net.ssid},
                    {"canal": net.channel, "seguridad": net.security, "wps": True},
                    "Desactivar WPS. El PIN de WPS es bruteable y permite recuperar "
                    "la clave sin tocar la red.",
                )
            )
    return findings
