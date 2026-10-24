"""WIFI-CHANNEL-CONGESTION (baja): muchas redes en el mismo canal.

Umbral: CONGESTION_UMBRAL redes (>= 6) vistas en el mismo canal. Es un dato de
rendimiento, no de seguridad: explica degradacion y ruido, no un ataque.
"""

from __future__ import annotations

from collections import defaultdict

from ..base import FindingDraft, NetworkFact, RuleContext, draft

RULE_ID = "WIFI-CHANNEL-CONGESTION"
RULE_VERSION = 1
CONGESTION_UMBRAL = 6


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    by_channel: dict[int, list[NetworkFact]] = defaultdict(list)
    for net in ctx.networks:
        if net.channel is not None:
            by_channel[net.channel].append(net)

    findings = []
    for channel, nets in sorted(by_channel.items()):
        if len(nets) < CONGESTION_UMBRAL:
            continue
        findings.append(
            draft(
                RULE_ID,
                RULE_VERSION,
                "baja",
                f"Canal {channel} saturado: {len(nets)} redes vistas",
                {"canal": str(channel)},
                {
                    "canal": channel,
                    "redes": [{"bssid": n.bssid, "ssid": n.ssid, "rssi": n.rssi} for n in nets],
                    "umbral": CONGESTION_UMBRAL,
                },
                "Reducir el numero de APs en ese canal o repartir canales. Afecta a "
                "la calidad, no a la confidencialidad.",
            )
        )
    return findings
