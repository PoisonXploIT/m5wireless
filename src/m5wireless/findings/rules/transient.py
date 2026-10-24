"""WIFI-TRANSIENT (info): red vista una sola vez y que no vuelve.

Logica: `seen_count == 1` y primera/ultima vez iguales. Sirve para separar el
ruido del inventario real: una red efimera no se puede auditar (no se puede
visitar ni cerrar), pero hay que dejar constancia de que aparecio.
"""

from __future__ import annotations

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-TRANSIENT"
RULE_VERSION = 1


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    observations_per_bssid: dict[str, int] = {}
    for row in ctx.observations:
        if row.bssid and row.event_type == "network_seen":
            observations_per_bssid[row.bssid] = observations_per_bssid.get(row.bssid, 0) + 1

    findings = []
    for net in ctx.networks:
        if net.seen_count != 1:
            continue
        if (
            net.first_seen is not None
            and net.last_seen is not None
            and net.first_seen != net.last_seen
        ):
            continue
        veces = observations_per_bssid.get(net.bssid, 1)
        if veces > 1:
            continue
        findings.append(
            draft(
                RULE_ID,
                RULE_VERSION,
                "info",
                f"Red efimera: {net.ssid or '(sin SSID)'} vista una sola vez",
                {"bssid": net.bssid, "ssid": net.ssid},
                {
                    "canal": net.channel,
                    "seguridad": net.security,
                    "rssi": net.rssi,
                    "veces_vista": veces,
                    "primera_vez": net.first_seen.isoformat() if net.first_seen else None,
                    "ultima_vez": net.last_seen.isoformat() if net.last_seen else None,
                },
                "No se puede evaluar una red que aparece una vez. Si vuelve a "
                "aparecer en otra sesion, se reevalua automaticamente.",
            )
        )
    return findings
