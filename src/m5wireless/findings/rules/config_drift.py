"""WIFI-CONFIG-DRIFT (media): el mismo BSSID cambia de seguridad o de canal
entre sesiones.

Logica: para cada BSSID presente en la sesion actual y en sesiones anteriores,
comparar `security` y `channel`. Un cambio de WPA2 a open, o de canal, es una
señal de que alguien tocó el AP (o de que otro AP se hizo pasar por él).

Necesita historial: sin sesiones anteriores cerradas, la regla no puede decir
nada y no dispara.
"""

from __future__ import annotations

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-CONFIG-DRIFT"
RULE_VERSION = 1


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    if not ctx.previous_networks:
        return []
    previous = {n.bssid: n for n in ctx.previous_networks}
    findings = []
    for net in ctx.networks:
        old = previous.get(net.bssid)
        if old is None:
            continue
        cambios: dict[str, object] = {}
        if (old.security or "") != (net.security or ""):
            cambios["seguridad"] = {"antes": old.security, "ahora": net.security}
        if old.channel != net.channel:
            cambios["canal"] = {"antes": old.channel, "ahora": net.channel}
        if not cambios:
            continue
        findings.append(
            draft(
                RULE_ID,
                RULE_VERSION,
                "media",
                f"Deriva de configuracion en {net.ssid or '(sin SSID)'} ({net.bssid})",
                {"bssid": net.bssid, "ssid": net.ssid},
                {"cambios": cambios},
                "Confirmar con el responsable del AP el cambio. Una seguridad que "
                "baja entre sesiones es el indicador mas claro de un AP alterado "
                "o suplantado.",
            )
        )
    return findings
