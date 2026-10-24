"""WIFI-OUI-INFRA (media): BSSID de fabricante de consumo/virtual en una red que
parece de infraestructura.

Logica (verificable, sin inventar fabricantes):
1. El primer octeto del BSSID tiene el bit 'locally assigned' (0x02). IEEE
   reserva ese bit para MAC generadas por software: un AP de empresa no lo usa,
   un hotspot de movil o un AP virtual si.
2. El SSID encaja con un patrón de infraestructura (operador, fibra, oficina,
   corporate, guest, etc.).

Limitacion documentada: el nombre del OUI no se consulta a la IEEE (no hay red
en el motor). La regla se apoya en el bit de la norma, no en una lista de
marcas, para no afirmar fabricantes que no podemos comprobar.
"""

from __future__ import annotations

import re

from ..base import FindingDraft, RuleContext, draft

RULE_ID = "WIFI-OUI-INFRA"
RULE_VERSION = 1

_LOCALLY_ASSIGNED = 0x02
_INFRA_PATTERN = re.compile(
    r"(fibra|operator|operador|movistar|vodafone|orange|telefonica|corporate|oficina|"
    r"office|guest|internal|infra)",
    re.IGNORECASE,
)


def _is_locally_assigned(bssid: str) -> bool:
    first = bssid.split(":")[0]
    try:
        return int(first, 16) & _LOCALLY_ASSIGNED != 0
    except ValueError:
        return False


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    findings = []
    for net in ctx.networks:
        if not net.bssid or not net.ssid:
            continue
        if not _is_locally_assigned(net.bssid):
            continue
        if not _INFRA_PATTERN.search(net.ssid):
            continue
        findings.append(
            draft(
                RULE_ID,
                RULE_VERSION,
                "media",
                f"Red '{net.ssid}' con BSSID generado por software ({net.bssid})",
                {"bssid": net.bssid, "ssid": net.ssid},
                {
                    "canal": net.channel,
                    "seguridad": net.security,
                    "oui": net.bssid[:8],
                    "motivo": "bit 'locally assigned' del primer octeto del BSSID",
                },
                "Un BSSID con MAC local no proviene de un AP de fabricante: puede ser "
                "un hotspot de movil o un AP virtual montado sobre la red de la "
                "organizacion. Confirmar quien lo sostiene.",
            )
        )
    return findings
