"""Registro ordenado de reglas y version del catalogo.

El orden importa: es el que aparece en el informe. `CATALOG_VERSION` sube cuando
se añade, elimina o cambia una regla, y queda registrada en el informe para que
un cliente sepa con que catalogo se evaluo su sesion.
"""

from __future__ import annotations

from .base import Rule
from .rules import (
    channel_congestion,
    client_open,
    config_drift,
    evil_twin,
    hidden_ssid,
    open_network,
    oui_infra,
    transient,
    wep,
    wps,
)

CATALOG_VERSION = 1

RULES: tuple[Rule, ...] = (
    Rule(open_network.RULE_ID, open_network.RULE_VERSION, open_network.evaluate),
    Rule(wep.RULE_ID, wep.RULE_VERSION, wep.evaluate),
    Rule(wps.RULE_ID, wps.RULE_VERSION, wps.evaluate),
    Rule(hidden_ssid.RULE_ID, hidden_ssid.RULE_VERSION, hidden_ssid.evaluate),
    Rule(evil_twin.RULE_ID, evil_twin.RULE_VERSION, evil_twin.evaluate),
    Rule(client_open.RULE_ID, client_open.RULE_VERSION, client_open.evaluate),
    Rule(oui_infra.RULE_ID, oui_infra.RULE_VERSION, oui_infra.evaluate),
    Rule(channel_congestion.RULE_ID, channel_congestion.RULE_VERSION, channel_congestion.evaluate),
    Rule(transient.RULE_ID, transient.RULE_VERSION, transient.evaluate),
    Rule(config_drift.RULE_ID, config_drift.RULE_VERSION, config_drift.evaluate),
)

RULE_IDS: tuple[str, ...] = tuple(r.rule_id for r in RULES)
