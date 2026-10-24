"""Motor de hallazgos: catalogo, deduplicacion, estados y fixture demo.

Criterio de aceptacion del paso 2: con el fixture demo salen EXACTAMENTE 5
hallazgos, sin duplicados, y reevaluar no rompe el triaje.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from m5wireless.findings.engine import context_from_fixture, evaluate_session
from m5wireless.findings.registry import CATALOG_VERSION, RULE_IDS, RULES
from m5wireless.store import MemoryStore, SQLiteStore

FIXTURE = Path(__file__).parent / "fixtures" / "assessment" / "redes.json"

EXPECTED_RULES = {
    "WIFI-OPEN",
    "WIFI-WEP",
    "WIFI-EVILTWIN",
    "WIFI-CLIENT-OPEN",
    "WIFI-TRANSIENT",
}


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    result = MemoryStore() if request.param == "memory" else SQLiteStore(tmp_path / "f.db")
    yield result
    result.close()


def test_catalog_has_ten_rules_in_order() -> None:
    assert len(RULES) == 10
    assert RULE_IDS == (
        "WIFI-OPEN",
        "WIFI-WEP",
        "WIFI-WPS",
        "WIFI-HIDDEN",
        "WIFI-EVILTWIN",
        "WIFI-CLIENT-OPEN",
        "WIFI-OUI-INFRA",
        "WIFI-CHANNEL-CONGESTION",
        "WIFI-TRANSIENT",
        "WIFI-CONFIG-DRIFT",
    )
    assert CATALOG_VERSION == 1
    assert all(rule.rule_version >= 1 for rule in RULES)


def test_demo_fixture_yields_exactly_five_findings(store) -> None:
    ctx = context_from_fixture(FIXTURE)
    ctx = replace(ctx, session_id="20261024-demo")
    findings = evaluate_session(store, ctx)
    assert len(findings) == 5
    assert {f.rule_id for f in findings} == EXPECTED_RULES
    assert len({f.id for f in findings}) == 5
    assert all(f.session_id == "20261024-demo" for f in findings)
    assert all(f.estado == "abierto" for f in findings)
    assert all(f.recomendacion for f in findings)
    assert all(f.evidencia for f in findings)


def test_reevaluation_does_not_duplicate_nor_erase_triage(store) -> None:
    ctx = context_from_fixture(FIXTURE)
    ctx = replace(ctx, session_id="20261024-demo")
    first = evaluate_session(store, ctx)
    stored = {f.id: f for f in first}
    target = next(f for f in first if f.rule_id == "WIFI-OPEN")
    store.update_finding(target.id, estado="falso_positivo")

    second = evaluate_session(store, ctx)
    assert len(second) == 5
    assert {f.id for f in second} == set(stored)
    reopened = store.get_finding(target.id)
    assert reopened is not None and reopened.estado == "falso_positivo"
    assert len(store.list_findings()) == 5


def test_findings_filters_work(store) -> None:
    ctx = context_from_fixture(FIXTURE)
    ctx = replace(ctx, session_id="20261024-demo")
    evaluate_session(store, ctx)
    assert len(store.list_findings(severidad="alta")) == 4
    assert len(store.list_findings(severidad="info")) == 1
    assert store.list_findings(session_id="otra") == []
    assert len(store.list_findings(estado="abierto")) == 5
