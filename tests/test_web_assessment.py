"""Tests de la consola de evaluacion (Paso 5): pagina, assets y accesibilidad basica.

No sustituye a axe (ver `scripts/axe_check.mjs`); aqui se verifica la estructura
que axe necesita para no fallar: landmarks, jerarquia de encabezados, etiquetas
de campos y ausencia de ids duplicados.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI
from fastapi.testclient import TestClient
from web_auth import TEST_TOKEN, auth_client

from m5wireless.store import MemoryStore
from m5wireless.web import create_app

TEMPLATE = Path(__file__).resolve().parents[1] / "src/m5wireless/web/templates/assessment.html"
ASSESSMENT_JS = Path(__file__).resolve().parents[1] / "src/m5wireless/web/static/js/assessment.js"
STYLE_CSS = Path(__file__).resolve().parents[1] / "src/m5wireless/web/static/css/style.css"


@pytest.fixture
def app() -> FastAPI:
    return create_app(MemoryStore(), session_token=TEST_TOKEN)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return auth_client(app)


def test_assessment_page_is_served(client: TestClient) -> None:
    res = client.get("/evaluacion")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    body = res.text
    assert 'id="hallazgos"' in body
    assert 'id="session-form"' in body
    assert 'id="findings-list"' in body
    assert 'id="evidence-table"' in body
    assert 'src="/static/js/assessment.js"' in body


def test_assessment_page_seeds_session_cookie(client: TestClient) -> None:
    res = client.get("/evaluacion")
    assert "m5w_ui" in res.headers.get("set-cookie", "")


def test_dashboard_links_to_assessment(client: TestClient) -> None:
    body = client.get("/").text
    assert 'href="/evaluacion"' in body
    assert 'aria-label="Secciones"' in body


def test_assessment_js_is_served(client: TestClient) -> None:
    res = client.get("/static/js/assessment.js")
    assert res.status_code == 200
    assert "/api/sessions" in res.text


def test_assessment_template_has_no_duplicate_ids() -> None:
    ids = re.findall(r'id="([^"]+)"', TEMPLATE.read_text(encoding="utf-8"))
    duplicates = {item for item in ids if ids.count(item) > 1}
    assert not duplicates, f"ids duplicados: {duplicates}"


def test_assessment_template_labels_every_field() -> None:
    """axe (label): cada input/select necesita etiqueta asociada o aria-label."""
    text = TEMPLATE.read_text(encoding="utf-8")
    labelled = set(re.findall(r'<label for="([^"]+)"', text))
    for match in re.finditer(r"<(?:input|select)\b([^>]*)>", text):
        attrs = match.group(1)
        id_match = re.search(r'id="([^"]+)"', attrs)
        if id_match:
            assert id_match.group(1) in labelled, f"campo sin etiqueta: {id_match.group(1)}"
        else:
            assert "aria-label" in attrs, f"campo sin id ni aria-label: {attrs}"


def test_assessment_template_is_responsive_and_landmarked() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert 'name="viewport"' in text
    assert "<header" in text and "<main" in text and "<footer" in text
    assert 'aria-label="Secciones"' in text


def test_css_defines_assessment_classes() -> None:
    css = STYLE_CSS.read_text(encoding="utf-8")
    for selector in (".nav-link", ".assessment", ".finding", ".triage", ".integrity"):
        assert selector in css, selector
    assert "max-width: 390px" in css


def test_assessment_js_escapes_nothing_but_never_injects_html() -> None:
    """El triaje se construye con textContent: no hay innerHTML en la pagina."""
    js = ASSESSMENT_JS.read_text(encoding="utf-8")
    assert "innerHTML" not in js
    assert "textContent" in js


def test_dashboard_moves_counters_to_collapsible_panel(client: TestClient) -> None:
    """Paso 5: contadores y canales pasan a un panel tecnico plegado."""
    body = client.get("/").text
    assert '<details class="panel tech-panel">' in body
    assert "<summary>" in body
    # El panel esta cerrado por defecto: la tabla de redes es lo primero.
    assert body.index('id="networks-table"') < body.index('class="panel tech-panel"')
    assert 'id="channels-24"' in body
    assert 'id="count-networks"' in body
