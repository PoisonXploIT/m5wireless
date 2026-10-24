"""Tests del frontend (Fase 4): / sirve el dashboard y los assets estaticos.

El comportamiento SSE en vivo ya esta cubierto en test_sse.py; aqui solo se
verifica la capa HTML/estatico y el endpoint de consola que alimenta el
panel de lineas raw.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI
from fastapi.testclient import TestClient
from web_auth import TEST_TOKEN, auth_client

from m5wireless.store import MemoryStore
from m5wireless.web import create_app


@pytest.fixture
def app(seeded_store: MemoryStore) -> FastAPI:
    return create_app(seeded_store, session_token=TEST_TOKEN)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return auth_client(app)


def test_root_serves_dashboard_html(client: TestClient) -> None:
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    body = res.text
    # Estructura minima del dashboard.
    assert 'id="networks-table"' in body
    assert 'id="console"' in body
    assert 'href="/static/css/style.css"' in body
    assert 'src="/static/js/dashboard.js"' in body


def test_root_serves_dashboard_with_empty_store() -> None:
    app = create_app(MemoryStore(), session_token=TEST_TOKEN)
    with auth_client(app) as client:
        res = client.get("/")
    assert res.status_code == 200
    assert 'id="networks-table"' in res.text


def test_static_assets_served(client: TestClient) -> None:
    css = client.get("/static/css/style.css")
    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]
    assert "rssi-good" in css.text

    js = client.get("/static/js/dashboard.js")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    assert "/api/events" in js.text


def test_console_endpoint_returns_recent_raw_lines(client: TestClient) -> None:
    res = client.get("/api/console", params={"limit": 3})
    assert res.status_code == 200
    lines = res.json()["lines"]
    # Las 3 ultimas en orden de insercion (la semilla no es cronologica);
    # cada linea trae raw_line.
    assert [line["raw_line"] for line in lines] == ["de line", "c1 line", "c2 line"]
    assert all(line["timestamp"] and line["event_type"] for line in lines)


# --- S5: XSS en los chips de filtro (m5w 4/7) ---

_JS_STATIC = ("/static/js/dashboard.js", "/static/js/network.js")


def test_filter_chips_build_text_with_text_content(client: TestClient) -> None:
    """renderChips ya no usa innerHTML: el texto del usuario se pinta literal."""
    js = client.get("/static/js/dashboard.js").text
    start = js.index("function renderChips()")
    end = js.index("chipsEl.appendChild(chip)", start) + len("chipsEl.appendChild(chip)")
    body = js[start:end]
    assert "innerHTML" not in body
    assert 'createElement("b")' in body  # el negrita se crea por DOM, no por cadena
    assert body.count("textContent") >= 2


def test_static_js_has_no_inner_html_with_interpolation(client: TestClient) -> None:
    """Los innerHTML que quedan son literales estaticos (iconos SVG), sin datos del usuario."""
    for path in _JS_STATIC:
        js = client.get(path).text
        for line_no, line in enumerate(js.splitlines(), start=1):
            if "innerHTML" in line and "${" in line:
                pytest.fail(f"{path}:{line_no} innerHTML con interpolacion: {line.strip()}")


def test_console_endpoint_limit_bounds(client: TestClient) -> None:
    # Limit mayor que el total devuelve todo el historico (6 en la semilla).
    res = client.get("/api/console", params={"limit": 100})
    assert len(res.json()["lines"]) == 6
    # limit < 1 -> 422 (Query ge=1).
    assert client.get("/api/console", params={"limit": 0}).status_code == 422


# Nota: el orden/limit de `get_recent_observations` en SQLiteStore esta cubierto
# por test_store.py (parametrizado memoria/SQLite); no se repite aqui porque la
# conexion SQLite no puede cruzar el hilo del portal de TestClient.
