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


# --- U1/U2/U3/U4/U5: responsive, contraste, h1, favicon y foco (m5w 5/7) ---

_CSS = "/static/css/style.css"
_PAGES = ("/", "/network")


def _rule(css: str, selector: str) -> str:
    """Devuelve el cuerpo de la primera regla exacta de `selector`."""
    start = css.index(selector + " {")
    end = css.index("}", start)
    return css[start:end]


def _has_rule(css: str, selector: str, needle: str) -> bool:
    """True si ALGUNA regla de `selector` contiene `needle` (hay dos `.footer`)."""
    return any(needle in body for body in css.split(selector + " {")[1:])


def _contrast(fg: str, bg: str) -> float:
    """Ratio WCAG entre dos colores hex (#rrggbb)."""

    def lum(hex_color: str) -> float:
        channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    la, lb = lum(fg), lum(bg)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def test_grid_children_can_shrink(client: TestClient) -> None:
    """U1: el grid no puede imponer el min-content de la tabla al viewport."""
    css = client.get(_CSS).text
    assert "minmax(0, 1fr)" in css
    assert "min-width: 0" in _rule(css, ".grid > *")
    assert "min-width: 0" in _rule(css, ".table-wrap")
    assert "minmax(0, 1fr)" in _rule(css, ".detail")
    assert "min-width: 0" in _rule(css, ".detail > *")


def test_console_timestamps_meet_contrast(client: TestClient) -> None:
    """U2: el timestamp de consola pasa a --text-dim y supera 4.5:1."""
    css = client.get(_CSS).text
    ts = _rule(css, ".console-line .ts")
    assert "var(--text-dim)" in ts
    root = _rule(css, ":root")
    faint = root.split("--text-faint:")[1].split(";")[0].strip()
    dim = root.split("--text-dim:")[1].split(";")[0].strip()
    console_bg = css.split(".console {")[1].split("background:")[1].split(";")[0].strip()
    assert _contrast(dim, console_bg) >= 4.5
    assert _contrast(faint, "#10151f") >= 4.5  # superficies de panel
    assert _contrast(faint, console_bg) >= 4.5


def test_primary_button_text_meets_contrast(client: TestClient) -> None:
    """U2: el blanco sobre el boton primario debe alcanzar 4.5:1."""
    css = client.get(_CSS).text
    strong = _rule(css, ":root").split("--accent-strong:")[1].split(";")[0].strip()
    assert _contrast("#ffffff", strong) >= 4.5
    assert "var(--accent-strong)" in _rule(css, ".btn-primary")


def test_network_page_has_h1(client: TestClient) -> None:
    """U3: /network abre con un h1 visible; el SSID sigue siendo h2."""
    body = client.get("/network").text
    assert '<h1 class="detail-heading">Detalle de red</h1>' in body
    assert body.count("<h1") == 1
    assert 'id="detail-ssid" class="detail-title"' in body


def test_favicon_is_a_real_file_not_a_data_uri(client: TestClient) -> None:
    """U4: favicon.svg, apple-touch-icon y mask-icon servidos por ruta (CSP-safe)."""
    svg = client.get("/static/favicon.svg")
    assert svg.status_code == 200
    assert "svg" in svg.headers["content-type"]
    assert "<svg" in svg.text

    png = client.get("/static/apple-touch-icon.png")
    assert png.status_code == 200
    assert "image/png" in png.headers["content-type"]
    assert png.content[:8] == b"\x89PNG\r\n\x1a\n"
    assert png.content[12:16] == b"IHDR"
    assert len(png.content) > 1000  # 180x180 real, no un placeholder

    mask = client.get("/static/mask-icon.svg")
    assert mask.status_code == 200

    for path in _PAGES:
        body = client.get(path).text
        assert 'rel="icon" href="/static/favicon.svg"' in body
        assert 'rel="apple-touch-icon" href="/static/apple-touch-icon.png"' in body
        assert 'rel="mask-icon" href="/static/mask-icon.svg"' in body
        assert "data:image/svg+xml" not in body  # incompatible con CSP estricta


def test_skip_link_and_focus_visible(client: TestClient) -> None:
    """U5: enlace de salto a la zona de contenido y anillo de foco global."""
    css = client.get(_CSS).text
    assert ":focus-visible" in css
    assert ".skip-link" in css
    for path in _PAGES:
        body = client.get(path).text
        assert 'class="skip-link"' in body
        target = body.split('class="skip-link" href="#')[1].split('"')[0]
        assert f'id="{target}"' in body


def test_flex_rows_wrap_at_mobile_width(client: TestClient) -> None:
    """U1: botones de consola y pie no desbordan a 390 px."""
    css = client.get(_CSS).text
    assert _has_rule(css, ".panel-actions", "flex-wrap: wrap")
    assert _has_rule(css, ".footer", "flex-wrap: wrap")
    assert _has_rule(css, ".panel-head", "flex-wrap: wrap")


def test_console_has_follow_button_and_search(client: TestClient) -> None:
    """P1.6: la consola tiene boton 'seguir' (auto-scroll) y caja de busqueda."""
    body = client.get("/").text
    assert 'id="console-follow"' in body
    assert 'id="console-search"' in body
    assert 'aria-pressed="true"' in body  # el boton expone su estado a lectores de pantalla
    assert 'id="console-search-count"' in body
    js = client.get("/static/js/dashboard.js").text
    assert 'followBtn.setAttribute("aria-pressed", String(follow))' in js
    # Con 'seguir' activo la consola va al final; con ite parado no se mueve.
    assert "if (follow) consoleEl.scrollTop = consoleEl.scrollHeight" in js
    assert "nearBottom" not in js  # ya no hay auto-scroll condicion: manda el boton


def test_console_search_highlights_through_dom_not_innerhtml(client: TestClient) -> None:
    """P1.6: el resaltado se monta por DOM (createTextNode + <mark>), nunca innerHTML."""
    js = client.get("/static/js/dashboard.js").text
    start = js.index("function setLineText(")
    body = js[start : js.index("function updateSearchCount()", start)]
    assert 'document.createElement("mark")' in body
    assert "innerHTML" not in body
    assert "createTextNode" in body
    assert 'mark.className = "hl"' in body
    # La busqueda se aplica tambien a las lineas que llegan por SSE (rerender + setLineText).
    assert "setLineText(txt, entry.text)" in js
    assert "function rerenderConsole()" in js


def test_console_highlight_meets_contrast(client: TestClient) -> None:
    """El resaltado (ambar #f2c14e con texto #14181f) supera 4.5:1 en cualquier tema."""
    css = client.get(_CSS).text
    rule = _rule(css, "mark.hl")
    fg = rule.split("color:")[1].split(";")[0].strip()
    bg = rule.split("background:")[1].split(";")[0].strip()
    assert _contrast(fg, bg) >= 4.5
    assert _has_rule(css, ".console-search", "font-family: var(--mono)")


def test_filters_persist_in_url_and_localstorage(client: TestClient) -> None:
    """P1.7: los filtros se escriben en la URL (?ssid=, ?ch=) y se leen al recargar."""
    js = client.get("/static/js/dashboard.js").text
    assert "URLSearchParams" in js
    assert "window.history.replaceState" in js
    for key in ("ssid", "ch", "rssi", "clients"):
        assert f'params.set("{key}"' in js
    assert "urlCarriesFilters()" in js
    assert "filtersFromUrl()" in js
    # La URL manda sobre localStorage (vista compartida), y al cambiar un filtro
    # se sincronizan ambas cosas.
    assert "La URL manda" in js
    assert js.count("syncUrlFromFilters()") >= 4  # init, filtros, chips y orden
    assert "FILTERS_STORAGE_KEY" in js
    assert "CONSOLE_STORAGE_KEY" in js  # 'seguir' y la busqueda tambien se recuerdan


def test_url_filters_do_not_touch_the_sse_stream(client: TestClient) -> None:
    """P1.7: los filtros son de cliente; el SSE sigue apuntando a /api/events limpio."""
    js = client.get("/static/js/dashboard.js").text
    assert 'new EventSource("/api/events")' in js
    assert 'EventSource("/api/events?' not in js
    assert 'replaceState({}, "", window.location.pathname' in js


# Nota: el orden/limit de `get_recent_observations` en SQLiteStore esta cubierto
# por test_store.py (parametrizado memoria/SQLite); no se repite aqui porque la
# conexion SQLite no puede cruzar el hilo del portal de TestClient.
