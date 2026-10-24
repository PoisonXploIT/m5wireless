"""Tests de seguridad P0.1: validacion de `Host` y token de sesion.

Cubre la aceptacion del plan (PLAN-MEJORA-2026-10-23, P0.1):

- `Host` ajeno (DNS rebinding) -> 403.
- `/api/*` sin sesion -> 401; con cookie `m5w_ui` o con `X-M5W-Token` -> 200.
- El SSE (`/api/events`) sin sesion -> 401 (se corta antes de abrir el stream).
- La cookie se emite en `/` y `/network` con `HttpOnly` y `SameSite=Strict`.
- El token se lee de `M5W_UI_TOKEN` o de `<data_dir>/.ui_token` (permisos 0600).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from m5wireless.store import MemoryStore
from m5wireless.web import create_app
from m5wireless.web.security import (
    COOKIE_NAME,
    TOKEN_FILENAME,
    resolve_allowed_hosts,
    resolve_session_token,
)

TOKEN = "token-de-test-0123456789"
LOCAL = "http://127.0.0.1:8000"


def _app(**kwargs: Any) -> FastAPI:
    return create_app(MemoryStore(), session_token=TOKEN, **kwargs)


# ---- Host ----


def test_foreign_host_is_403() -> None:
    """Un `Host` ajeno (DNS rebinding) se rechaza antes de tocar el store."""
    client = TestClient(_app(), base_url=LOCAL, headers={"Host": "rebind.example"})
    res = client.get("/api/networks")
    assert res.status_code == 403
    assert "Host no permitido" in res.json()["detail"]


def test_foreign_host_blocks_tambien_las_paginas() -> None:
    client = TestClient(_app(), base_url=LOCAL, headers={"Host": "evil.example"})
    assert client.get("/").status_code == 403
    assert client.get("/network").status_code == 403


def test_loopback_hosts_are_allowed() -> None:
    for host in ("localhost", "127.0.0.1", "127.0.0.1:8000", "[::1]:8000"):
        client = TestClient(_app(), base_url=LOCAL, headers={"Host": host, "X-M5W-Token": TOKEN})
        assert client.get("/api/health").status_code == 200, host


def test_extra_allowed_host_is_admitted() -> None:
    app = _app(allowed_hosts=["viewer.local"])
    client = TestClient(app, base_url=LOCAL, headers={"Host": "viewer.local", "X-M5W-Token": TOKEN})
    assert client.get("/api/health").status_code == 200


def test_allowed_hosts_from_env() -> None:
    hosts = resolve_allowed_hosts(["LAN-PC.local"])
    assert "lan-pc.local" in hosts
    assert "localhost" in hosts


# ---- sesion ----


def test_api_without_session_is_401() -> None:
    client = TestClient(_app(), base_url=LOCAL)
    res = client.get("/api/export/csv")
    assert res.status_code == 401
    assert "X-M5W-Token" in res.json()["detail"]


def test_api_with_cookie_is_200() -> None:
    """El navegador entra por `/`, recibe la cookie y luego la API responde."""
    client = TestClient(_app(), base_url=LOCAL)
    page = client.get("/")
    assert page.status_code == 200
    cookie_header = page.headers["set-cookie"]
    assert COOKIE_NAME in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=Strict" in cookie_header
    assert client.get("/api/networks").status_code == 200


def test_network_page_emits_cookie() -> None:
    client = TestClient(_app(), base_url=LOCAL)
    res = client.get("/network")
    assert res.status_code == 200
    assert COOKIE_NAME in res.headers["set-cookie"]


def test_api_with_header_token_is_200() -> None:
    """Alternativa para clientes de script: cabecera `X-M5W-Token`."""
    client = TestClient(_app(), base_url=LOCAL, headers={"X-M5W-Token": TOKEN})
    assert client.get("/api/health").status_code == 200


def test_api_with_wrong_token_is_401() -> None:
    client = TestClient(_app(), base_url=LOCAL, headers={"X-M5W-Token": "no-es-el-token"})
    assert client.get("/api/health").status_code == 401


def test_sse_without_session_is_401() -> None:
    """El stream SSE sin sesion se corta con 401 antes de abrir la conexion."""
    client = TestClient(_app(), base_url=LOCAL)
    res = client.get("/api/events")
    assert res.status_code == 401
    assert "sesion requerida" in res.json()["detail"]


def test_static_assets_no_require_session() -> None:
    """El CSS/JS son estaticos y no exponen datos: basta con el Host validado."""
    client = TestClient(_app(), base_url=LOCAL)
    assert client.get("/static/css/style.css").status_code == 200


# ---- resolucion del token ----


def test_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("M5W_UI_TOKEN", "token-des-env")
    assert resolve_session_token(None) == "token-des-env"


def test_token_file_is_created_with_0600(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    token = resolve_session_token(data_dir)
    path = data_dir / TOKEN_FILENAME
    assert path.exists()
    assert path.read_text(encoding="utf-8").strip() == token
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if os.name == "nt":
        # Windows no modela los bits POSIX por usuario: `chmod 0600` se traduce
        # en "solo lectura/escritura del propietario" (el modo reportado sigue
        # siendo 0o666). Lo comprobable aqui es que solo el propietario tenga
        # lectura y escritura y no haya bit de ejecución.
        assert mode & 0o700 == 0o600, f"modo inesperado: {oct(mode)}"
    else:
        assert mode == 0o600, f"permisos demasiado abiertos: {oct(mode)}"


def test_token_reused_from_file(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / TOKEN_FILENAME).write_text("token-persistido\n", encoding="utf-8")
    assert resolve_session_token(data_dir) == "token-persistido"


def test_env_wins_over_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / TOKEN_FILENAME).write_text("token-fichero\n", encoding="utf-8")
    monkeypatch.setenv("M5W_UI_TOKEN", "token-env")
    assert resolve_session_token(data_dir) == "token-env"


def test_app_exposes_session_token_for_clients() -> None:
    """`app.state.session_token` permite a los tests/clientes conocer el token."""
    app = create_app(MemoryStore(), data_dir=None)
    token = app.state.session_token
    client = TestClient(app, base_url=LOCAL, headers={"X-M5W-Token": token})
    assert client.get("/api/health").status_code == 200
