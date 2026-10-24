"""Helpers comunes para los tests de la API web (P0.1: Host y token de sesion).

Desde la P0.1, `/api/*` exige el token de sesion y el middleware rechaza Hosts
que no sean loopback. Estos helpers evitan repetir la cabecera y el `base_url`
en cada test:

- `base_url` apunta a `127.0.0.1` (Host de loopback, admitido).
- `X-M5W-Token` lleva el token fijo de los tests, pasado a `create_app` con
  `session_token=TEST_TOKEN` para no escribir ficheros ni depender del entorno.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

TEST_TOKEN = "m5w-token-de-test"
LOCAL_BASE_URL = "http://127.0.0.1:8000"
AUTH_HEADERS = {"X-M5W-Token": TEST_TOKEN}


def auth_client(app: FastAPI) -> TestClient:
    """TestClient autorizado (Host loopback + cabecera de sesion)."""
    return TestClient(app, base_url=LOCAL_BASE_URL, headers=AUTH_HEADERS)
