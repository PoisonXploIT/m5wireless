"""Seguridad de la superficie web (P0.1): `Host` validado y token de sesion.

Dos controles, en un middleware ASGI puro (no `BaseHTTPMiddleware`: bufferiza
el cuerpo y rompería el streaming de `/api/events`):

1. **`Host`**: solo loopback (`localhost`, `127.0.0.1`, `::1`) o los hosts que
   declare el operador (`M5W_ALLOWED_HOSTS` / `create_app(allowed_hosts=...)`).
   Cierra el DNS rebinding: una pagina externa puede resolver su dominio a
   127.0.0.1 y hablar al puerto local conservando su propio `Host`, que hasta
   aqui no se miraba (solo se comparaba la IP del cliente).
2. **Sesion**: `/api/*` (incluido `/api/events`) exige el token de sesion, en
   la cookie `m5w_ui` (`HttpOnly`, `SameSite=Strict`, emitida en `/` y
   `/network`) o en la cabecera `X-M5W-Token` para clientes de script. El token
   sale de `M5W_UI_TOKEN` o de `<data_dir>/.ui_token` (creado con 0600); sin
   `data_dir` se genera uno efimero en memoria.

El HTML de las paginas no exige token: es solo la plantilla del dashboard. Los
datos, que son lo sensible, estan detras de `/api/`.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
from collections.abc import Iterable, MutableMapping
from pathlib import Path
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

COOKIE_NAME = "m5w_ui"
TOKEN_HEADER = "X-M5W-Token"
TOKEN_FILENAME = ".ui_token"

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Rutas que emiten la cookie de sesion (el navegador entra por aqui).
PAGE_PATHS = frozenset({"/", "/network"})
# Cualquier `/api` o `/api/...` necesita sesion (incluido /api/events, el SSE).
API_PREFIX = "/api"


def normalize_host(raw: str) -> str:
    """`Host` sin puerto y en minusculas: `Localhost:8000` -> `localhost`."""
    host = raw.strip().lower()
    if not host:
        return ""
    if host.startswith("["):  # literal IPv6: [::1]:8000
        end = host.find("]")
        host = host[1:end] if end != -1 else host[1:]
    else:
        host = host.split(":", 1)[0]
    return host


def resolve_allowed_hosts(extra: Iterable[str] | None = None) -> frozenset[str]:
    """Loopback + hosts extra (argumento o `M5W_ALLOWED_HOSTS`, separados por comas)."""
    hosts = set(LOOPBACK_HOSTS)
    env = os.environ.get("M5W_ALLOWED_HOSTS", "")
    for item in list(extra or ()) + env.split(","):
        host = normalize_host(item)
        if host:
            hosts.add(host)
    return frozenset(hosts)


def resolve_session_token(data_dir: Path | None) -> str:
    """Token de sesion: `M5W_UI_TOKEN`, luego `<data_dir>/.ui_token`, y si no, generado.

    Al generar, se persiste en el `data_dir` con permisos 0600 para que la
    sesion sobreviva entre arranques y no se imprima en la consola.
    """
    from_env = os.environ.get("M5W_UI_TOKEN")
    if from_env:
        return from_env
    if data_dir is None:
        return secrets.token_hex(32)
    path = data_dir / TOKEN_FILENAME
    try:
        existing = path.read_text(encoding="utf-8").strip()
    except OSError:
        existing = ""
    if existing:
        return existing
    token = secrets.token_hex(32)
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        # os.open con modo 0600: el fichero nace ya restringido (evita la ventana
        # entre `write` y `chmod`).
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{token}\n")
        os.chmod(path, 0o600)  # Windows no modela los bits POSIX: refuerza la intencion
    except OSError:
        pass  # sin data_dir escribible: token efimero, la sesion caduca al parar
    return token


def _parse_headers(scope: Scope) -> tuple[str, dict[str, str], str]:
    """Devuelve (host, cookies, token de cabecera) desde los headers ASGI."""
    host = ""
    cookies: dict[str, str] = {}
    header_token = ""
    for name, value in scope["headers"]:
        low = name.lower()
        if low == b"host" and not host:
            host = normalize_host(value.decode("latin-1"))
        elif low == b"cookie":
            for part in value.decode("latin-1").split(";"):
                key, _, val = part.strip().partition("=")
                if key:
                    cookies[key] = val
        elif low == TOKEN_HEADER.lower().encode("ascii") and not header_token:
            header_token = value.decode("latin-1")
    return host, cookies, header_token


async def _json_error(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class SecurityMiddleware:
    """Valida el `Host`, exige el token en `/api/*` y siembra la cookie en las paginas."""

    def __init__(self, app: ASGIApp, *, session_token: str, allowed_hosts: frozenset[str]) -> None:
        self._app = app
        self._token = session_token
        self._allowed_hosts = allowed_hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        host, cookies, header_token = _parse_headers(scope)
        if host and host not in self._allowed_hosts:
            await _json_error(send, 403, f"Host no permitido: {host}")
            return

        path = str(scope.get("path", ""))
        if path == API_PREFIX or path.startswith(f"{API_PREFIX}/"):
            candidate = cookies.get(COOKIE_NAME, "") or header_token
            if not hmac.compare_digest(candidate, self._token):
                await _json_error(
                    send,
                    401,
                    "sesion requerida: visita / o envia la cabecera X-M5W-Token",
                )
                return

        if path not in PAGE_PATHS:
            await self._app(scope, receive, send)
            return

        cookie = f"{COOKIE_NAME}={self._token}; Path=/; HttpOnly; SameSite=Strict"

        async def send_with_cookie(message: MutableMapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((b"set-cookie", cookie.encode("latin-1")))
            await send(message)

        await self._app(scope, receive, send_with_cookie)
