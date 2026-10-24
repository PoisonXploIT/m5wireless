"""Seguridad de la superficie web (P0.1, P0.2 y P0.3): `Host`, token, raices y cabeceras.

Cuatro controles, en middleware ASGI puro (no `BaseHTTPMiddleware`: bufferiza
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

3. **Raices de ficheros** (P0.2): el navegador de capturas (`/api/fs/browse`) y el
   importador (`/api/import`) solo trabajan dentro de `M5W_BROWSE_ROOTS` (por defecto
   `data/` y el perfil del usuario). La ruta se resuelve (symlinks incluidos) y se
   compara con `is_relative_to`; una ruta con `..` es 400 y una ruta fuera de la raiz
   es 403.

4. **Cabeceras de respuesta** (P0.3): CSP, `X-Content-Type-Options: nosniff`,
   `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` y `Permissions-Policy`
   en TODAS las respuestas (paginas, assets, API y errores del propio middleware).
   El servidor escucha en 0.0.0.0 por defecto: sin estas cabeceras, una pagina
   externa podria incrustar el dashboard (`frame-ancestors`) o sniffar un HTML
   servido como `text/plain`.

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
BROWSE_ROOTS_ENV = "M5W_BROWSE_ROOTS"

# CSP: el dashboard no carga scripts externos; el CSS se referencia por fichero y
# hay algún `style="..."` inline en las plantillas, de ahí el 'unsafe-inline' de
# style-src. `script-src 'self'` sin inline: el JS vive en /static/js.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# (nombre, valor) de las cabeceras endurecidas. `Permissions-Policy` apaga las
# APIs de navegador que este dashboard no usa (camara, micro, geolocalizacion...).
SECURITY_HEADERS: tuple[tuple[str, bytes], ...] = (
    ("content-security-policy", CSP.encode("latin-1")),
    ("x-content-type-options", b"nosniff"),
    ("referrer-policy", b"no-referrer"),
    ("x-frame-options", b"DENY"),
    (
        "permissions-policy",
        (
            b"camera=(), microphone=(), geolocation=(), interest-topic=(), "
            b"payment=(), usb=(), sensor=(), autoplay=(), storage=()"
        ),
    ),
)

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Rutas que emiten la cookie de sesion (el navegador entra por aqui).
PAGE_PATHS = frozenset({"/", "/network", "/evaluacion"})
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


def resolve_browse_roots(
    data_dir: Path | None = None, extra: Iterable[str] | None = None
) -> tuple[Path, ...]:
    """Raices admitidas por `/api/fs/browse` y `/api/import`.

    Orden: `M5W_BROWSE_ROOTS` (separado por comas) y `create_app(browse_roots=...)`;
    si el operador no declara ninguna, las raices por defecto son el `data_dir`
    (donde viven los pcaps y artefactos propios) y el perfil del usuario. Las rutas
    relativas se resuelven contra el directorio de trabajo. Se descartan las raices
    inexistentes: una raiz que no existe no puede servir de puerta.
    """
    raw = os.environ.get(BROWSE_ROOTS_ENV, "")
    items = [item.strip() for item in list(extra or ()) + raw.split(",") if item.strip()]
    if not items:
        items = [str(data_dir) if data_dir is not None else "data", str(Path.home())]
    roots: list[Path] = []
    for item in items:
        candidate = Path(item)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_dir() and resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


def is_within_roots(path: Path, roots: Iterable[Path]) -> bool:
    """`path` (ya resuelto) esta dentro de alguna raiz; los symlinks cuentan.

    `Path.resolve()` sigue los symlinks: un enlace dentro de `data/` que apunte
    a `C:/Windows` deja de ser `is_relative_to` de la raiz y se rechaza igual
    que la ruta directa.
    """
    return any(path == root or path.is_relative_to(root) for root in roots)


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


class SecurityHeadersMiddleware:
    """Añade las cabeceras de seguridad a TODAS las respuestas HTTP.

    Va el primero (el mas externo), de modo que tambien cubre los 401/403 que
    genera `SecurityMiddleware` y las respuestas streaming del SSE. No duplica:
    si el handler ya puso una de esas cabeceras, se conserva la suya.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: MutableMapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])
                present = {name.lower() for name, _ in headers}
                for name, value in SECURITY_HEADERS:
                    if name not in present:
                        headers.append((name.encode("ascii"), value))
            await send(message)

        await self._app(scope, receive, send_with_headers)


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
