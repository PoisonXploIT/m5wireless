"""Endpoints REST (Fase 3).

El store llega por inyeccion de dependencias (`get_store`), nunca como
instancia global mutable: en produccion lo pone `create_app`, en tests se
sobreescribe con `app.dependency_overrides[get_store]`.

Semantica de filtros:
- `since` / `until`: ventana sobre `last_seen` del estado actual (ISO-8601,
  aware). Para el filtro `firmware` se usa la misma ventana sobre el
  historico.
- `min_rssi`: RSSI >= valor (las redes sin RSSI se excluyen).
"""

from __future__ import annotations

import csv
import io
import threading
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ..models import normalize_mac
from ..store.base import AbstractStore, ObservationRow
from ..worker.collector import Collector
from .security import is_within_roots, resolve_browse_roots
from .schemas import (
    ChannelDistributionResponse,
    ClientRead,
    CollectorStats,
    ConsoleResponse,
    FsBrowseResponse,
    FsEntry,
    HealthResponse,
    HistoryRow,
    ImportRequest,
    ImportResponse,
    NetworkDetail,
    NetworkListResponse,
    StatusResponse,
    client_read,
    console_line,
    history_row,
    network_detail,
    network_read,
)

router = APIRouter()

CSV_COLUMNS = (
    "timestamp",
    "firmware",
    "source",
    "event_type",
    "bssid",
    "rssi",
    "client_mac",
    "raw_line",
)


def get_store(request: Request) -> AbstractStore:
    """Dependencia FastAPI: el store inyectado al crear la app."""
    return cast(AbstractStore, request.app.state.store)


def _normalize_or_422(value: str, label: str) -> str:
    try:
        return normalize_mac(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{label} no valida: {value!r}") from None


# ---- salud ----


@router.get("/api/health", response_model=HealthResponse)
def health(request: Request, store: AbstractStore = Depends(get_store)) -> HealthResponse:
    collector = getattr(request.app.state, "collector", None)
    stats: CollectorStats | None = None
    source: str | None = None
    if isinstance(collector, Collector):
        stats = CollectorStats(**collector.stats())
        source = collector.source_type
    return HealthResponse(
        status="ok",
        store=type(store).__name__,
        source=source,
        collector=stats,
        networks=len(store.get_networks()),
        clients=len(store.get_clients()),
    )


# ---- estado de conexion ----


def _safe_name(raw: object) -> str | None:
    r"""Nombre del fichero o dispositivo, sin la ruta del operador.

    Una fuente puede devolver una ruta absoluta (`C:\Users\...\demo_scan.log` o
    `/mnt/sdcard/logs`). Lo que se expone es el nombre: la ruta revela el usuario,
    el disco y dónde están las capturas (P0.3, no filtrar rutas).
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    return Path(text).name or None


@router.get("/api/status", response_model=StatusResponse)
def status(request: Request) -> StatusResponse:
    """Estado de la fuente (puerto, baudrate, firmware, conectado/reconectando).

    `path` y `display` nunca contienen una ruta absoluta: `display` es la etiqueta
    que enseña la barra superior (`file:demo_scan.log`).
    """
    collector = getattr(request.app.state, "collector", None)
    if not isinstance(collector, Collector):
        return StatusResponse(
            source=None,
            state=None,
            port=None,
            baudrate=None,
            path=None,
            display=None,
            firmware=None,
        )
    info = collector.status()
    baudrate = info.get("baudrate")
    source = collector.source_type
    name = _safe_name(info.get("path") or info.get("root") or info.get("port"))
    display = info.get("display") or (f"{source}:{name}" if source and name else source)
    return StatusResponse(
        source=source,
        state=str(info["state"]),
        port=cast("str | None", info.get("port")),
        baudrate=int(baudrate) if isinstance(baudrate, int) else None,
        path=name,
        display=cast("str | None", display),
        firmware=str(info["firmware"]),
    )


# ---- importador de capturas (pcaps grabados / SD montada en el PC) ----
# El servidor por defecto escucha en 0.0.0.0 (acceso movil por LAN), asi que
# el navegador de ficheros y la importacion quedan restringidos a clientes
# loopback: el filesystem del anfitrion no se expone a la red.
# "testclient" es el host que inyecta TestClient de starlette en los tests.
# Ademas (P0.2), ambas rutas solo trabajan dentro de `M5W_BROWSE_ROOTS`.

_LOCAL_CLIENTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})
_IMPORT_EXTENSIONS = (".pcap", ".cap")
_IMPORT_MAX_BYTES = 64 * 1024 * 1024  # defensa: un pcap gigante tumbaria la memoria
_IMPORT_MAX_FILES = 200  # defensa: una carpeta con miles de pcaps colapsaria el worker
_BROWSE_MAX_ENTRIES = 1000
# Un solo import a la vez: el parseo es CPU-bound y dos a la vez saturan el
# collector y el store. `acquire(blocking=False)` = 409 inmediato si ya hay uno.
_IMPORT_LOCK = threading.Lock()


def _require_local(request: Request) -> None:
    host = request.client.host if request.client is not None else ""
    if host not in _LOCAL_CLIENTS:
        raise HTTPException(status_code=403, detail="solo accesible desde localhost")


def _browse_roots(request: Request) -> tuple[Path, ...]:
    """Raices admitidas, resueltas al construir la app (`create_app`)."""
    roots = getattr(request.app.state, "browse_roots", None)
    if roots is None:
        roots = resolve_browse_roots(getattr(request.app.state, "data_dir", None))
    return tuple(roots)


def _resolve_within_roots(raw: str, roots: tuple[Path, ...]) -> Path:
    """Resuelve `raw` (relativa o absoluta) y la deja dentro de las raices.

    - 400: ruta vacia, con `..` o con caracteres nulos (traversal).
    - 403: la ruta resuelta cae fuera de `M5W_BROWSE_ROOTS`. `resolve()` sigue
      los symlinks, un enlace dentro de `data/` que apunte a `C:/Windows` queda
      rechazado igual que la ruta directa.
    """
    if not raw or not raw.strip():
        raise HTTPException(status_code=400, detail="path vacio")
    if "\x00" in raw:
        raise HTTPException(status_code=400, detail="path invalido")
    candidate = Path(raw)
    if any(part == ".." for part in candidate.parts):
        raise HTTPException(status_code=400, detail="path no puede contener '..'")
    try:
        resolved = candidate.resolve()
    except OSError as exc:  # pragma: no cover - resolve() casi nunca falla
        raise HTTPException(status_code=400, detail=f"path no resoluble: {exc}") from exc
    if not is_within_roots(resolved, roots):
        allowed = ", ".join(str(root) for root in roots) or "ninguna"
        raise HTTPException(
            status_code=403,
            detail=f"ruta fuera de las raices permitidas ({allowed})",
        )
    return resolved


@router.get("/api/fs/browse", response_model=FsBrowseResponse)
def browse_fs(request: Request, path: str | None = Query(None)) -> FsBrowseResponse:
    """Lista un directorio (dirs + pcaps/caps) para el modal importador.

    Sin `path` se listan las raices permitidas (ya no las unidades del disco).
    """
    _require_local(request)
    roots = _browse_roots(request)
    if not path:
        return FsBrowseResponse(
            path=None,
            parent=None,
            entries=[
                FsEntry(name=root.name or str(root), path=str(root), kind="dir")
                for root in roots
            ],
        )
    root = _resolve_within_roots(path, roots)
    if not root.is_dir():
        raise HTTPException(status_code=404, detail=f"directorio no existe: {root}")
    entries: list[FsEntry] = []
    try:
        children = sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        for child in children:
            if child.name.startswith("."):
                continue
            try:
                target = child.resolve()  # symlinks resueltos: si salen, se descartan
            except OSError:
                continue
            if not is_within_roots(target, roots):
                continue  # symlink que apunta fuera de la raiz: no se ofrece
            try:
                if target.is_dir():
                    entries.append(FsEntry(name=child.name, path=str(target), kind="dir"))
                elif child.name.lower().endswith(_IMPORT_EXTENSIONS):
                    entries.append(
                        FsEntry(
                            name=child.name,
                            path=str(target),
                            kind="file",
                            size=target.stat().st_size,
                        )
                    )
            except OSError:
                continue  # entrada esvanecida (tarjeta extraida a mitad de scan)
            if len(entries) >= _BROWSE_MAX_ENTRIES:
                break
    except OSError as exc:
        raise HTTPException(status_code=404, detail=f"no se pudo leer {root}: {exc}") from exc
    # No se puede subir por encima de la raiz: el boton "arriba" desaparece.
    parent = None if any(root == r for r in roots) else str(root.parent)
    return FsBrowseResponse(path=str(root), parent=parent, entries=entries)


@router.post("/api/import", response_model=ImportResponse)
def import_captures(request: Request, body: ImportRequest) -> ImportResponse:
    """Parsea un pcap o una carpeta de pcaps y los vuelca al pipeline en vivo.

    `def` (no `async`): FastAPI lo ejecuta en el threadpool, y el parseo de
    pcaps es CPU-bound. Los eventos entran por `collector.submit_events`, asi
    que llegan a store + SSE igual que los de una fuente binaria.

    Limites (P0.2): solo rutas dentro de `M5W_BROWSE_ROOTS`, maximo 200 ficheros
    por import y un import concurrente (409 si ya va uno).
    """
    _require_local(request)
    collector = getattr(request.app.state, "collector", None)
    if not isinstance(collector, Collector):
        raise HTTPException(
            status_code=409, detail="import requiere el servidor con collector en marcha"
        )
    target = _resolve_within_roots(body.path, _browse_roots(request))
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"ruta no existe: {target}")

    if target.is_dir():
        candidates = [
            path
            for path in sorted(target.rglob("*"))
            if path.is_file()
            and path.name.lower().endswith(_IMPORT_EXTENSIONS)
            and is_within_roots(path.resolve(), _browse_roots(request))
        ]
    elif target.name.lower().endswith(_IMPORT_EXTENSIONS):
        candidates = [target]
    else:
        raise HTTPException(status_code=422, detail="extension no soportada (solo .pcap/.cap)")
    if len(candidates) > _IMPORT_MAX_FILES:
        raise HTTPException(
            status_code=422,
            detail=f"demasiados ficheros ({len(candidates)}); maximo {_IMPORT_MAX_FILES} por import",
        )
    if not candidates:
        return ImportResponse(files=0, events=0, errors=0, messages=[])

    if not _IMPORT_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="ya hay una importacion en curso")

    from ..parser.pcap import PcapParseError, PcapParser

    parser = PcapParser()
    counts = {"files": 0, "events": 0, "errors": 0}
    messages: list[str] = []

    def ingest(path: Path) -> None:
        try:
            if path.stat().st_size > _IMPORT_MAX_BYTES:
                counts["errors"] += 1
                messages.append(f"{path.name}: supera 64 MiB, omitido")
                return
            events = parser.parse(path.read_bytes(), source="sdcard")
        except PcapParseError as exc:
            counts["errors"] += 1
            messages.append(f"{path.name}: {exc}")
            return
        except OSError as exc:
            counts["errors"] += 1
            messages.append(f"{path.name}: no legible ({exc})")
            return
        counts["files"] += 1
        counts["events"] += len(events)
        collector.submit_events(events)

    try:
        for path in candidates:
            ingest(path)
    finally:
        _IMPORT_LOCK.release()
    return ImportResponse(
        files=counts["files"],
        events=counts["events"],
        errors=counts["errors"],
        messages=messages[:20],
    )


# ---- redes ----


@router.get("/api/networks", response_model=NetworkListResponse)
def list_networks(
    store: AbstractStore = Depends(get_store),
    since: datetime | None = Query(None, description="last_seen >= since"),
    until: datetime | None = Query(None, description="last_seen <= until"),
    min_rssi: int | None = Query(None, description="RSSI >= min_rssi"),
    channel: int | None = Query(None),
    ssid: str | None = Query(None),
    firmware: str | None = Query(
        None, description="solo redes observadas por este firmware (historico)"
    ),
) -> NetworkListResponse:
    networks = store.get_networks(since=since, until=until)
    if min_rssi is not None:
        networks = [n for n in networks if n.rssi is not None and n.rssi >= min_rssi]
    if channel is not None:
        networks = [n for n in networks if n.channel == channel]
    if ssid is not None:
        networks = [n for n in networks if n.ssid == ssid]
    if firmware is not None:
        seen_bssids = {
            row.bssid
            for row in store.iter_observations(since=since, until=until)
            if row.firmware == firmware and row.bssid is not None
        }
        networks = [n for n in networks if n.bssid in seen_bssids]
    return NetworkListResponse(networks=[network_read(n) for n in networks])


@router.get("/api/networks/{bssid}", response_model=NetworkDetail)
def get_network(bssid: str, store: AbstractStore = Depends(get_store)) -> NetworkDetail:
    bssid = _normalize_or_422(bssid, "BSSID")
    net = store.get_network(bssid)
    if net is None:
        raise HTTPException(status_code=404, detail=f"red desconocida: {bssid}")
    clients = store.get_clients(associated_to=bssid)
    history = list(store.get_network_history(bssid))
    return network_detail(net, clients, history)


# ---- clientes ----


@router.get("/api/clients", response_model=list[ClientRead])
def list_clients(
    store: AbstractStore = Depends(get_store),
    bssid: str | None = Query(None, description="solo clientes de esta red"),
) -> list[ClientRead]:
    associated_to = _normalize_or_422(bssid, "BSSID") if bssid is not None else None
    return [client_read(c) for c in store.get_clients(associated_to=associated_to)]


@router.get("/api/clients/{mac}", response_model=ClientRead)
def get_client(mac: str, store: AbstractStore = Depends(get_store)) -> ClientRead:
    mac = _normalize_or_422(mac, "MAC")
    client = store.get_client(mac)
    if client is None:
        raise HTTPException(status_code=404, detail=f"cliente desconocido: {mac}")
    return client_read(client)


# ---- export ----


def _iter_csv_chunks(rows: Iterator[ObservationRow], batch_size: int = 500) -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    def flush() -> str:
        chunk = buffer.getvalue()
        buffer.seek(0)
        buffer.truncate()
        return chunk

    writer.writerow(CSV_COLUMNS)
    yield flush()
    pending = 0
    for row in rows:
        writer.writerow(
            (
                row.timestamp.isoformat(),
                row.firmware,
                row.source,
                row.event_type,
                row.bssid or "",
                "" if row.rssi is None else str(row.rssi),
                row.client_mac or "",
                row.raw_line,
            )
        )
        pending += 1
        if pending >= batch_size:
            yield flush()
            pending = 0
    tail = flush()
    if tail:
        yield tail


@router.get("/api/export/csv")
def export_csv(
    store: AbstractStore = Depends(get_store),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
) -> StreamingResponse:
    """Historico completo en CSV, streaming por lotes (no carga todo en memoria)."""
    return StreamingResponse(
        _iter_csv_chunks(store.iter_observations(since=since, until=until)),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="observations.csv"'},
    )


@router.get("/api/export/json", response_model=list[HistoryRow])
def export_json(
    store: AbstractStore = Depends(get_store),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
) -> list[HistoryRow]:
    return [history_row(r) for r in store.iter_observations(since=since, until=until)]


# ---- consola ----


@router.get("/api/console", response_model=ConsoleResponse)
def console(
    store: AbstractStore = Depends(get_store),
    limit: int = Query(100, ge=1, le=1000, description="ultimas N lineas"),
) -> ConsoleResponse:
    """Ultimas N lineas del historico (con `raw_line`), de la mas antigua a la
    mas reciente. Alimenta el panel de consola serial del dashboard."""
    return ConsoleResponse(lines=[console_line(r) for r in store.get_recent_observations(limit)])


# ---- stats ----


@router.get("/api/stats/channels", response_model=ChannelDistributionResponse)
def channel_distribution(
    store: AbstractStore = Depends(get_store),
) -> ChannelDistributionResponse:
    return ChannelDistributionResponse(channels=store.get_channel_distribution())
