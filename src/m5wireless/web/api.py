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
import json
import threading
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from ..findings.engine import context_from_store, evaluate_session
from ..findings.registry import CATALOG_VERSION
from ..models import (
    ObservationEvent,
    Session,
    normalize_mac,
)
from ..report import build_context, verify_evidence, write_evidence, write_report
from ..report.writer import FORMATS
from ..session import close_session, get_live_session
from ..store.base import AbstractStore, ObservationRow
from ..worker.collector import Collector
from .schemas import (
    ChannelDistributionResponse,
    ClientRead,
    CollectorStats,
    ConsoleResponse,
    ExportCountResponse,
    FindingListResponse,
    FindingRead,
    FindingUpdate,
    FsBrowseResponse,
    FsEntry,
    HealthResponse,
    HistoryRow,
    ImportCancelResponse,
    ImportFileResult,
    ImportRequest,
    ImportResponse,
    NetworkDetail,
    NetworkListResponse,
    ReportResponse,
    SessionCreate,
    SessionListResponse,
    SessionRead,
    SessionUpdate,
    StatusResponse,
    client_read,
    console_line,
    finding_read,
    history_row,
    network_detail,
    network_read,
    session_read,
)
from .security import is_within_roots, resolve_browse_roots

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
# Cancelacion (X1): la UI llama a /api/import/cancel y el bucle se para ENTRE
# ficheros (no a mitad de un pcap: un pcap se parsea entero o no se toca).
# `_IMPORT_RUNNING` se pone al arrancar el bucle y se limpia en el `finally`,
# incluido si el navegador cierra la conexion a mitad del stream.
_IMPORT_CANCEL = threading.Event()
_IMPORT_RUNNING = False


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
                FsEntry(name=root.name or str(root), path=str(root), kind="dir") for root in roots
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


def _import_candidates(target: Path, roots: tuple[Path, ...]) -> list[Path]:
    """Ficheros a importar: un pcap suelto o la carpeta (recursiva)."""
    if target.is_dir():
        return [
            path
            for path in sorted(target.rglob("*"))
            if path.is_file()
            and path.name.lower().endswith(_IMPORT_EXTENSIONS)
            and is_within_roots(path.resolve(), roots)
        ]
    if target.name.lower().endswith(_IMPORT_EXTENSIONS):
        return [target]
    raise HTTPException(status_code=422, detail="extension no soportada (solo .pcap/.cap)")


def _run_import(
    candidates: list[Path], collector: Collector, summary: ImportResponse
) -> Iterator[dict[str, object]]:
    """Generador de progreso: una linea por fichero y la ultima, el resumen.

    Es un generador `def` (no async): FastAPI lo iterar en el threadpool, y
    si el navegador cierra la conexion el generador se cierra y el `finally`
    suelta la lock. La cancelacion se comprueba ENTRE ficheros: un pcap se
    parsea entero, no se interrumpe a mitad.
    """
    global _IMPORT_RUNNING
    from ..parser.pcap import PcapParseError, PcapParser

    parser = PcapParser()
    results: list[ImportFileResult] = []
    cancelled = False
    total = len(candidates)
    yield {"type": "start", "total": total}
    try:
        for index, path in enumerate(candidates, start=1):
            if _IMPORT_CANCEL.is_set():
                cancelled = True
                break
            error: str | None = None
            events: list[ObservationEvent] = []
            try:
                if path.stat().st_size > _IMPORT_MAX_BYTES:
                    error = "supera 64 MiB, omitido"
                else:
                    events = parser.parse(path.read_bytes(), source="sdcard")
            except PcapParseError as exc:
                error = str(exc)
            except OSError as exc:
                error = f"no legible ({exc})"
            if error is None:
                summary.files += 1
                summary.events += len(events)
                collector.submit_events(events)
            else:
                summary.errors += 1
                summary.messages.append(f"{path.name}: {error}")
            result = ImportFileResult(
                name=path.name, ok=error is None, events=len(events), error=error
            )
            results.append(result)
            yield {
                "type": "file",
                "index": index,
                "total": total,
                "name": path.name,
                "ok": result.ok,
                "events": result.events,
                "error": error,
            }
    finally:
        _IMPORT_RUNNING = False
        _IMPORT_LOCK.release()
        _IMPORT_CANCEL.clear()
    yield {
        "type": "done",
        "files": summary.files,
        "events": summary.events,
        "errors": summary.errors,
        "messages": summary.messages[:20],
        "results": [r.model_dump() for r in results],
        "cancelled": cancelled,
        "skipped": total - len(results),
    }
    summary.results = results
    summary.cancelled = cancelled
    summary.skipped = total - len(results)


@router.post("/api/import", response_model=None)
def import_captures(request: Request, body: ImportRequest) -> ImportResponse | StreamingResponse:
    """Parsea un pcap o una carpeta de pcaps y los vuelca al pipeline en vivo.

    `def` (no `async`): FastAPI lo ejecuta en el threadpool, y el parseo de
    pcaps es CPU-bound. Los eventos entran por `collector.submit_events`, asi
    que llegan a store + SSE igual que los de una fuente binaria.

    Con `stream: true` responde NDJSON (X1): `{"type":"start",...}`, una linea
    por fichero y la ultima `{"type":"done",...}` con el resumen por archivo.
    Sin `stream`, el resumen JSON de siempre. El progreso se puede cancelar con
    `POST /api/import/cancel`.

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

    candidates = _import_candidates(target, _browse_roots(request))
    if len(candidates) > _IMPORT_MAX_FILES:
        raise HTTPException(
            status_code=422,
            detail=f"demasiados ficheros ({len(candidates)}); maximo {_IMPORT_MAX_FILES} por import",
        )
    if not candidates:
        return ImportResponse(files=0, events=0, errors=0, messages=[], results=[])

    if not _IMPORT_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="ya hay una importacion en curso")
    global _IMPORT_RUNNING
    _IMPORT_RUNNING = True
    _IMPORT_CANCEL.clear()
    summary = ImportResponse(files=0, events=0, errors=0, messages=[], results=[])
    stream = _run_import(candidates, collector, summary)
    if body.stream:
        return StreamingResponse(
            (json.dumps(item, ensure_ascii=False) + "\n" for item in stream),
            media_type="application/x-ndjson",
        )
    for _ in stream:
        pass
    return summary


@router.post("/api/import/cancel", response_model=ImportCancelResponse)
def cancel_import(request: Request) -> ImportCancelResponse:
    """Pide la parada del import en curso (X1: cancelacion del modal)."""
    _require_local(request)
    active = _IMPORT_RUNNING
    if active:
        _IMPORT_CANCEL.set()
    return ImportCancelResponse(active=active, requested=active)


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


def _filtered_rows(
    store: AbstractStore,
    *,
    since: datetime | None,
    until: datetime | None,
    ssid: str | None = None,
    channel: int | None = None,
    min_rssi: int | None = None,
    firmware: str | None = None,
) -> Iterator[ObservationRow]:
    r"""Observaciones del alcance "filtrado" del dialogo de export (X2).

    Son los filtros que maneja la tabla del dashboard (texto de SSID, canal,
    RSSI minimo, firmware) aplicados server-side, para que el CSV/JSON exportado
    coincida con lo que se ve en pantalla. Sin filtros = alcance "todo".
    """
    rows = store.iter_observations(since=since, until=until)
    if ssid is None and channel is None and min_rssi is None and firmware is None:
        yield from rows
        return
    nets = {net.bssid: net for net in store.get_networks(since=since, until=until) if net.bssid}
    needle = ssid.lower() if ssid else None
    for row in rows:
        if firmware is not None and row.firmware != firmware:
            continue
        if min_rssi is not None and (row.rssi is None or row.rssi < min_rssi):
            continue
        if needle is not None or channel is not None:
            net = nets.get(row.bssid) if row.bssid else None
            if net is None:
                continue
            if needle is not None and needle not in (net.ssid or "").lower():
                continue
            if channel is not None and net.channel != channel:
                continue
        yield row


@router.get("/api/export/csv")
def export_csv(
    store: AbstractStore = Depends(get_store),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    ssid: str | None = Query(None, description="texto del SSID (substring, sin mayusculas)"),
    channel: int | None = Query(None),
    min_rssi: int | None = Query(None),
    firmware: str | None = Query(None),
) -> StreamingResponse:
    r"""Historico en CSV, streaming por lotes (no carga todo en memoria).

    Sin filtros = "todo"; con filtros = "filtrado" (dialogo de export, X2)."""
    rows = _filtered_rows(
        store,
        since=since,
        until=until,
        ssid=ssid,
        channel=channel,
        min_rssi=min_rssi,
        firmware=firmware,
    )
    return StreamingResponse(
        _iter_csv_chunks(rows),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="observations.csv"'},
    )


@router.get("/api/export/json", response_model=list[HistoryRow])
def export_json(
    store: AbstractStore = Depends(get_store),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    ssid: str | None = Query(None),
    channel: int | None = Query(None),
    min_rssi: int | None = Query(None),
    firmware: str | None = Query(None),
) -> list[HistoryRow]:
    rows = _filtered_rows(
        store,
        since=since,
        until=until,
        ssid=ssid,
        channel=channel,
        min_rssi=min_rssi,
        firmware=firmware,
    )
    return [history_row(r) for r in rows]


@router.get("/api/export/count", response_model=ExportCountResponse)
def export_count(
    store: AbstractStore = Depends(get_store),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    ssid: str | None = Query(None),
    channel: int | None = Query(None),
    min_rssi: int | None = Query(None),
    firmware: str | None = Query(None),
) -> ExportCountResponse:
    """Cuanto se exportaria con el alcance elegido (lo muestra el dialogo)."""
    rows = _filtered_rows(
        store,
        since=since,
        until=until,
        ssid=ssid,
        channel=channel,
        min_rssi=min_rssi,
        firmware=firmware,
    )
    observations = sum(1 for _ in rows)
    filtered = any(v is not None for v in (since, until, ssid, channel, min_rssi, firmware))
    return ExportCountResponse(
        observations=observations,
        networks=len(store.get_networks(since=since, until=until)),
        scope="filtered" if filtered else "all",
    )


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


# ---- sesiones, hallazgos e informe (Fase A, paso 4) ----


def get_sessions_root(request: Request) -> Path:
    """Dependencia: carpeta `data/sessions` usada por la app."""
    return cast(Path, getattr(request.app.state, "sessions_root", Path("data/sessions")))


@router.get("/api/sessions", response_model=SessionListResponse)
def list_sessions(
    store: AbstractStore = Depends(get_store),
    root: Path = Depends(get_sessions_root),
    estado: str | None = Query(None, description="abierta | cerrada"),
) -> SessionListResponse:
    live = get_live_session(store, root=root)
    return SessionListResponse(
        sessions=[session_read(s) for s in store.list_sessions(estado=estado)],
        live=session_read(live),
    )


@router.post("/api/sessions", response_model=SessionRead, status_code=201)
def create_session_endpoint(
    payload: SessionCreate,
    store: AbstractStore = Depends(get_store),
    root: Path = Depends(get_sessions_root),
) -> SessionRead:
    from .. import __version__
    from ..session import create_session

    session = create_session(
        store,
        payload.nombre,
        root=root,
        cliente=payload.cliente,
        operador=payload.operador,
        lugar=payload.lugar,
        alcance=payload.alcance,
        dispositivo=payload.dispositivo,
        source=payload.source,
        version_app=__version__,
    )
    return session_read(session)


def _get_session_or_404(store: AbstractStore, session_id: str) -> Session:
    session = store.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"sesion no encontrada: {session_id}")
    return session


@router.get("/api/sessions/{session_id}", response_model=SessionRead)
def get_session(
    session_id: str,
    store: AbstractStore = Depends(get_store),
) -> SessionRead:
    return session_read(_get_session_or_404(store, session_id))


@router.patch("/api/sessions/{session_id}", response_model=SessionRead)
def update_session(
    session_id: str,
    payload: SessionUpdate,
    store: AbstractStore = Depends(get_store),
) -> SessionRead:
    session = _get_session_or_404(store, session_id)
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return session_read(session)
    merged = Session(
        id=session.id,
        nombre=updates.get("nombre", session.nombre),
        cliente=updates.get("cliente", session.cliente),
        operador=updates.get("operador", session.operador),
        lugar=updates.get("lugar", session.lugar),
        alcance=updates.get("alcance", session.alcance),
        dispositivo=updates.get("dispositivo", session.dispositivo),
        source=session.source,
        inicio=session.inicio,
        fin=session.fin,
        estado=session.estado,
        version_app=session.version_app,
        artifacts=session.artifacts,
    )
    store.save_session(merged)
    return session_read(merged)


@router.post("/api/sessions/{session_id}/close", response_model=SessionRead)
def close_session_endpoint(
    session_id: str,
    store: AbstractStore = Depends(get_store),
    root: Path = Depends(get_sessions_root),
) -> SessionRead:
    """Cerrar la sesion: evalua el catalogo, escribe informe y evidencia."""
    _get_session_or_404(store, session_id)
    evaluate_session(store, context_from_store(store, session_id))
    closed = close_session(store, session_id, root=root)
    write_report(root / session_id, build_context(store, session_id))
    return session_read(closed)


@router.get("/api/sessions/{session_id}/findings", response_model=FindingListResponse)
def session_findings(
    session_id: str,
    store: AbstractStore = Depends(get_store),
    severidad: str | None = Query(None),
    estado: str | None = Query(None),
) -> FindingListResponse:
    _get_session_or_404(store, session_id)
    findings = store.list_findings(session_id=session_id, severidad=severidad, estado=estado)
    return FindingListResponse(
        findings=[finding_read(f) for f in findings],
        total=len(findings),
        catalog_version=CATALOG_VERSION,
    )


@router.get("/api/findings", response_model=FindingListResponse)
def all_findings(
    store: AbstractStore = Depends(get_store),
    severidad: str | None = Query(None),
    estado: str | None = Query(None),
) -> FindingListResponse:
    findings = store.list_findings(severidad=severidad, estado=estado)
    return FindingListResponse(
        findings=[finding_read(f) for f in findings],
        total=len(findings),
        catalog_version=CATALOG_VERSION,
    )


@router.patch("/api/findings/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    store: AbstractStore = Depends(get_store),
) -> FindingRead:
    updated = store.update_finding(finding_id, estado=payload.estado)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"hallazgo no encontrado: {finding_id}")
    return finding_read(updated)


@router.post("/api/sessions/{session_id}/report", response_model=ReportResponse)
def generate_report(
    session_id: str,
    store: AbstractStore = Depends(get_store),
    root: Path = Depends(get_sessions_root),
    fmt: str = Query("md,html", description="md, html o ambos"),
) -> ReportResponse:
    _get_session_or_404(store, session_id)
    formats = tuple(f.strip().lower() for f in fmt.split(",") if f.strip())
    for item in formats:
        if item not in FORMATS:
            raise HTTPException(status_code=422, detail=f"fmt no valido: {item!r}")
    ctx = build_context(store, session_id)
    written = write_report(root / session_id, ctx, formats)
    return ReportResponse(
        session_id=session_id,
        formats=list(formats),
        written=[str(p) for p in written],
        integrity=verify_evidence(root / session_id),
    )


@router.get("/api/sessions/{session_id}/report")
def download_report(
    session_id: str,
    store: AbstractStore = Depends(get_store),
    root: Path = Depends(get_sessions_root),
    fmt: str = Query("md", pattern="^(md|html)$"),
) -> Response:
    """Descargar el informe (lo genera si no existe aun)."""
    _get_session_or_404(store, session_id)
    path = root / session_id / f"report.{fmt}"
    if not path.is_file():
        write_report(root / session_id, build_context(store, session_id), (fmt,))
    media = "text/markdown" if fmt == "md" else "text/html"
    return Response(
        content=path.read_text(encoding="utf-8"),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="report-{session_id}.{fmt}"'},
    )


@router.get("/api/sessions/{session_id}/evidence")
def session_evidence(
    session_id: str,
    store: AbstractStore = Depends(get_store),
    root: Path = Depends(get_sessions_root),
) -> dict[str, object]:
    _get_session_or_404(store, session_id)
    path = root / session_id / "evidence.json"
    if not path.is_file():
        write_evidence(root / session_id, build_context(store, session_id))
    return cast("dict[str, object]", json.loads(path.read_text(encoding="utf-8")))
