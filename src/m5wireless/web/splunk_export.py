"""Endpoints de export a Splunk HEC (dialogo de export, X2).

Rutas:

- `GET  /api/export/splunk/status`: esta configurado Splunk y con que URL;
  el token NO se devuelve jamas.
- `POST /api/export/splunk/test`: prueba de conexion. Siempre responde 200 con
  `ok: true/false` y un mensaje legible: un HEC caido no rompe la UI.
- `POST /api/export/splunk`: envia al HEC las observaciones del alcance elegido
  (todo o filtrado) en el formato elegido (JSON o linea CSV).

La config se busca en este orden: `app.state.splunk_config` (la que pasa la
CLI), el exporter en marcha (`app.state.exporter`) y, si no, las variables
`M5W_SPLUNK_HEC_URL` / `M5W_SPLUNK_HEC_TOKEN`.
"""

from __future__ import annotations

import csv
import io
import os
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from ..store.base import AbstractStore, ObservationRow
from .api import _filtered_rows, get_store
from .schemas import (
    SplunkSendRequest,
    SplunkSendResponse,
    SplunkStatusResponse,
    SplunkTestResponse,
)

# Defensa: un export enorme no reventaria HEC ni el tiempo de respuesta.
_EXPORT_SPLUNK_MAX_EVENTS = 2000

router = APIRouter()


def _splunk_config(request: Request) -> object | None:
    r"""Config HEC: `app.state.splunk_config`, el exporter en marcha o el env.

    `None` = no configurado; el dialogo lo dice claro en lugar de intentar una
    conexion a ciegas.
    """
    config: object | None = getattr(request.app.state, "splunk_config", None)
    if config is not None:
        return config
    exporter = getattr(request.app.state, "exporter", None)
    if exporter is not None:
        exporter_config: object | None = getattr(exporter, "config", None)
        return exporter_config
    url = os.environ.get("M5W_SPLUNK_HEC_URL", "").strip()
    token = os.environ.get("M5W_SPLUNK_HEC_TOKEN", "").strip()
    if url and token:
        from ..exporter.splunk_hec import SplunkHecConfig

        return SplunkHecConfig(url=url, token=token)
    return None


def _hec_health_url(url: str) -> str:
    r"""`https://splunk:8088/services/collector/event` -> `.../heathcheck`.

    Splunk publica el health check de HEC en `/heathcheck` (sic): permite
    comprobar la conexion sin indexar datos de prueba.
    """
    parts = urlsplit(url)
    if not parts.netloc:
        raise HTTPException(status_code=422, detail="URL HEC invalida")
    scheme = parts.scheme or "https"
    return f"{scheme}://{parts.netloc}/heathcheck"


def _hec_request(config: object, url: str, *, payload: object | None = None) -> httpx.Response:
    r"""Un HTTP contra HEC; el token va por cabecera y nunca se imprime.

    `payload` puede ser un dict (un evento) o una lista (varios eventos): HEC
    acepta un array de eventos en una sola peticion, lo que evita 2000 HTTP
    para un export grande.
    """
    with httpx.Client(
        verify=bool(getattr(config, "verify", True)),
        timeout=float(getattr(config, "timeout", 10.0)),
    ) as client:
        headers = {"Authorization": f"Splunk {getattr(config, 'token', '')}"}
        if payload is None:
            return client.get(url, headers=headers)
        return client.post(
            url,
            json=payload,
            params={"sourcetype": str(getattr(config, "sourcetype", "m5wireless"))},
            headers=headers,
        )


def _row_to_json(row: ObservationRow) -> dict[str, object]:
    return {
        "timestamp": row.timestamp.isoformat(),
        "firmware": row.firmware,
        "source": row.source,
        "event_type": row.event_type,
        "bssid": row.bssid,
        "rssi": row.rssi,
        "client_mac": row.client_mac,
        "raw_line": row.raw_line,
    }


def _row_to_csv_line(row: ObservationRow) -> str:
    """La observacion como linea CSV, con las mismas columnas que /api/export/csv."""
    buffer = io.StringIO()
    csv.writer(buffer, quoting=csv.QUOTE_MINIMAL).writerow(
        [
            row.timestamp.isoformat(),
            row.firmware,
            row.source,
            row.event_type,
            row.bssid or "",
            "" if row.rssi is None else str(row.rssi),
            row.client_mac or "",
            row.raw_line,
        ]
    )
    return buffer.getvalue().rstrip("\r\n")


@router.get("/api/export/splunk/status", response_model=SplunkStatusResponse)
def splunk_status(request: Request) -> SplunkStatusResponse:
    r"""Si Splunk esta configurado y con que URL; el token no se devuelve."""
    config = _splunk_config(request)
    exporter = getattr(request.app.state, "exporter", None)
    queued = int(exporter.queue_size()) if exporter is not None else 0
    if config is None:
        return SplunkStatusResponse(configured=False, queued=queued)
    return SplunkStatusResponse(
        configured=True,
        url=str(getattr(config, "url", "")),
        sourcetype=str(getattr(config, "sourcetype", "m5wireless")),
        verify=bool(getattr(config, "verify", True)),
        queued=queued,
    )


@router.post("/api/export/splunk/test", response_model=SplunkTestResponse)
def splunk_test(request: Request) -> SplunkTestResponse:
    r"""Prueba de conexion a HEC: siempre 200 con ok/fallo, nunca lanza (X2).

    La UI muestra el resultado dentro del dialogo; un fallo de red o un status
    inesperado se traduce a un mensaje legible y no rompe nada.
    """
    config = _splunk_config(request)
    if config is None:
        return SplunkTestResponse(
            ok=False,
            message="Splunk no configurado: define M5W_SPLUNK_HEC_URL y M5W_SPLUNK_HEC_TOKEN",
            url="",
        )
    url = str(getattr(config, "url", ""))
    try:
        health_url = _hec_health_url(url)
    except HTTPException as exc:
        return SplunkTestResponse(ok=False, message=str(exc.detail), url=url)
    try:
        response = _hec_request(config, health_url)
    except httpx.HTTPError as exc:
        return SplunkTestResponse(ok=False, message=f"HEC inalcanzable: {exc}", url=health_url)
    if response.status_code == 200:
        return SplunkTestResponse(
            ok=True, message="HEC responde: conexion OK", status_code=200, url=health_url
        )
    if response.status_code == 404:
        # Splunk sin /heathcheck: si el endpoint de eventos responde (405/400),
        # la conexion esta viva; eso ya vale como prueba.
        try:
            probe = _hec_request(config, url)
        except httpx.HTTPError as exc:
            return SplunkTestResponse(ok=False, message=f"HEC inalcanzable: {exc}", url=url)
        if 400 <= probe.status_code < 500:
            return SplunkTestResponse(
                ok=True,
                message=f"HEC accesible (el endpoint de eventos responde {probe.status_code})",
                status_code=probe.status_code,
                url=url,
            )
        return SplunkTestResponse(
            ok=False,
            message=f"HEC devolvio status {probe.status_code}",
            status_code=probe.status_code,
            url=url,
        )
    return SplunkTestResponse(
        ok=False,
        message=f"HEC devolvio status {response.status_code} (revisa el token)",
        status_code=response.status_code,
        url=health_url,
    )


@router.post("/api/export/splunk", response_model=SplunkSendResponse)
def splunk_send(
    request: Request,
    body: SplunkSendRequest,
    store: AbstractStore = Depends(get_store),
) -> SplunkSendResponse:
    r"""Enviar al HEC lo que se exporte (formato y alcance del dialogo).

    `format: json` manda cada observacion como JSON; `csv` manda la linea CSV.
    El envio es best-effort: si HEC cae a mitad se devuelve lo enviado y el
    motivo, sin romper la respuesta.
    """
    config = _splunk_config(request)
    if config is None:
        raise HTTPException(
            status_code=400,
            detail="Splunk no configurado (M5W_SPLUNK_HEC_URL / M5W_SPLUNK_HEC_TOKEN)",
        )
    if body.format not in ("json", "csv"):
        raise HTTPException(status_code=422, detail="format debe ser json o csv")
    rows = list(
        _filtered_rows(
            store,
            since=body.since,
            until=body.until,
            ssid=body.ssid,
            channel=body.channel,
            min_rssi=body.min_rssi,
            firmware=body.firmware,
        )
    )
    total = len(rows)
    if total > _EXPORT_SPLUNK_MAX_EVENTS:
        rows = rows[:_EXPORT_SPLUNK_MAX_EVENTS]
    batch_size = max(1, int(getattr(config, "batch_size", 100)))
    events: list[object] = [
        _row_to_json(row) if body.format == "json" else _row_to_csv_line(row) for row in rows
    ]
    sent = 0
    failed = 0
    message = ""
    url = str(getattr(config, "url", ""))
    for start in range(0, len(events), batch_size):
        batch = events[start : start + batch_size]
        try:
            response = _hec_request(config, url, payload=[{"event": event} for event in batch])
        except httpx.HTTPError as exc:
            failed += len(batch)
            message = f"HEC inalcanzable: {exc}"
            break
        if 200 <= response.status_code < 300:
            sent += len(batch)
        else:
            message = f"HEC devolvio status {response.status_code}"
            break
    failed = len(events) - sent
    if not message:
        message = f"Enviadas {sent} observaciones a HEC" if sent else "Sin observaciones que enviar"
    return SplunkSendResponse(
        ok=failed == 0, sent=sent, failed=failed, total=total, message=message
    )
