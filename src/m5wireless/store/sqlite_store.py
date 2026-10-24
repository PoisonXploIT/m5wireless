"""Store SQLite (default): persistencia local en un fichero.

Esquema (plan §8.2) con dos matizs acordados:

- `clients` es el **estado actual** (PK por mac); la traza completa de
  asociaciones vive en `observations`.
- Indexes en ``observations.timestamp`` y ``networks.last_seen``.

Desviaciones documentadas respecto al esquema propuesto:

- Se omite la columna ``networks.n_clients``: se calcula en lectura a partir de
  ``clients`` (evita mantener un contador denormalizado que no se puede
  actualizar de forma fiable).
- La FK ``clients.bssid -> networks.bssid`` se declara pero NO se fuerza
  (sin ``PRAGMA foreign_keys=ON``): un cliente puede referenciar una red que
  aun no ha aparecido como linea de red, y la insercion no debe fallar.

Los timestamps se guardan como texto ISO-8601 UTC; al ser todos el mismo
formato, el orden lexicografico coincide con el cronologico.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from ..models import (
    Active,
    Artifact,
    Client,
    Finding,
    FindingStatus,
    Network,
    ObservationEvent,
    Session,
    utc_now,
)
from .base import AbstractStore, ObservationRow, event_to_observation_row

_SCHEMA = """
CREATE TABLE IF NOT EXISTS networks (
    bssid TEXT PRIMARY KEY,
    ssid TEXT,
    channel INTEGER,
    rssi INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_networks_last_seen ON networks(last_seen);

CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY,
    bssid TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    FOREIGN KEY (bssid) REFERENCES networks(bssid)
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP,
    firmware TEXT,
    source TEXT,
    event_type TEXT,
    bssid TEXT,
    rssi INTEGER,
    client_mac TEXT,
    raw_line TEXT
);
CREATE INDEX IF NOT EXISTS idx_observations_timestamp ON observations(timestamp);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    nombre TEXT NOT NULL,
    cliente TEXT NOT NULL DEFAULT '',
    operador TEXT NOT NULL DEFAULT '',
    lugar TEXT NOT NULL DEFAULT '',
    alcance TEXT NOT NULL DEFAULT '',
    dispositivo TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'file',
    inicio TIMESTAMP NOT NULL,
    fin TIMESTAMP,
    estado TEXT NOT NULL DEFAULT 'abierta',
    version_app TEXT NOT NULL DEFAULT '',
    artifacts TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_sessions_estado ON sessions(estado);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    severidad TEXT NOT NULL,
    titulo TEXT NOT NULL,
    activo TEXT NOT NULL DEFAULT '{}',
    evidencia TEXT NOT NULL DEFAULT '{}',
    recomendacion TEXT NOT NULL DEFAULT '',
    estado TEXT NOT NULL DEFAULT 'abierto',
    creado TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severidad ON findings(severidad);
CREATE INDEX IF NOT EXISTS idx_findings_estado ON findings(estado);
"""


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _row_to_session(row: sqlite3.Row) -> Session:
    artifacts = tuple(
        Artifact(a["nombre"], a["ruta"], a["sha256"], int(a["bytes"]))
        for a in json.loads(row["artifacts"] or "[]")
    )
    return Session(
        id=row["id"],
        nombre=row["nombre"],
        cliente=row["cliente"],
        operador=row["operador"],
        lugar=row["lugar"],
        alcance=row["alcance"],
        dispositivo=row["dispositivo"],
        source=row["source"],
        inicio=_from_iso(row["inicio"]),
        fin=_from_iso(row["fin"]) if row["fin"] else None,
        estado=row["estado"],
        version_app=row["version_app"],
        artifacts=artifacts,
    )


def _row_to_finding(row: sqlite3.Row) -> Finding:
    activo_raw = json.loads(row["activo"] or "{}")
    return Finding(
        id=row["id"],
        session_id=row["session_id"],
        rule_id=row["rule_id"],
        rule_version=int(row["rule_version"]),
        severidad=row["severidad"],
        titulo=row["titulo"],
        activo=Active(
            bssid=activo_raw.get("bssid"),
            ssid=activo_raw.get("ssid"),
            client_mac=activo_raw.get("client_mac"),
        ),
        evidencia=json.loads(row["evidencia"] or "{}"),
        recomendacion=row["recomendacion"],
        estado=row["estado"],
        creado=_from_iso(row["creado"]),
    )


class SQLiteStore(AbstractStore):
    """Persistencia local en SQLite (stdlib, sin dependencias extra)."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        # `check_same_thread=False`: FastAPI ejecuta las rutas sincronas en un
        # threadpool, asi que la conexion creada al construir el store se usa
        # desde varios hilos. Las escrituras se serializan con `_lock`.
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _write(self, sql: str, params: tuple[object, ...]) -> sqlite3.Cursor:
        """Ejecutar y confirmar bajo lock: las rutas FastAPI corren en threadpool."""
        with self._lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
        return cursor

    # ---- escritura ----
    def upsert_network(self, network: Network, *, at: datetime) -> None:
        self._write(
            """
            INSERT INTO networks (bssid, ssid, channel, rssi, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(bssid) DO UPDATE SET
                ssid = COALESCE(excluded.ssid, networks.ssid),
                channel = COALESCE(excluded.channel, networks.channel),
                rssi = COALESCE(excluded.rssi, networks.rssi),
                last_seen = excluded.last_seen
            """,
            (
                network.bssid,
                network.ssid,
                network.channel,
                network.rssi,
                _iso(at),
                _iso(at),
            ),
        )

    def upsert_client(self, client: Client, *, at: datetime) -> None:
        self._write(
            """
            INSERT INTO clients (mac, bssid, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                bssid = COALESCE(excluded.bssid, clients.bssid),
                last_seen = excluded.last_seen
            """,
            (client.mac, client.bssid, _iso(at), _iso(at)),
        )

    def record_observation(self, event: ObservationEvent) -> None:
        row = event_to_observation_row(event)
        self._write(
            """
            INSERT INTO observations
                (timestamp, firmware, source, event_type, bssid, rssi, client_mac, raw_line)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _iso(row.timestamp),
                row.firmware,
                row.source,
                row.event_type,
                row.bssid,
                row.rssi,
                row.client_mac,
                row.raw_line,
            ),
        )

    # ---- consulta ----
    def get_network(self, bssid: str) -> Network | None:
        cursor = self._conn.execute("SELECT * FROM networks WHERE bssid = ?", (bssid,))
        row = cursor.fetchone()
        if row is None:
            return None
        clients_cursor = self._conn.execute("SELECT mac FROM clients WHERE bssid = ?", (bssid,))
        clients = {r["mac"] for r in clients_cursor.fetchall()}
        return Network(
            bssid=row["bssid"],
            ssid=row["ssid"],
            channel=row["channel"],
            rssi=row["rssi"],
            n_clients=len(clients),
            clients=clients,
            first_seen=_from_iso(row["first_seen"]),
            last_seen=_from_iso(row["last_seen"]),
        )

    def get_client(self, mac: str) -> Client | None:
        cursor = self._conn.execute("SELECT * FROM clients WHERE mac = ?", (mac,))
        row = cursor.fetchone()
        if row is None:
            return None
        return Client(
            mac=row["mac"],
            bssid=row["bssid"],
            first_seen=_from_iso(row["first_seen"]),
            last_seen=_from_iso(row["last_seen"]),
        )

    def iter_observations(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> Iterator[ObservationRow]:
        clauses = ["1=1"]
        params: list[str] = []
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(_iso(since))
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(_iso(until))
        cursor = self._conn.execute(
            f"SELECT * FROM observations WHERE {' AND '.join(clauses)} ORDER BY id", params
        )
        for r in cursor:
            yield ObservationRow(
                timestamp=_from_iso(r["timestamp"]),
                firmware=r["firmware"],
                source=r["source"],
                event_type=r["event_type"],
                bssid=r["bssid"],
                rssi=r["rssi"],
                client_mac=r["client_mac"],
                raw_line=r["raw_line"],
            )

    def get_recent_observations(self, limit: int) -> list[ObservationRow]:
        if limit <= 0:
            return []
        cursor = self._conn.execute("SELECT * FROM observations ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        result: list[ObservationRow] = []
        for r in reversed(rows):
            result.append(
                ObservationRow(
                    timestamp=_from_iso(r["timestamp"]),
                    firmware=r["firmware"],
                    source=r["source"],
                    event_type=r["event_type"],
                    bssid=r["bssid"],
                    rssi=r["rssi"],
                    client_mac=r["client_mac"],
                    raw_line=r["raw_line"],
                )
            )
        return result

    def get_networks(
        self, *, since: datetime | None = None, until: datetime | None = None
    ) -> list[Network]:
        clauses = ["1=1"]
        params: list[str] = []
        if since is not None:
            clauses.append("last_seen >= ?")
            params.append(_iso(since))
        if until is not None:
            clauses.append("last_seen <= ?")
            params.append(_iso(until))
        cursor = self._conn.execute(f"SELECT * FROM networks WHERE {' AND '.join(clauses)}", params)
        result: list[Network] = []
        for row in cursor.fetchall():
            clients_cursor = self._conn.execute(
                "SELECT mac FROM clients WHERE bssid = ?", (row["bssid"],)
            )
            clients = {r["mac"] for r in clients_cursor.fetchall()}
            result.append(
                Network(
                    bssid=row["bssid"],
                    ssid=row["ssid"],
                    channel=row["channel"],
                    rssi=row["rssi"],
                    n_clients=len(clients),
                    clients=clients,
                    first_seen=_from_iso(row["first_seen"]),
                    last_seen=_from_iso(row["last_seen"]),
                )
            )
        return result

    def get_clients(self, *, associated_to: str | None = None) -> list[Client]:
        if associated_to is None:
            cursor = self._conn.execute("SELECT * FROM clients")
        else:
            cursor = self._conn.execute("SELECT * FROM clients WHERE bssid = ?", (associated_to,))
        return [
            Client(
                mac=r["mac"],
                bssid=r["bssid"],
                first_seen=_from_iso(r["first_seen"]),
                last_seen=_from_iso(r["last_seen"]),
            )
            for r in cursor.fetchall()
        ]

    def get_network_history(
        self,
        bssid: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[ObservationRow]:
        clauses = ["bssid = ?"]
        params: list[str] = [bssid]
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(_iso(since))
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(_iso(until))
        cursor = self._conn.execute(
            f"SELECT * FROM observations WHERE {' AND '.join(clauses)} ORDER BY timestamp",
            params,
        )
        return [
            ObservationRow(
                timestamp=_from_iso(r["timestamp"]),
                firmware=r["firmware"],
                source=r["source"],
                event_type=r["event_type"],
                bssid=r["bssid"],
                rssi=r["rssi"],
                client_mac=r["client_mac"],
                raw_line=r["raw_line"],
            )
            for r in cursor.fetchall()
        ]

    def get_channel_distribution(self) -> dict[int, int]:
        cursor = self._conn.execute(
            "SELECT channel, COUNT(*) AS n FROM networks WHERE channel IS NOT NULL GROUP BY channel"
        )
        return {int(r["channel"]): int(r["n"]) for r in cursor.fetchall()}

    # ---- sesiones y hallazgos ----
    def save_session(self, session: Session) -> None:
        self._write(
            """
            INSERT INTO sessions (id, nombre, cliente, operador, lugar, alcance, dispositivo,
                                  source, inicio, fin, estado, version_app, artifacts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                nombre = excluded.nombre,
                cliente = excluded.cliente,
                operador = excluded.operador,
                lugar = excluded.lugar,
                alcance = excluded.alcance,
                dispositivo = excluded.dispositivo,
                source = excluded.source,
                inicio = excluded.inicio,
                fin = excluded.fin,
                estado = excluded.estado,
                version_app = excluded.version_app,
                artifacts = excluded.artifacts
            """,
            (
                session.id,
                session.nombre,
                session.cliente,
                session.operador,
                session.lugar,
                session.alcance,
                session.dispositivo,
                session.source,
                _iso(session.inicio),
                _iso(session.fin) if session.fin is not None else None,
                session.estado,
                session.version_app,
                json.dumps([asdict(a) for a in session.artifacts], ensure_ascii=False),
            ),
        )

    def get_session(self, session_id: str) -> Session | None:
        cursor = self._conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        return _row_to_session(row) if row is not None else None

    def list_sessions(self, *, estado: str | None = None) -> list[Session]:
        if estado is None:
            cursor = self._conn.execute("SELECT * FROM sessions ORDER BY inicio DESC")
        else:
            cursor = self._conn.execute(
                "SELECT * FROM sessions WHERE estado = ? ORDER BY inicio DESC", (estado,)
            )
        return [_row_to_session(r) for r in cursor.fetchall()]

    def save_finding(self, finding: Finding) -> None:
        self._write(
            """
            INSERT INTO findings (id, session_id, rule_id, rule_version, severidad, titulo,
                                  activo, evidencia, recomendacion, estado, creado)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                rule_version = excluded.rule_version,
                severidad = excluded.severidad,
                titulo = excluded.titulo,
                evidencia = excluded.evidencia,
                recomendacion = excluded.recomendacion,
                estado = findings.estado,
                creado = findings.creado
            """,
            (
                finding.id,
                finding.session_id,
                finding.rule_id,
                finding.rule_version,
                finding.severidad,
                finding.titulo,
                json.dumps(
                    {k: v for k, v in asdict(finding.activo).items() if v is not None},
                    ensure_ascii=False,
                ),
                json.dumps(finding.evidencia, ensure_ascii=False, default=str),
                finding.recomendacion,
                finding.estado,
                _iso(finding.creado),
            ),
        )

    def get_finding(self, finding_id: str) -> Finding | None:
        cursor = self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cursor.fetchone()
        return _row_to_finding(row) if row is not None else None

    def list_findings(
        self,
        *,
        session_id: str | None = None,
        severidad: str | None = None,
        estado: str | None = None,
    ) -> list[Finding]:
        clauses = ["1=1"]
        params: list[str] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if severidad is not None:
            clauses.append("severidad = ?")
            params.append(severidad)
        if estado is not None:
            clauses.append("estado = ?")
            params.append(estado)
        cursor = self._conn.execute(
            f"SELECT * FROM findings WHERE {' AND '.join(clauses)} ORDER BY severidad, id",
            params,
        )
        return [_row_to_finding(r) for r in cursor.fetchall()]

    def update_finding(self, finding_id: str, *, estado: FindingStatus) -> Finding | None:
        cursor = self._write("UPDATE findings SET estado = ? WHERE id = ?", (estado, finding_id))
        if cursor.rowcount == 0:
            return None
        return self.get_finding(finding_id)

    # ---- mantenimiento ----
    def prune_older_than(self, days: int, *, reference: datetime | None = None) -> int:
        ref = reference if reference is not None else utc_now()
        cutoff = _iso(ref - timedelta(days=days))
        cursor = self._write("DELETE FROM observations WHERE timestamp < ?", (cutoff,))
        return cursor.rowcount

    def close(self) -> None:
        self._conn.close()
