"""Tests de sesiones y hallazgos (Fase A, paso 1).

Cubre: alta/cierre de sesion, ids deterministas, filtros de hallazgos, sesion
viva implicita, escritura de evidencia en `data/sessions/<id>/` y migracion de
una SQLite antigua sin perder filas.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from m5wireless.models import Active, Artifact, Finding, Session, make_session_id
from m5wireless.session import close_session, create_session, get_live_session, session_dir
from m5wireless.store import AbstractStore, MemoryStore, SQLiteStore

NOW = datetime(2026, 10, 24, 9, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(minutes=35)


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path) -> AbstractStore:
    result: AbstractStore = (
        MemoryStore() if request.param == "memory" else SQLiteStore(tmp_path / "s.db")
    )
    yield result
    result.close()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "sessions"


# --------------------------------------------------------------------------
# Modelo
# --------------------------------------------------------------------------


def test_make_session_id_is_a_slug() -> None:
    assert make_session_id("Auditoria WiFi oficina B", NOW) == "20261024-auditoria-wifi-oficina-b"
    assert make_session_id("   ", NOW) == "20261024-sesion"


def test_session_validators() -> None:
    with pytest.raises(ValueError, match="cerrada"):
        Session(id="x", nombre="x", estado="cerrada", inicio=NOW)  # cerrada sin fin
    with pytest.raises(ValueError, match="severidad"):
        Finding(
            id="f1",
            session_id="s",
            rule_id="WIFI-OPEN",
            rule_version=1,
            severidad="extrema",
            titulo="t",
            activo=Active(bssid="aa:bb:cc:dd:ee:01"),
        )
    with pytest.raises(ValueError, match="aware"):
        Session(id="x", nombre="x", inicio=datetime.fromisoformat("2026-10-24T00:00:00"))


def test_finding_id_is_stable_and_dedupes() -> None:
    from m5wireless.models import make_finding_id

    a = Active(bssid="aa:bb:cc:dd:ee:01")
    b = Active(bssid="aa:bb:cc:dd:ee:01")
    c = Active(bssid="aa:bb:cc:dd:ee:01", ssid="Oficina-A")
    assert make_finding_id("WIFI-OPEN", a) == make_finding_id("WIFI-OPEN", b)
    assert make_finding_id("WIFI-OPEN", a) != make_finding_id("WIFI-OPEN", c)
    assert make_finding_id("WIFI-OPEN", a) != make_finding_id("WIFI-WEP", a)


# --------------------------------------------------------------------------
# Sesiones
# --------------------------------------------------------------------------


def test_create_and_close_session(store: AbstractStore, root: Path) -> None:
    session = create_session(
        store,
        "Auditoria oficina B",
        root=root,
        cliente="Acme",
        operador="Sammi",
        lugar="Planta 2",
        alcance="Solo redes 192.168.10.0/24",
        dispositivo="marauder-m5stick-1",
        source="file",
        version_app="3.5.0",
        inicio=NOW,
    )
    assert session.estado == "abierta"
    assert session.id == "20261024-auditoria-oficina-b"
    assert (root / session.id / "session.json").is_file()

    closed = close_session(store, session.id, root=root, closed_at=LATER)
    assert closed.estado == "cerrada"
    assert closed.fin == LATER
    payload = json.loads((root / session.id / "session.json").read_text(encoding="utf-8"))
    assert payload["estado"] == "cerrada"
    assert payload["fin"] == LATER.isoformat()

    # Cerrar de nuevo no cambia la fecha.
    again = close_session(store, session.id, root=root, closed_at=LATER + timedelta(hours=1))
    assert again.fin == LATER


def test_session_artifacts_are_hashed(store: AbstractStore, root: Path) -> None:
    session = create_session(store, "Demo", root=root, inicio=NOW)
    artifacts = root / session.id / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "captura.log").write_bytes(b"linea 1\nlinea 2\n")
    closed = close_session(store, session.id, root=root, closed_at=LATER)
    assert len(closed.artifacts) == 1
    art = closed.artifacts[0]
    assert isinstance(art, Artifact)
    assert art.nombre == "captura.log"
    assert len(art.sha256) == 64
    assert art.bytes == 16
    hashes = json.loads((root / session.id / "hashes.json").read_text(encoding="utf-8"))
    assert hashes["algorithm"] == "sha256"
    assert hashes["artifacts"][0]["sha256"] == art.sha256


def test_list_sessions_filters_by_estado(store: AbstractStore, root: Path) -> None:
    a = create_session(store, "A", root=root, inicio=NOW)
    create_session(store, "B", root=root, inicio=NOW)
    close_session(store, a.id, root=root, closed_at=LATER)
    assert {s.id for s in store.list_sessions()} == {a.id} | {"20261024-b"}
    assert [s.id for s in store.list_sessions(estado="cerrada")] == [a.id]
    assert [s.id for s in store.list_sessions(estado="abierta")] == ["20261024-b"]


def test_live_session_is_implicit_and_reusable(store: AbstractStore, root: Path) -> None:
    first = get_live_session(store, root=root, version_app="3.5.0")
    second = get_live_session(store, root=root)
    assert first.id == second.id
    assert first.id.endswith("-viva")
    assert len(store.list_sessions()) == 1


# --------------------------------------------------------------------------
# Hallazgos
# --------------------------------------------------------------------------


def _finding(rule_id: str, bssid: str, severidad: str = "alta") -> Finding:
    from m5wireless.models import make_finding_id

    activo = Active(bssid=bssid)
    return Finding(
        id=make_finding_id(rule_id, activo),
        session_id="20261024-demo",
        rule_id=rule_id,
        rule_version=1,
        severidad=severidad,
        titulo=f"{rule_id} en {bssid}",
        activo=activo,
        evidencia={"canal": 6},
        recomendacion="Cambiar la configuracion",
    )


def test_findings_roundtrip_and_filters(store: AbstractStore) -> None:
    store.save_finding(_finding("WIFI-OPEN", "aa:bb:cc:dd:ee:01"))
    store.save_finding(_finding("WIFI-WEP", "11:22:33:44:55:02", severidad="media"))
    assert len(store.list_findings()) == 2
    assert len(store.list_findings(session_id="20261024-demo")) == 2
    assert len(store.list_findings(session_id="otra")) == 0
    assert [f.rule_id for f in store.list_findings(severidad="alta")] == ["WIFI-OPEN"]
    assert store.get_finding("WIFI-OPEN-000000000000") is None


def test_finding_upsert_preserves_triage_state(store: AbstractStore) -> None:
    finding = _finding("WIFI-OPEN", "aa:bb:cc:dd:ee:01")
    store.save_finding(finding)
    updated = store.update_finding(finding.id, estado="falso_positivo")
    assert updated is not None and updated.estado == "falso_positivo"
    # Re-evaluar la misma regla no borra la decision de triaje.
    store.save_finding(finding)
    assert store.get_finding(finding.id).estado == "falso_positivo"  # type: ignore[union-attr]
    assert store.update_finding("no-existe", estado="abierto") is None


# --------------------------------------------------------------------------
# Migracion
# --------------------------------------------------------------------------


def test_sqlite_migration_keeps_existing_rows(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """
        CREATE TABLE networks (
            bssid TEXT PRIMARY KEY, ssid TEXT, channel INTEGER, rssi INTEGER,
            first_seen TIMESTAMP, last_seen TIMESTAMP
        )
        """
    )
    conn.execute(
        "INSERT INTO networks (bssid, ssid, channel, rssi, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (
            "aa:bb:cc:dd:ee:01",
            "Legacy",
            6,
            -70,
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    conn.execute(
        "CREATE TABLE observations (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP, firmware TEXT, source TEXT, event_type TEXT, bssid TEXT, rssi INTEGER, client_mac TEXT, raw_line TEXT)"
    )
    conn.execute(
        "INSERT INTO observations (timestamp, firmware, source, event_type, bssid, raw_line) VALUES (?, ?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:00:00+00:00",
            "marauder",
            "file",
            "network_seen",
            "aa:bb:cc:dd:ee:01",
            "Found network",
        ),
    )
    conn.commit()
    conn.close()

    store = SQLiteStore(db)
    assert len(store.get_networks()) == 1
    assert len(list(store.iter_observations())) == 1
    create_session(store, "Nueva sesion", root=tmp_path / "sessions", inicio=NOW)
    assert len(store.list_sessions()) == 1
    store.close()

    # Las tablas nuevas existen y las viejas conservan su contenido.
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    conn.close()


def test_session_dir_creates_artifacts_folder(root: Path) -> None:
    directory = session_dir(root, "20261024-x")
    assert directory.is_dir()
    assert (directory / "artifacts").is_dir()
