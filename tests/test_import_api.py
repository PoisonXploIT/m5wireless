"""Tests del importador de capturas: /api/fs/browse + /api/import.

El builder de pcaps se reutiliza de test_pcap_parser (misma estructura que
el fixture real). No hace falta hardware: cualquier pcap en una carpeta
temporal es un caso real de importacion.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

# Mismos builders sinteticos que tests/test_pcap_parser.py.
from test_pcap_parser import _build_eapol, _build_mgmt, _wrap_pcap
from web_auth import TEST_TOKEN, auth_client

from m5wireless.parser.registry import get_parser
from m5wireless.source.file_source import FileSource
from m5wireless.store import MemoryStore
from m5wireless.web import api as api_module
from m5wireless.web import create_app
from m5wireless.web.api import _IMPORT_MAX_FILES, get_store
from m5wireless.web.security import is_within_roots
from m5wireless.worker.collector import Collector

AP_MAC = "aa:bb:cc:dd:ee:01"
CLIENT_MAC = "0a:5e:1d:a6:e0:51"
TS = (1_700_000_000, 0)


def _valid_pcap(ssid: str) -> bytes:
    return _wrap_pcap(
        [
            _build_mgmt(ssid=ssid, ts=TS),
            _build_eapol(ts=TS),
        ]
    )


@pytest.fixture
def client(seeded_store: MemoryStore, tmp_path: Path) -> TestClient:
    """App sin collector (mismo patron que tests/test_api.py).

    `browse_roots=[tmp_path]`: las raices del navegador se fijan a la carpeta
    temporal del test, asi los casos de "fuera de la raiz" son deterministas en
    Windows y en el runner de CI (Linux), donde `/tmp` no cuelga del perfil.
    """
    app = create_app(seeded_store, session_token=TEST_TOKEN, browse_roots=[str(tmp_path)])
    app.dependency_overrides[get_store] = lambda: seeded_store
    with auth_client(app) as test_client:
        yield test_client


@pytest.fixture
def client_with_collector(
    seeded_store: MemoryStore, marauder_log_path: Path, tmp_path: Path
) -> TestClient:
    """App con collector (no arrancado: submit_events funciona igual)."""
    source = FileSource(str(marauder_log_path), follow=False)
    collector = Collector(source, get_parser("marauder"), seeded_store, source_type="file")
    app = create_app(
        seeded_store,
        collector=collector,
        session_token=TEST_TOKEN,
        browse_roots=[str(tmp_path)],
    )
    app.dependency_overrides[get_store] = lambda: seeded_store
    with auth_client(app) as test_client:
        yield test_client


# ---- browse ----


def test_browse_root(client: TestClient) -> None:
    res = client.get("/api/fs/browse")
    assert res.status_code == 200
    body = res.json()
    assert body["path"] is None
    assert body["parent"] is None
    assert len(body["entries"]) >= 1
    assert all(e["kind"] == "dir" for e in body["entries"])


def test_browse_dir_lists_dirs_and_pcaps(client: TestClient, tmp_path: Path) -> None:
    (tmp_path / "handshakes").mkdir()
    (tmp_path / "captura.pcap").write_bytes(_valid_pcap("TESTNET"))
    (tmp_path / ".oculto").mkdir()
    (tmp_path / "notas.txt").write_text("hola", encoding="utf-8")
    res = client.get("/api/fs/browse", params={"path": str(tmp_path)})
    assert res.status_code == 200
    body = res.json()
    # Las rutas devueltas vienen resueltas (symlinks y separadores normalizados).
    assert body["path"] == str(tmp_path.resolve())
    # `tmp_path` es una de las raices: no se puede subir por encima de ella,
    # el boton "arriba" desaparece (P0.2).
    assert body["parent"] is None
    by_name = {e["name"]: e for e in body["entries"]}
    assert by_name["handshakes"]["kind"] == "dir"
    assert by_name["captura.pcap"]["kind"] == "file"
    assert by_name["captura.pcap"]["size"] == (tmp_path / "captura.pcap").stat().st_size
    assert ".oculto" not in by_name
    assert "notas.txt" not in by_name


def test_browse_missing_dir(client: TestClient, tmp_path: Path) -> None:
    """Dentro de la raiz: 404 si el directorio no existe.

    Fuera de la raiz se responde 403 ANTES de comprobar la existencia: no se
    confirma (ni se niega) que `C:/Windows` exista, solo que no es navegable.
    """
    assert (
        client.get("/api/fs/browse", params={"path": str(tmp_path / "no-existe")}).status_code
        == 404
    )
    assert client.get("/api/fs/browse", params={"path": "Z:/no/existe/nada"}).status_code == 403


# ---- import ----


def test_import_file(client_with_collector: TestClient, tmp_path: Path) -> None:
    pcap = tmp_path / "importada.pcap"
    pcap.write_bytes(_valid_pcap("RED_IMPORTADA"))
    res = client_with_collector.post("/api/import", json={"path": str(pcap)})
    assert res.status_code == 200
    body = res.json()
    assert body["files"] == 1
    # 1 NetworkSeen + 1 ClientAssociated.
    assert body["events"] == 2
    assert body["errors"] == 0

    nets = client_with_collector.get("/api/networks").json()["networks"]
    assert any(n["ssid"] == "RED_IMPORTADA" and n["bssid"] == AP_MAC for n in nets)
    clients = client_with_collector.get("/api/clients").json()
    assert any(c["mac"] == CLIENT_MAC for c in clients)


def test_import_dir_counts_errors(client_with_collector: TestClient, tmp_path: Path) -> None:
    sub = tmp_path / "sd"
    sub.mkdir()
    (sub / "bien.pcap").write_bytes(_valid_pcap("OK_NET"))
    (sub / "roto.pcap").write_bytes(b"no es un pcap")
    res = client_with_collector.post("/api/import", json={"path": str(sub)})
    assert res.status_code == 200
    body = res.json()
    assert body["files"] == 1
    assert body["events"] == 2
    assert body["errors"] == 1
    assert len(body["messages"]) == 1
    assert "roto.pcap" in body["messages"][0]


def test_import_unsupported_extension(client_with_collector: TestClient, tmp_path: Path) -> None:
    txt = tmp_path / "notas.txt"
    txt.write_text("hola", encoding="utf-8")
    res = client_with_collector.post("/api/import", json={"path": str(txt)})
    assert res.status_code == 422


def test_import_missing_path(client_with_collector: TestClient, tmp_path: Path) -> None:
    assert (
        client_with_collector.post(
            "/api/import", json={"path": str(tmp_path / "no-existe.pcap")}
        ).status_code
        == 404
    )
    assert (
        client_with_collector.post("/api/import", json={"path": "Z:/no/existe.pcap"}).status_code
        == 403
    )


def test_import_without_collector(client: TestClient, tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(_valid_pcap("NADA"))
    res = client.post("/api/import", json={"path": str(pcap)})
    assert res.status_code == 409


# ---- gate loopback ----


def test_fs_endpoints_require_loopback(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("m5wireless.web.api._LOCAL_CLIENTS", frozenset())
    assert client.get("/api/fs/browse").status_code == 403
    res = client.post("/api/import", json={"path": "C:/x.pcap"})
    assert res.status_code == 403


# ---- raices permitidas (P0.2: M5W_BROWSE_ROOTS) ----


def test_browse_root_lists_roots_not_drives(client: TestClient, tmp_path: Path) -> None:
    """Sin `path` se listan las raices admitidas, ya no las unidades del disco."""
    res = client.get("/api/fs/browse")
    assert res.status_code == 200
    body = res.json()
    paths = [entry["path"] for entry in body["entries"]]
    assert str(tmp_path) in paths
    assert not any(Path(path).resolve() != Path(path) for path in paths)
    assert all(is_within_roots(Path(path), [tmp_path]) for path in paths)


def test_browse_rejects_path_outside_roots(client: TestClient) -> None:
    """`C:/Windows` (o su equivalente POSIX) esta fuera de las raices: 403."""
    res = client.get("/api/fs/browse", params={"path": "C:/Windows"})
    assert res.status_code == 403
    assert "raices permitidas" in res.json()["detail"]


def test_browse_rejects_traversal(client: TestClient) -> None:
    """Una ruta con `..` es una travesia: 400 antes de tocar el filesystem."""
    for bad in ("../../", "data/../../etc", ".."):
        res = client.get("/api/fs/browse", params={"path": bad})
        assert res.status_code == 400, bad
    res = client.get("/api/fs/browse", params={"path": "   "})
    assert res.status_code == 400


def test_browse_parent_stops_at_the_root(client: TestClient, tmp_path: Path) -> None:
    """Desde la propia raiz no se puede subir: el boton 'arriba' se desactiva."""
    res = client.get("/api/fs/browse", params={"path": str(tmp_path)})
    assert res.status_code == 200
    assert res.json()["parent"] is None
    sub = tmp_path / "sd"
    sub.mkdir()
    res = client.get("/api/fs/browse", params={"path": str(sub)})
    assert res.json()["parent"] == str(tmp_path)


def test_browse_rejects_symlink_out_of_root(client: TestClient, tmp_path: Path) -> None:
    """Un symlink dentro de la raiz que apunta fuera se rechaza (403) y no se lista."""
    inside = tmp_path / "dentro"
    inside.mkdir()
    outside = tmp_path.parent / "fuera"
    outside.mkdir(exist_ok=True)
    try:
        link = inside / "escape"
        os.symlink(outside, link)
    except OSError:
        pytest.skip("el sistema no permite crear symlinks (Windows sin permisos)")
    res = client.get("/api/fs/browse", params={"path": str(link)})
    assert res.status_code == 403
    listing = client.get("/api/fs/browse", params={"path": str(inside)}).json()
    assert "escape" not in {entry["name"] for entry in listing["entries"]}


def test_data_dir_is_a_root_by_default(
    seeded_store: MemoryStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sin `M5W_BROWSE_ROOTS`, `data/` (el `data_dir`) y el perfil son navegables."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "captura.pcap").write_bytes(_valid_pcap("RAIZ_DATA"))
    monkeypatch.chdir(tmp_path)
    app = create_app(seeded_store, session_token=TEST_TOKEN, data_dir=data_dir)
    app.dependency_overrides[get_store] = lambda: seeded_store
    with auth_client(app) as test_client:
        roots = {entry["path"] for entry in test_client.get("/api/fs/browse").json()["entries"]}
        assert str(data_dir.resolve()) in roots
        assert str(Path.home().resolve()) in roots
        res = test_client.get("/api/fs/browse", params={"path": "data/"})
        assert res.status_code == 200
        assert res.json()["path"] == str(data_dir.resolve())
        assert test_client.get("/api/fs/browse", params={"path": "C:/Windows"}).status_code == 403
        assert test_client.get("/api/fs/browse", params={"path": "../../"}).status_code == 400


def test_browse_roots_env_var(
    seeded_store: MemoryStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`M5W_BROWSE_ROOTS` sustituye las raices por defecto."""
    sd = tmp_path / "sd"
    sd.mkdir()
    monkeypatch.setenv("M5W_BROWSE_ROOTS", f"{sd}, {tmp_path}")
    app = create_app(seeded_store, session_token=TEST_TOKEN)
    app.dependency_overrides[get_store] = lambda: seeded_store
    with auth_client(app) as test_client:
        paths = {entry["path"] for entry in test_client.get("/api/fs/browse").json()["entries"]}
        assert paths == {str(sd.resolve()), str(tmp_path.resolve())}
        assert test_client.get("/api/fs/browse", params={"path": str(sd)}).status_code == 200
        assert (
            test_client.get("/api/fs/browse", params={"path": str(Path.home())}).status_code == 403
        )


def test_import_rejects_path_outside_roots(client_with_collector: TestClient) -> None:
    res = client_with_collector.post("/api/import", json={"path": "C:/Windows"})
    assert res.status_code == 403
    assert client_with_collector.post("/api/import", json={"path": "../x.pcap"}).status_code == 400


def test_import_rejects_symlink_out_of_root(
    client_with_collector: TestClient, tmp_path: Path
) -> None:
    inside = tmp_path / "dentro"
    inside.mkdir()
    outside = tmp_path.parent / "fuera"
    outside.mkdir(exist_ok=True)
    pcap = outside / "robada.pcap"
    pcap.write_bytes(_valid_pcap("FUERA"))
    try:
        link = inside / "escape.pcap"
        os.symlink(pcap, link)
    except OSError:
        pytest.skip("el sistema no permite crear symlinks (Windows sin permisos)")
    res = client_with_collector.post("/api/import", json={"path": str(link)})
    assert res.status_code == 403
    assert not any(
        n["ssid"] == "FUERA" for n in client_with_collector.get("/api/networks").json()["networks"]
    )


def test_import_caps_at_200_files(client_with_collector: TestClient, tmp_path: Path) -> None:
    """Mas de 200 pcaps en la carpeta: 422 y nada se importa (tope duro)."""
    folder = tmp_path / "miles"
    folder.mkdir()
    for i in range(_IMPORT_MAX_FILES + 1):
        (folder / f"cap{i}.pcap").write_bytes(_valid_pcap(f"RED{i}"))
    res = client_with_collector.post("/api/import", json={"path": str(folder)})
    assert res.status_code == 422
    assert "200" in res.json()["detail"]
    ssids = {n["ssid"] for n in client_with_collector.get("/api/networks").json()["networks"]}
    assert "RED0" not in ssids  # no se importa ni un fichero


def test_import_is_serialised(client_with_collector: TestClient, tmp_path: Path) -> None:
    """Un import concurrente se rechaza con 409 (el parseo es CPU-bound)."""
    pcap = tmp_path / "serial.pcap"
    pcap.write_bytes(_valid_pcap("SERIALIZADA"))
    with api_module._IMPORT_LOCK:
        res = client_with_collector.post("/api/import", json={"path": str(pcap)})
    assert res.status_code == 409
    assert "en curso" in res.json()["detail"]
    # Soltada la lock, el mismo import funciona: no queda bloqueada.
    res = client_with_collector.post("/api/import", json={"path": str(pcap)})
    assert res.status_code == 200
    assert res.json()["files"] == 1


# ---- progreso por fichero y cancelacion (X1) ----


def _ndjson_lines(text: str) -> list[dict[str, object]]:
    """Objetos NDJSON de una respuesta, uno por linea no vacia."""
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_import_stream_reports_progress_per_file(
    client_with_collector: TestClient, tmp_path: Path
) -> None:
    """Con `stream: true`: una linea por fichero y el resumen al final (X1)."""
    folder = tmp_path / "sd"
    folder.mkdir()
    for i in range(3):
        (folder / f"cap{i}.pcap").write_bytes(_valid_pcap(f"RED{i}"))
    (folder / "roto.pcap").write_bytes(b"no es un pcap")

    before = client_with_collector.get("/api/export/count").json()["observations"]
    res = client_with_collector.post("/api/import", json={"path": str(folder), "stream": True})
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/x-ndjson")
    items = _ndjson_lines(res.text)
    assert items[0] == {"type": "start", "total": 4}
    per_file = [item for item in items if item["type"] == "file"]
    assert [item["index"] for item in per_file] == [1, 2, 3, 4]
    assert [item["total"] for item in per_file] == [4, 4, 4, 4]
    assert [item["name"] for item in per_file] == [
        "cap0.pcap",
        "cap1.pcap",
        "cap2.pcap",
        "roto.pcap",
    ]
    assert sum(1 for item in per_file if item["ok"]) == 3
    assert sum(item["events"] for item in per_file) == 6
    done = items[-1]
    assert done["type"] == "done"
    assert done["files"] == 3 and done["events"] == 6 and done["errors"] == 1
    assert done["cancelled"] is False and done["skipped"] == 0
    assert len(done["results"]) == 4
    assert done["results"][3]["ok"] is False and "roto.pcap" in done["messages"][0]
    # Los eventos importados llegan al store: 6 pcaps sinteticos x 2 eventos.
    # (Todos comparten el mismo BSSID, asi que se ve una sola red nueva: lo que
    # cuenta aqui es el numero de observaciones.)
    after = client_with_collector.get("/api/export/count").json()["observations"]
    assert after - before == 6


def test_import_without_stream_keeps_the_old_shape(
    client_with_collector: TestClient, tmp_path: Path
) -> None:
    """Sin `stream` sigue habiendo un JSON unico (compatibilidad con la CLI)."""
    pcap = tmp_path / "solo.pcap"
    pcap.write_bytes(_valid_pcap("SIN_STREAM"))
    res = client_with_collector.post("/api/import", json={"path": str(pcap)})
    assert res.status_code == 200
    body = res.json()
    assert body["files"] == 1 and body["events"] == 2
    assert body["cancelled"] is False


def test_import_cancel_stops_between_files(
    client_with_collector: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancelacion a media: el import para entre ficheros y informa de los omitidos.

    El parser se ralentiza a proposito (200 ms por fichero) para que la cancelacion
    llegue mientras el import sigue vivo: sin retardo, 6 pcaps minimos se parsean
    en milisegundos y ya habria terminado.
    """
    folder = tmp_path / "muchos"
    folder.mkdir()
    for i in range(6):
        (folder / f"cap{i}.pcap").write_bytes(_valid_pcap(f"RED{i}"))

    from m5wireless.parser import pcap as pcap_module

    original_parse = pcap_module.PcapParser.parse

    def slow_parse(self, data: bytes, *, source: str = "file") -> list[object]:
        time.sleep(0.2)
        return original_parse(self, data, source=source)

    monkeypatch.setattr(pcap_module.PcapParser, "parse", slow_parse)

    summary: dict[str, object] = {}

    def run_import() -> None:
        with client_with_collector.stream(
            "POST", "/api/import", json={"path": str(folder), "stream": True}
        ) as res:
            for line in res.iter_lines():
                if not line:
                    continue
                item = json.loads(line)
                if item["type"] == "done":
                    summary.update(item)

    thread = threading.Thread(target=run_import)
    thread.start()
    time.sleep(0.5)
    cancel = client_with_collector.post("/api/import/cancel")
    assert cancel.status_code == 200
    assert cancel.json() == {"active": True, "requested": True}
    thread.join(timeout=10)

    assert summary, "el stream no cerró con el resumen"
    assert summary["cancelled"] is True
    assert 0 < summary["files"] < 6
    assert summary["skipped"] == 6 - summary["files"]
    # La lock queda libre y el flag se limpia: el siguiente import arranca normal.
    assert api_module._IMPORT_RUNNING is False
    res = client_with_collector.post("/api/import", json={"path": str(folder / "cap0.pcap")})
    assert res.status_code == 200


def test_import_cancel_with_nothing_running(client_with_collector: TestClient) -> None:
    """Cancelar sin import en curso: 200 y active=false (no es un error)."""
    res = client_with_collector.post("/api/import/cancel")
    assert res.status_code == 200
    assert res.json() == {"active": False, "requested": False}
