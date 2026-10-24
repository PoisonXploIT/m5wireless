"""Gestion de sesiones de evaluacion (Fase A, paso 1).

Una sesion vive en dos sitios:

- **el store** (memoria o SQLite): filas `sessions` y `findings`, para consultar
  y filtrar.
- **la carpeta `data/sessions/<id>/`**: `session.json`, `findings.json`,
  `report.md`, `report.html`, `artifacts/` y `hashes.json`. Esta carpeta es la
  evidencia portable; esta gitignored y es lo que se entrega al cliente.

Escritura atomica: se escribe a un fichero temporal y se renombra. Un `SIGINT`
a mitad de escritura no deja un `session.json` truncado.

La **sesion viva** (`<fecha>-viva`) se crea de forma implicita cuando alguien
usa la CLI o la API sin crear una sesion explicita: mantiene la compatibilidad
con el flujo actual de "visor de logs" sin obligar a nadie a cambiar su forma
de trabajar.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Artifact, Finding, Session, SessionSource, make_session_id, utc_now
from .store import AbstractStore

DEFAULT_SESSIONS_ROOT = Path("data/sessions")
LIVE_SESSION_SUFFIX = "viva"


def session_dir(root: Path | str, session_id: str) -> Path:
    """Ruta de la carpeta de una sesion (la crea si no existe)."""
    path = Path(root) / session_id
    path.mkdir(parents=True, exist_ok=True)
    (path / "artifacts").mkdir(exist_ok=True)
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, payload: Any) -> None:
    """Escribir JSON de forma atomica (tmp + rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
    ) as handle:
        handle.write(text)
        tmp = handle.name
    os.replace(tmp, path)


def hash_artifacts(directory: Path) -> list[Artifact]:
    """Hash SHA-256 de todos los ficheros de la carpeta `artifacts/`."""
    artifacts: list[Artifact] = []
    if not directory.is_dir():
        return artifacts
    for file in sorted(directory.iterdir()):
        if not file.is_file():
            continue
        artifacts.append(
            Artifact(
                nombre=file.name,
                ruta=file.relative_to(directory.parent).as_posix(),
                sha256=sha256_file(file),
                bytes=file.stat().st_size,
            )
        )
    return artifacts


def create_session(
    store: AbstractStore,
    nombre: str,
    *,
    root: Path | str = DEFAULT_SESSIONS_ROOT,
    cliente: str = "",
    operador: str = "",
    lugar: str = "",
    alcance: str = "",
    dispositivo: str = "",
    source: SessionSource = "file",
    version_app: str = "",
    inicio: datetime | None = None,
    session_id: str | None = None,
) -> Session:
    """Crear una sesion abierta: fila en el store + `session.json` en disco."""
    start = inicio or utc_now()
    session = Session(
        id=session_id or make_session_id(nombre, start),
        nombre=nombre,
        cliente=cliente,
        operador=operador,
        lugar=lugar,
        alcance=alcance,
        dispositivo=dispositivo,
        source=source,
        inicio=start,
        estado="abierta",
        version_app=version_app,
    )
    store.save_session(session)
    directory = session_dir(root, session.id)
    write_json_atomic(directory / "session.json", _session_payload(session))
    (directory / "artifacts").mkdir(exist_ok=True)
    return session


def close_session(
    store: AbstractStore,
    session_id: str,
    *,
    root: Path | str = DEFAULT_SESSIONS_ROOT,
    closed_at: datetime | None = None,
    findings: tuple[Finding, ...] = (),
) -> Session:
    """Cerrar la sesion: fecha de fin, hallazgos e inventario de evidencia.

    Devuelve la sesion ya cerrada. Si no existe, lanza KeyError (el llamador
    decide si eso es un error de usuario o un 404).
    """
    session = store.get_session(session_id)
    if session is None:
        raise KeyError(f"sesion no encontrada: {session_id}")
    if session.estado == "cerrada":
        return session

    directory = session_dir(root, session_id)
    artifacts = tuple(hash_artifacts(directory / "artifacts"))
    closed = Session(
        id=session.id,
        nombre=session.nombre,
        cliente=session.cliente,
        operador=session.operador,
        lugar=session.lugar,
        alcance=session.alcance,
        dispositivo=session.dispositivo,
        source=session.source,
        inicio=session.inicio,
        fin=closed_at or utc_now(),
        estado="cerrada",
        version_app=session.version_app,
        artifacts=artifacts,
    )
    store.save_session(closed)
    for finding in findings:
        store.save_finding(finding)
    write_json_atomic(directory / "session.json", _session_payload(closed))
    write_json_atomic(
        directory / "findings.json",
        [
            _finding_payload(f)
            for f in sorted(store.list_findings(session_id=session_id), key=lambda f: f.id)
        ],
    )
    write_json_atomic(
        directory / "hashes.json",
        {
            "generated": utc_now().isoformat(),
            "algorithm": "sha256",
            "session_id": session_id,
            "artifacts": [asdict(a) for a in artifacts],
        },
    )
    return closed


def get_live_session(
    store: AbstractStore,
    *,
    root: Path | str = DEFAULT_SESSIONS_ROOT,
    version_app: str = "",
) -> Session:
    """Sesion viva implicita: la que usa quien no crea una explicita."""
    session_id = f"{utc_now():%Y%m%d}-{LIVE_SESSION_SUFFIX}"
    existing = store.get_session(session_id)
    if existing is not None:
        return existing
    return create_session(
        store,
        nombre="Sesion viva",
        root=root,
        source="file",
        version_app=version_app,
        session_id=session_id,
    )


def _session_payload(session: Session) -> dict[str, Any]:
    return {
        "id": session.id,
        "nombre": session.nombre,
        "cliente": session.cliente,
        "operador": session.operador,
        "lugar": session.lugar,
        "alcance": session.alcance,
        "dispositivo": session.dispositivo,
        "source": session.source,
        "inicio": session.inicio.isoformat(),
        "fin": session.fin.isoformat() if session.fin is not None else None,
        "estado": session.estado,
        "version_app": session.version_app,
        "artifacts": [asdict(a) for a in session.artifacts],
    }


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "session_id": finding.session_id,
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "severidad": finding.severidad,
        "titulo": finding.titulo,
        "activo": {k: v for k, v in asdict(finding.activo).items() if v is not None},
        "evidencia": finding.evidencia,
        "recomendacion": finding.recomendacion,
        "estado": finding.estado,
        "creado": finding.creado.isoformat(),
    }
