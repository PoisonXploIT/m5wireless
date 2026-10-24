"""Store en memoria: sin persistencia, para desarrollo y demos."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta

from ..models import (
    Client,
    Finding,
    FindingStatus,
    Network,
    ObservationEvent,
    Session,
    utc_now,
)
from .base import AbstractStore, ObservationRow, event_to_observation_row


class MemoryStore(AbstractStore):
    """Estado actual en dicts + historico append-only en una lista."""

    def __init__(self) -> None:
        self._networks: dict[str, Network] = {}
        self._clients: dict[str, Client] = {}
        self._observations: list[ObservationRow] = []
        self._sessions: dict[str, Session] = {}
        self._findings: dict[str, Finding] = {}

    # ---- escritura ----
    def upsert_network(self, network: Network, *, at: datetime) -> None:
        existing = self._networks.get(network.bssid)
        if existing is None:
            self._networks[network.bssid] = Network(
                bssid=network.bssid,
                ssid=network.ssid,
                channel=network.channel,
                rssi=network.rssi,
                first_seen=at,
                last_seen=at,
            )
        else:
            if network.ssid is not None:
                existing.ssid = network.ssid
            if network.channel is not None:
                existing.channel = network.channel
            if network.rssi is not None:
                existing.rssi = network.rssi
            existing.last_seen = at

    def upsert_client(self, client: Client, *, at: datetime) -> None:
        existing = self._clients.get(client.mac)
        if existing is None:
            self._clients[client.mac] = Client(
                mac=client.mac, bssid=client.bssid, first_seen=at, last_seen=at
            )
        else:
            # `Client` es frozen: se reconstruye con el estado actualizado.
            new_bssid = client.bssid if client.bssid is not None else existing.bssid
            self._clients[client.mac] = Client(
                mac=existing.mac,
                bssid=new_bssid,
                first_seen=existing.first_seen,
                last_seen=at,
            )

    def record_observation(self, event: ObservationEvent) -> None:
        self._observations.append(event_to_observation_row(event))

    # ---- consulta ----
    def get_network(self, bssid: str) -> Network | None:
        net = self._networks.get(bssid)
        if net is None:
            return None
        clients = {c.mac for c in self._clients.values() if c.bssid == net.bssid}
        return Network(
            bssid=net.bssid,
            ssid=net.ssid,
            channel=net.channel,
            rssi=net.rssi,
            n_clients=len(clients),
            clients=clients,
            first_seen=net.first_seen,
            last_seen=net.last_seen,
        )

    def get_client(self, mac: str) -> Client | None:
        client = self._clients.get(mac)
        if client is None:
            return None
        return Client(
            mac=client.mac,
            bssid=client.bssid,
            first_seen=client.first_seen,
            last_seen=client.last_seen,
        )

    def iter_observations(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> Iterator[ObservationRow]:
        for row in self._observations:
            if since is not None and row.timestamp < since:
                continue
            if until is not None and row.timestamp > until:
                continue
            yield row

    def get_recent_observations(self, limit: int) -> list[ObservationRow]:
        if limit <= 0:
            return []
        # De la mas antigua a la mas reciente (orden cronologico).
        return list(self._observations[-limit:])

    def get_networks(
        self, *, since: datetime | None = None, until: datetime | None = None
    ) -> list[Network]:
        result: list[Network] = []
        for net in self._networks.values():
            if since is not None and net.last_seen < since:
                continue
            if until is not None and net.last_seen > until:
                continue
            clients = {c.mac for c in self._clients.values() if c.bssid == net.bssid}
            result.append(
                Network(
                    bssid=net.bssid,
                    ssid=net.ssid,
                    channel=net.channel,
                    rssi=net.rssi,
                    n_clients=len(clients),
                    clients=clients,
                    first_seen=net.first_seen,
                    last_seen=net.last_seen,
                )
            )
        return result

    def get_clients(self, *, associated_to: str | None = None) -> list[Client]:
        out: list[Client] = []
        for c in self._clients.values():
            if associated_to is not None and c.bssid != associated_to:
                continue
            out.append(
                Client(mac=c.mac, bssid=c.bssid, first_seen=c.first_seen, last_seen=c.last_seen)
            )
        return out

    def get_network_history(
        self,
        bssid: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[ObservationRow]:
        rows: list[ObservationRow] = []
        for row in self._observations:
            if row.bssid != bssid:
                continue
            if since is not None and row.timestamp < since:
                continue
            if until is not None and row.timestamp > until:
                continue
            rows.append(row)
        return rows

    def get_channel_distribution(self) -> dict[int, int]:
        dist: dict[int, int] = {}
        for net in self._networks.values():
            if net.channel is not None:
                dist[net.channel] = dist.get(net.channel, 0) + 1
        return dist

    # ---- sesiones y hallazgos ----
    def save_session(self, session: Session) -> None:
        self._sessions[session.id] = session

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def list_sessions(self, *, estado: str | None = None) -> list[Session]:
        return [s for s in self._sessions.values() if estado is None or s.estado == estado]

    def save_finding(self, finding: Finding) -> None:
        existing = self._findings.get(finding.id)
        if existing is not None:
            # Re-evaluacion de la misma regla sobre el mismo activo: se actualiza
            # la evidencia, pero NO se pierde el triaje ya decidido.
            finding = Finding(
                id=finding.id,
                session_id=finding.session_id,
                rule_id=finding.rule_id,
                rule_version=finding.rule_version,
                severidad=finding.severidad,
                titulo=finding.titulo,
                activo=finding.activo,
                evidencia=finding.evidencia,
                recomendacion=finding.recomendacion,
                estado=existing.estado,
                creado=existing.creado,
            )
        self._findings[finding.id] = finding

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def list_findings(
        self,
        *,
        session_id: str | None = None,
        severidad: str | None = None,
        estado: str | None = None,
    ) -> list[Finding]:
        out: list[Finding] = []
        for f in self._findings.values():
            if session_id is not None and f.session_id != session_id:
                continue
            if severidad is not None and f.severidad != severidad:
                continue
            if estado is not None and f.estado != estado:
                continue
            out.append(f)
        return out

    def update_finding(self, finding_id: str, *, estado: FindingStatus) -> Finding | None:
        existing = self._findings.get(finding_id)
        if existing is None:
            return None
        updated = Finding(
            id=existing.id,
            session_id=existing.session_id,
            rule_id=existing.rule_id,
            rule_version=existing.rule_version,
            severidad=existing.severidad,
            titulo=existing.titulo,
            activo=existing.activo,
            evidencia=existing.evidencia,
            recomendacion=existing.recomendacion,
            estado=estado,
            creado=existing.creado,
        )
        self._findings[finding_id] = updated
        return updated

    # ---- mantenimiento ----
    def prune_older_than(self, days: int, *, reference: datetime | None = None) -> int:
        ref = reference if reference is not None else utc_now()
        cutoff = ref - timedelta(days=days)
        before = len(self._observations)
        self._observations = [r for r in self._observations if r.timestamp >= cutoff]
        return before - len(self._observations)
