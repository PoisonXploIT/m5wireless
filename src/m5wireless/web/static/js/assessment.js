/* m5wireless - consola de evaluacion (Paso 5).
   Vanilla JS, sin frameworks. Habla con /api/sessions, /api/findings,
   /api/sessions/{id}/close, /api/sessions/{id}/report y /api/sessions/{id}/evidence.
   La autenticacion va por la cookie `m5w_ui` que siembra el servidor en /evaluacion. */

"use strict";

const SEVERITY_ORDER = ["alta", "media", "baja", "info"];
const TRIAGE_STATES = ["abierto", "aceptado", "falso_positivo", "corregido"];

const state = {
  sessionId: null,
  session: null,
  findings: [],
  catalogVersion: 0,
  integrity: null,
};

const $ = (id) => document.getElementById(id);

function toast(message, kind = "info") {
  const host = $("toasts");
  if (!host) return;
  const item = document.createElement("div");
  item.className = `toast toast-${kind}`;
  item.textContent = message;
  host.appendChild(item);
  setTimeout(() => item.remove(), 4000);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body && body.detail) detail = String(body.detail);
    } catch (error) {
      /* respuesta no JSON */
    }
    throw new Error(detail);
  }
  return res.json();
}

function escapeText(value) {
  return String(value === null || value === undefined ? "" : value);
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("es", { dateStyle: "medium", timeStyle: "short" });
}

/* ---------- sesion ---------- */

function renderSession(session) {
  state.session = session;
  state.sessionId = session ? session.id : null;
  const status = $("session-status");
  const meta = $("session-meta");
  if (!session) {
    status.textContent = "sesion: sin crear";
    status.className = "status status-offline";
    meta.textContent = "sin sesion";
    $("session-close").disabled = true;
    return;
  }
  status.textContent = `sesion: ${session.id} (${session.estado})`;
  status.className = session.estado === "cerrada" ? "status status-online" : "status status-warn";
  meta.textContent = [
    session.nombre,
    session.cliente || "sin cliente",
    session.operador || "sin operador",
    session.source,
    `inicio ${formatDateTime(session.inicio)}`,
    session.fin ? `fin ${formatDateTime(session.fin)}` : "en curso",
  ].join(" - ");
  $("session-close").disabled = session.estado === "cerrada";
  $("report-md").href = `/api/sessions/${session.id}/report?fmt=md`;
  $("report-html").href = `/api/sessions/${session.id}/report?fmt=html`;
  const select = $("session-select");
  if (select) select.value = session.id;
}

function populateSessionSelect(sessions) {
  const select = $("session-select");
  select.textContent = "";
  const option = document.createElement("option");
  option.value = "";
  option.textContent = "ninguna";
  select.appendChild(option);
  sessions.forEach((session) => {
    const item = document.createElement("option");
    item.value = session.id;
    item.textContent = `${session.id} - ${session.nombre} (${session.estado})`;
    select.appendChild(item);
  });
}

async function loadSessions() {
  const data = await api("/api/sessions");
  populateSessionSelect(data.sessions);
  renderSession(data.live || data.sessions[0] || null);
}

async function createSession(event) {
  event.preventDefault();
  const payload = {
    nombre: $("session-nombre").value.trim(),
    cliente: $("session-cliente").value.trim(),
    operador: $("session-operador").value.trim(),
    lugar: $("session-lugar").value.trim(),
    alcance: $("session-alcance").value.trim(),
    source: $("session-source").value,
  };
  if (!payload.nombre) {
    toast("El nombre de la sesion es obligatorio", "warn");
    return;
  }
  try {
    const session = await api("/api/sessions", { method: "POST", body: JSON.stringify(payload) });
    renderSession(session);
    toast(`Sesion creada: ${session.id}`, "ok");
    await refreshFindings();
  } catch (error) {
    toast(`No se pudo crear la sesion: ${error.message}`, "warn");
  }
}

async function closeSession() {
  if (!state.sessionId) return;
  try {
    const session = await api(`/api/sessions/${state.sessionId}/close`, { method: "POST" });
    renderSession(session);
    toast("Sesion cerrada: reglas evaluadas e informe generado", "ok");
    await refreshFindings();
    await refreshEvidence();
  } catch (error) {
    toast(`No se pudo cerrar la sesion: ${error.message}`, "warn");
  }
}

async function selectSession(sessionId) {
  if (!sessionId) {
    state.session = null;
    state.sessionId = null;
    renderSession(null);
    await refreshFindings();
    return;
  }
  try {
    const session = await api(`/api/sessions/${sessionId}`);
    renderSession(session);
    await refreshFindings();
    await refreshEvidence();
  } catch (error) {
    toast(`No se pudo cargar la sesion: ${error.message}`, "warn");
  }
}

/* ---------- hallazgos ---------- */

function activeLabel(activo) {
  if (!activo) return "";
  const parts = [];
  if (activo.bssid) parts.push(`BSSID ${activo.bssid}`);
  if (activo.ssid) parts.push(`SSID ${activo.ssid}`);
  if (activo.client_mac) parts.push(`cliente ${activo.client_mac}`);
  if (activo.channel) parts.push(`canal ${activo.channel}`);
  return parts.join(" - ");
}

function findingItem(finding) {
  const li = document.createElement("li");
  li.className = `finding finding-${finding.severidad} estado-${finding.estado}`;

  const head = document.createElement("div");
  head.className = "finding-head";
  const sev = document.createElement("span");
  sev.className = `sev sev-${finding.severidad}`;
  sev.textContent = finding.severidad;
  const title = document.createElement("h3");
  title.textContent = finding.titulo;
  head.appendChild(sev);
  head.appendChild(title);
  li.appendChild(head);

  const meta = document.createElement("p");
  meta.className = "finding-meta mono";
  meta.textContent = `${finding.rule_id} v${finding.rule_version} - ${activeLabel(finding.activo)}`;
  li.appendChild(meta);

  const evidence = document.createElement("p");
  evidence.className = "finding-evidence";
  const entries = Object.entries(finding.evidencia || {});
  evidence.textContent = entries
    .map(([key, value]) => `${key}: ${typeof value === "object" ? JSON.stringify(value) : value}`)
    .join(" | ");
  li.appendChild(evidence);

  const rec = document.createElement("p");
  rec.className = "finding-rec";
  rec.textContent = `Recomendacion: ${finding.recomendacion}`;
  li.appendChild(rec);

  const group = document.createElement("div");
  group.className = "triage";
  group.setAttribute("role", "group");
  group.setAttribute("aria-label", `Triaje del hallazgo ${finding.rule_id}`);
  TRIAGE_STATES.forEach((estado) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-sm" + (finding.estado === estado ? " is-on" : "");
    button.setAttribute("aria-pressed", finding.estado === estado ? "true" : "false");
    button.textContent = estado.replace("_", " ");
    button.addEventListener("click", () => triage(finding.id, estado));
    group.appendChild(button);
  });
  li.appendChild(group);
  return li;
}

async function refreshFindings() {
  const severidad = $("filter-severidad").value;
  const estado = $("filter-estado").value;
  const query = new URLSearchParams();
  if (severidad) query.set("severidad", severidad);
  if (estado) query.set("estado", estado);
  const url = state.sessionId
    ? `/api/sessions/${state.sessionId}/findings?${query.toString()}`
    : `/api/findings?${query.toString()}`;
  const data = await api(url);
  state.findings = data.findings;
  state.catalogVersion = data.catalog_version;
  renderCounters(data.findings);
  const list = $("findings-list");
  list.textContent = "";
  data.findings.forEach((finding) => list.appendChild(findingItem(finding)));
  $("findings-empty").hidden = data.total > 0;
}

function renderCounters(findings) {
  const bySeverity = { alta: 0, media: 0, baja: 0, info: 0 };
  findings.forEach((finding) => {
    if (bySeverity[finding.severidad] !== undefined) bySeverity[finding.severidad] += 1;
  });
  $("count-total").textContent = String(findings.length);
  SEVERITY_ORDER.forEach((severity) => {
    const node = $(`count-${severity}`);
    if (node) node.textContent = String(bySeverity[severity] || 0);
  });
  $("count-open").textContent = String(findings.filter((f) => f.estado === "abierto").length);
}

async function triage(findingId, estado) {
  try {
    const updated = await api(`/api/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ estado }),
    });
    state.findings = state.findings.map((f) => (f.id === updated.id ? updated : f));
    toast(`Hallazgo ${updated.rule_id} marcado como ${estado.replace("_", " ")}`, "ok");
    renderCounters(state.findings);
    const list = $("findings-list");
    list.textContent = "";
    state.findings.forEach((finding) => list.appendChild(findingItem(finding)));
  } catch (error) {
    toast(`No se pudo triar el hallazgo: ${error.message}`, "warn");
  }
}

/* ---------- informe y evidencia ---------- */

async function generateReport() {
  if (!state.sessionId) {
    toast("Primero crea una sesion", "warn");
    return;
  }
  try {
    const data = await api(`/api/sessions/${state.sessionId}/report?fmt=md,html`, { method: "POST" });
    state.integrity = data.integrity;
    renderIntegrity(data.integrity);
    toast(`Informe generado (${data.formats.join(", ")})`, "ok");
    await refreshEvidence();
  } catch (error) {
    toast(`No se pudo generar el informe: ${error.message}`, "warn");
  }
}

function renderIntegrity(integrity) {
  const node = $("integrity");
  if (!integrity) {
    node.textContent = "Integridad: sin verificar";
    node.className = "integrity";
    return;
  }
  node.textContent = integrity.ok
    ? "Integridad: verificada (hashes de evidencia coinciden)"
    : `Integridad: problemas (${(integrity.problems || []).length})`;
  node.className = integrity.ok ? "integrity integrity-ok" : "integrity integrity-bad";
}

async function refreshEvidence() {
  if (!state.sessionId) return;
  try {
    const evidence = await api(`/api/sessions/${state.sessionId}/evidence`);
    const body = $("evidence-body");
    body.textContent = "";
    (evidence.hashes || []).forEach((artifact) => {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      name.textContent = artifact.nombre;
      const hash = document.createElement("td");
      hash.className = "mono";
      hash.textContent = artifact.sha256;
      const size = document.createElement("td");
      size.textContent = String(artifact.bytes);
      const status = document.createElement("td");
      status.textContent = artifact.ok === false ? "hash no coincide" : "verificado";
      row.appendChild(name);
      row.appendChild(hash);
      row.appendChild(size);
      row.appendChild(status);
      body.appendChild(row);
    });
    renderIntegrity(evidence.integrity || null);
  } catch (error) {
    toast(`No se pudo leer la evidencia: ${error.message}`, "warn");
  }
}

/* ---------- arranque ---------- */

$("session-form").addEventListener("submit", createSession);
$("session-close").addEventListener("click", closeSession);
$("session-select").addEventListener("change", (event) => selectSession(event.target.value));
$("report-generate").addEventListener("click", generateReport);
$("filter-severidad").addEventListener("change", refreshFindings);
$("filter-estado").addEventListener("change", refreshFindings);

loadSessions()
  .then(refreshFindings)
  .catch((error) => toast(`No se pudo cargar la evaluacion: ${error.message}`, "warn"));
