// Paso 5: verificacion axe-core de la consola de evaluacion.
//
// Requiere Chrome con depuracion remota y un servidor m5wireless accesible:
//   chrome --headless=new --remote-debugging-port=9222 about:blank
//   node scripts/axe_check.js http://127.0.0.1:8010/evaluacion
//
// No necesita Playwright: habla con Chrome por el DevTools Protocol (CDP)
// y ejecuta axe-core dentro de la pagina cargada.

const fs = require("node:fs");
const path = require("node:path");

const AXE_PATH = path.join(process.cwd(), "node_modules/axe-core/axe.min.js");
const CDP = process.env.M5W_CDP || "http://127.0.0.1:9222";
const url = process.argv[2] || "http://127.0.0.1:8010/evaluacion";

function cdpSend(ws, id, method, params = {}) {
  ws.send(JSON.stringify({ id, method, params }));
}

function cdpWait(ws, id, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.removeEventListener("message", handler);
      reject(new Error(`CDP timeout para id ${id}`));
    }, timeoutMs);
    function handler(event) {
      const message = JSON.parse(String(event.data));
      if (message.id === id) {
        clearTimeout(timer);
        ws.removeEventListener("message", handler);
        resolve(message);
      }
    }
    ws.addEventListener("message", handler);
  });
}

async function main() {
  const axeSource = fs.readFileSync(AXE_PATH, "utf8");

  const created = await fetch(`${CDP}/json/new?url=${encodeURIComponent(url)}`, { method: "PUT" }).then((r) => r.json());
  if (!created || !created.webSocketDebuggerUrl) {
    throw new Error("No se pudo abrir una pagina en Chrome (arranca chrome --headless --remote-debugging-port=9222)");
  }

  const ws = new WebSocket(created.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve);
    ws.addEventListener("error", reject);
  });

  cdpSend(ws, 1, "Page.enable");
  await cdpWait(ws, 1);

  cdpSend(ws, 2, "Page.navigate", { url });
  await cdpWait(ws, 2);

  // Esperar a que el JS renderice la sesion viva.
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // Forzar la seleccion de una sesion cerrada para que axe vea hallazgos reales.
  cdpSend(ws, 3, "Runtime.evaluate", {
    expression: "(() => { const sel = document.getElementById('session-select'); const closed = [...sel.options].map(o => o.value).filter(v => v && !v.endsWith('-viva')); if (closed.length) { sel.value = closed[0]; sel.dispatchEvent(new Event('change')); } return closed.length; })()",
  });
  await cdpWait(ws, 3, 20000);
  await new Promise((resolve) => setTimeout(resolve, 2000));

  cdpSend(ws, 4, "Runtime.evaluate", {
    expression: "JSON.stringify({ hallazgos: document.querySelectorAll('.finding').length, total: document.getElementById('count-total').textContent, evidencia: document.querySelectorAll('#evidence-body tr').length, integridad: document.getElementById('integrity').textContent })",
  });
  const counts = await cdpWait(ws, 4, 20000);
  console.log("renderizado:", counts.result && counts.result.result ? counts.result.result.value : "(sin datos)");

  cdpSend(ws, 5, "Runtime.evaluate", { expression: axeSource });
  await cdpWait(ws, 5, 20000);

  cdpSend(ws, 6, "Runtime.evaluate", {
    expression: "axe.run(document, { reportLevel: 'violations' }).then(r => JSON.stringify(r.violations))",
    awaitPromise: true,
    returnValues: true,
  });
  const result = await cdpWait(ws, 6, 60000);
  const raw = result.result && result.result.result ? result.result.result.value : "[]";
  const violations = JSON.parse(raw);

  if (!violations.length) {
    console.log("axe: 0 violaciones");
    ws.close();
    return;
  }

  console.log(`axe: ${violations.length} violaciones`);
  for (const violation of violations) {
    console.log(`- [${violation.impact}] ${violation.id} (${violation.nodes.length} nodo/s)`);
    for (const node of violation.nodes.slice(0, 3)) {
      const target = node.target ? node.target.join(" ") : node.html;
      console.log(`    ${target}`);
    }
  }
  ws.close();
  process.exitCode = 1;
}

main().catch((error) => {
  console.error("axe_check fallo:", error.message);
  process.exitCode = 2;
});
