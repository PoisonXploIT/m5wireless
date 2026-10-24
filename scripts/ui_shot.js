// Captura de pantalla de una pagina de m5wireless a un ancho dado (prueba
// visual de responsive). Uso:
//   node scripts/ui_shot.js http://127.0.0.1:8012/evaluacion 390 shot.png
// Requiere Chrome con --remote-debugging-port=9222.

const CDP = process.env.M5W_CDP || "http://127.0.0.1:9222";
const url = process.argv[2] || "http://127.0.0.1:8012/evaluacion";
const width = Number(process.argv[3] || 390);
const out = process.argv[4] || "shot.png";

function send(ws, id, method, params = {}) {
  ws.send(JSON.stringify({ id, method, params }));
}

function wait(ws, id, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`CDP timeout ${id}`)), timeoutMs);
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
  const created = await fetch(`${CDP}/json/new?url=${encodeURIComponent(url)}`, { method: "PUT" }).then((r) => r.json());
  const ws = new WebSocket(created.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve);
    ws.addEventListener("error", reject);
  });

  send(ws, 1, "Page.enable");
  await wait(ws, 1);
  send(ws, 2, "Emulation.setDeviceMetricsOverride", {
    width,
    height: 900,
    deviceScaleFactor: 1,
    mobile: true,
  });
  await wait(ws, 2);
  send(ws, 3, "Page.navigate", { url });
  await wait(ws, 3);
  await new Promise((resolve) => setTimeout(resolve, 3000));
  send(ws, 4, "Page.captureScreenshot", { format: "png" });
  const shot = await wait(ws, 4, 30000);
  const data = shot.result && shot.result.data;
  require("node:fs").writeFileSync(out, Buffer.from(data, "base64"));
  console.log(`captura ${width}px -> ${out}`);
  ws.close();
}

main().catch((error) => {
  console.error("ui_shot fallo:", error.message);
  process.exitCode = 2;
});
