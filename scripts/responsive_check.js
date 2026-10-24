// Comprobacion de desbordamiento horizontal a un ancho dado (390 px es el
// objetivo del Paso 5). Uso:
//   node scripts/responsive_check.js http://127.0.0.1:8012/evaluacion 390
// Requiere Chrome con --remote-debugging-port=9222.

const CDP = process.env.M5W_CDP || "http://127.0.0.1:9222";
const url = process.argv[2] || "http://127.0.0.1:8012/evaluacion";
const width = Number(process.argv[3] || 390);

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
  send(ws, 2, "Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: true });
  await wait(ws, 2);
  send(ws, 3, "Page.navigate", { url });
  await wait(ws, 3);
  await new Promise((resolve) => setTimeout(resolve, 3000));

  send(ws, 4, "Runtime.evaluate", {
    expression: "(() => {" +
      "  const insideScroller = (el) => {" +
      "    let node = el;" +
      "    while (node && node !== document.body) {" +
      "      const style = getComputedStyle(node);" +
      "      if (style.overflowX === 'auto' || style.overflowX === 'scroll') return true;" +
      "      node = node.parentElement;" +
      "    }" +
      "    return false;" +
      "  };" +
      "  const overflow = [];" +
      "  document.querySelectorAll('*').forEach((el) => {" +
      "    const rect = el.getBoundingClientRect();" +
      "    if (rect.right > " + width + " + 1 && !insideScroller(el)) {" +
      "      overflow.push(el.tagName + '.' + (el.className || '') + ' right=' + Math.round(rect.right));" +
      "    }" +
      "  });" +
      "  return JSON.stringify({" +
      "    viewport: window.innerWidth," +
      "    scrollWidth: document.documentElement.scrollWidth," +
      "    overflowCount: overflow.length," +
      "    sample: overflow.slice(0, 8)," +
      "  });" +
      "})()",
  });
  const result = await wait(ws, 4, 30000);
  const value = result.result && result.result.result ? result.result.result.value : "{}";
  console.log(value);
  const data = JSON.parse(value);
  ws.close();
  if (data.scrollWidth > width || data.overflowCount > 0) {
    console.log(`desbordamiento a ${width} px: SI`);
    process.exitCode = 1;
  } else {
    console.log(`desbordamiento a ${width} px: NO`);
  }
}

main().catch((error) => {
  console.error("responsive_check fallo:", error.message);
  process.exitCode = 2;
});
