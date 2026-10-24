// Contraste WCAG real de los textos renderados, medido con CDP (no axe).
// axe-core no mide contraste si el tema no esta activo en la captura; aqui se
// calcula a partir del color y el fondo computados de cada elemento de texto.
// Uso:
//   node scripts/contrast_check.js http://127.0.0.1:8013/evaluacion 390

const CDP = process.env.M5W_CDP || "http://127.0.0.1:9222";
const url = process.argv[2] || "http://127.0.0.1:8013/evaluacion";
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

const EXPRESSION = `(() => {
  const parse = (value) => {
    const match = value.match(/rgba?\\(([^)]+)\\)/);
    if (!match) return null;
    const parts = match[1].split(',').map((n) => parseFloat(n));
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const luminance = (c) => {
    const channel = (v) => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b);
  };
  const ratio = (a, b) => {
    const hi = Math.max(luminance(a), luminance(b));
    const lo = Math.min(luminance(a), luminance(b));
    return (hi + 0.05) / (lo + 0.05);
  };
  const background = (el) => {
    let node = el;
    while (node) {
      const color = getComputedStyle(node).backgroundColor;
      const parsed = parse(color);
      if (parsed && parsed.a > 0.05) return parsed;
      node = node.parentElement;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  };
  const offenders = [];
  const samples = [];
  document.querySelectorAll('*').forEach((el) => {
    const text = (el.textContent || '').trim();
    if (!text) return;
    const children = Array.from(el.children).some((c) => (c.textContent || '').trim());
    if (children) return;
    const style = getComputedStyle(el);
    const fg = parse(style.color);
    if (!fg) return;
    const bg = background(el);
    const value = ratio(fg, bg);
    const size = parseFloat(style.fontSize);
    const bold = parseInt(style.fontWeight || '400', 10) >= 700;
    const threshold = size >= 18 || (size >= 14 && bold) ? 3 : 4.5;
    const record = {
      tag: el.tagName.toLowerCase(),
      cls: el.className || '',
      text: text.slice(0, 40),
      ratio: Math.round(value * 100) / 100,
      threshold: threshold,
      size: size,
    };
    samples.push(record);
    if (value < threshold) offenders.push(record);
  });
  const minimum = samples.reduce((min, item) => Math.min(min, item.ratio), 99);
  return JSON.stringify({ viewport: window.innerWidth, checked: samples.length, minimum: minimum, offenders: offenders.slice(0, 10) });
})()`;

async function main() {
  const targets = await fetch(`${CDP}/json`).then((r) => r.json());
  const created =
    targets.find((t) => t.type === "page" && t.url === url) ||
    targets.find((t) => t.type === "page") ||
    (await fetch(`${CDP}/json/new?url=${encodeURIComponent(url)}`, { method: "PUT" }).then((r) => r.json()));
  const ws = new WebSocket(created.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve);
    ws.addEventListener("error", reject);
  });

  send(ws, 1, "Page.enable");
  await wait(ws, 1);
  send(ws, 2, "Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await wait(ws, 2);
  send(ws, 3, "Page.navigate", { url });
  await wait(ws, 3);
  await new Promise((resolve) => setTimeout(resolve, 2000));
  // El override se vuelve a aplicar tras la navegacion: algunas versiones de
  // Chrome lo ignoran si se fija antes de cargar la pagina.
  send(ws, 5, "Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await wait(ws, 5);
  await new Promise((resolve) => setTimeout(resolve, 1500));

  send(ws, 4, "Runtime.evaluate", { expression: EXPRESSION });
  const result = await wait(ws, 4, 30000);
  const value = result.result && result.result.result ? result.result.result.value : "{}";
  const data = JSON.parse(value);
  ws.close();
  console.log(value);
  if (data.offenders.length) {
    console.log(`contraste: ${data.offenders.length} elementos por debajo del umbral WCAG`);
    process.exitCode = 1;
  } else {
    console.log(`contraste: OK (minimo ${data.minimum} sobre ${data.checked} elementos)`);
  }
}

main().catch((error) => {
  console.error("contrast_check fallo:", error.message);
  process.exitCode = 2;
});
