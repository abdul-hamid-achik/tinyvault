/**
 * Captures an icon button in its hover state, with its tooltip open, so hover
 * depth and tooltip rendering can be verified visually instead of assumed.
 *
 * Synthetic CDP mouse moves do not update :hover in this Electron build, so the
 * hover styling is forced with CSS.forcePseudoState (a legitimate inspection
 * technique) and the tooltip is triggered with a real bubbling mouseover, which
 * is what React's onMouseEnter listens to.
 *
 * Requires the app launched with --remote-debugging-port=9222. Uses Node's
 * built-in WebSocket against CDP directly — no Playwright, no extra deps.
 *
 *   node scripts/shot-hover.mjs [css-selector] [out.png]
 *
 * The debug port is a local attack surface; only run this against a throwaway
 * instance and close it right after.
 */
import { writeFileSync } from "node:fs";

const SELECTOR = process.argv[2] ?? '[aria-label="Edit value"]';
const OUT = process.argv[3] ?? "/tmp/tv-hover.png";
const CDP = "http://127.0.0.1:9222";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  let page = null;
  for (let i = 0; i < 30 && !page; i++) {
    try {
      const targets = await (await fetch(`${CDP}/json`)).json();
      page = targets.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
    } catch {
      /* not up yet */
    }
    if (!page) await sleep(500);
  }
  if (!page) throw new Error("no debuggable page target on :9222");

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error("cdp websocket failed"));
  });

  let nextId = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id === undefined || !pending.has(msg.id)) return;
    const entry = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) entry.reject(new Error(JSON.stringify(msg.error)));
    else entry.resolve(msg.result);
  };
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });

  await send("Page.enable");
  await send("Runtime.enable");
  await send("DOM.enable");
  await send("CSS.enable");

  // Wait for the app to mount and render rows.
  let found = null;
  for (let i = 0; i < 40 && !found; i++) {
    const { root } = await send("DOM.getDocument");
    const { nodeId } = await send("DOM.querySelector", {
      nodeId: root.nodeId,
      selector: SELECTOR
    });
    found = nodeId || null;
    if (!found) await sleep(500);
  }
  if (!found) throw new Error(`selector not found in the page: ${SELECTOR}`);

  // Force :hover on the button and on its row, so the row's group-hover
  // (actions fading in from opacity-40) is visible too.
  await send("CSS.forcePseudoState", { nodeId: found, forcedPseudoClasses: ["hover"] });
  const { root } = await send("DOM.getDocument");
  const { nodeId: rowId } = await send("DOM.querySelector", {
    nodeId: root.nodeId,
    selector: "tr.group"
  });
  if (rowId) {
    await send("CSS.forcePseudoState", { nodeId: rowId, forcedPseudoClasses: ["hover"] });
  }

  // Real bubbling mouseover: what React's onMouseEnter (the tooltip trigger)
  // actually listens to.
  await send("Runtime.evaluate", {
    expression: `(() => {
      const el = document.querySelector(${JSON.stringify(SELECTOR)});
      if (!el) return false;
      el.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
      return true;
    })()`
  });

  // Tooltip delay is 350ms; let the entrance animation settle.
  await sleep(800);

  const shot = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(OUT, Buffer.from(shot.data, "base64"));
  console.log(`forced hover + tooltip on ${SELECTOR} → ${OUT}`);

  ws.close();
}

main().catch((err) => {
  console.error("shot-hover failed:", err.message);
  process.exit(1);
});
