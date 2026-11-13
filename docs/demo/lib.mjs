import { chromium } from "playwright-core";
import fs from "fs";
export const CHROME = process.env.PLAYWRIGHT_CHROME; // ruta al ejecutable de Chromium/Chrome (p. ej. el de ~/.cache/ms-playwright)
export const W = 1280, H = 720;

// Overlay: subtítulo inferior + cursor visible (en headless el puntero no sale en el video)
const OVERLAY = `(() => {
  const add = () => {
    if (document.getElementById("__cap")) return;
    const st = document.createElement("style");
    st.textContent = \`
      #__cap{position:fixed;left:0;right:0;bottom:0;z-index:2147483647;padding:14px 28px;font:600 20px/1.35 system-ui,sans-serif;color:#fff;
        background:linear-gradient(90deg,rgba(30,41,99,.96),rgba(30,64,175,.96));text-align:center;transition:opacity .35s;pointer-events:none}
      #__cap small{display:block;font-weight:400;font-size:14px;opacity:.85;margin-top:2px}
      #__cur{position:fixed;z-index:2147483647;width:22px;height:22px;border-radius:50%;background:rgba(239,68,68,.55);border:2px solid #fff;
        box-shadow:0 0 0 2px rgba(239,68,68,.7);pointer-events:none;transform:translate(-50%,-50%);transition:transform .08s}
      #__cur.click{transform:translate(-50%,-50%) scale(.6)}\`;
    document.documentElement.appendChild(st);
    const c = document.createElement("div"); c.id = "__cap"; c.style.opacity = 0; document.documentElement.appendChild(c);
    const k = document.createElement("div"); k.id = "__cur"; k.style.left = "-50px"; k.style.top = "-50px"; document.documentElement.appendChild(k);
    document.addEventListener("mousemove", e => { k.style.left = e.clientX + "px"; k.style.top = e.clientY + "px"; }, true);
    document.addEventListener("mousedown", () => k.classList.add("click"), true);
    document.addEventListener("mouseup", () => k.classList.remove("click"), true);
    window.__caption = (t, s) => { c.style.opacity = t ? 1 : 0; if (t) c.innerHTML = t + (s ? "<small>" + s + "</small>" : ""); };
  };
  if (document.documentElement) add(); else document.addEventListener("DOMContentLoaded", add);
})();`;

export async function newSession(dir, name) {
  const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ["--no-sandbox"] });
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir, size: { width: W, height: H } }, locale: "es-EC",
    timezoneId: "America/Guayaquil", acceptDownloads: true });
  await ctx.addInitScript(OVERLAY);
  const page = await ctx.newPage();
  const video = page.video();
  return { browser, ctx, page, async close() { await ctx.close(); const p = await video.path(); await browser.close(); fs.renameSync(p, `${dir}/${name}.webm`); return `${dir}/${name}.webm`; } };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const caption = (page, t, s) => page.evaluate(([t, s]) => window.__caption && window.__caption(t, s), [t, s]).catch(() => {});

let mouse = { x: 640, y: 360 };
export async function moveTo(page, x, y, steps = 22) {
  const sx = mouse.x, sy = mouse.y;
  for (let i = 1; i <= steps; i++) { // curva suave (ease in-out)
    const t = i / steps, e = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    await page.mouse.move(sx + (x - sx) * e, sy + (y - sy) * e);
    await sleep(14);
  }
  mouse = { x, y };
}
export async function click(page, locator, { pause = 450 } = {}) {
  await locator.scrollIntoViewIfNeeded();
  const b = await locator.boundingBox();
  await moveTo(page, b.x + b.width / 2, b.y + b.height / 2);
  await sleep(pause);
  await page.mouse.down(); await sleep(70); await page.mouse.up();
  await sleep(250);
}
export async function type(page, locator, text, delay = 55) {
  await click(page, locator, { pause: 200 });
  await locator.pressSequentially(text, { delay });
}
export async function card(page, title, sub, ms = 3200) {
  await page.setContent(`<body style="margin:0;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
    background:linear-gradient(135deg,#1e2a63,#1e40af);color:#fff;font-family:system-ui,sans-serif;text-align:center">
    <div style="font-size:54px;font-weight:800;letter-spacing:.5px;max-width:1000px">${title}</div>
    <div style="font-size:24px;opacity:.85;margin-top:18px;max-width:900px">${sub || ""}</div></body>`);
  await sleep(ms);
}
export function readEnv(path) {
  return Object.fromEntries(fs.readFileSync(path, "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => [l.split("=")[0], l.slice(l.indexOf("=") + 1)]));
}
