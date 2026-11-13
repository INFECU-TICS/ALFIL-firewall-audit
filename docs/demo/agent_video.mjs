import fs from "fs";
import { newSession, caption, sleep } from "./lib.mjs";
const out = "out";
const runs = JSON.parse(fs.readFileSync(`${out}/agent_runs.json`, "utf8"));
const s = await newSession(out, "seg2");
const { page } = s;
const esc = (t) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
await page.setContent(`<body style="margin:0;background:#0b1020;color:#d6deeb;font:15px/1.5 ui-monospace,Menlo,Consolas,monospace;padding:22px 28px 90px;white-space:pre-wrap;word-break:break-word">
 <div id=t></div></body>`);
await page.addStyleTag({ content: "body{overflow:hidden} .p{color:#7fdbca} .u{color:#ffd580;font-weight:700} .tool{color:#82aaff} .ans{color:#d6deeb} .dim{color:#6b7794}" });
const add = (html) => page.evaluate((h) => { const d = document.getElementById("t"); d.insertAdjacentHTML("beforeend", h); window.scrollTo(0, document.body.scrollHeight); }, html);
await caption(page, "7 · El agente usa el MCP", "Sesión real de opencode con un modelo gratuito (acelerada).");
await sleep(1500);
for (const r of runs) {
  await add(`<span class=p>$ </span><span class=u id=cmd></span>\n`);
  const text = `opencode run ${r.cont ? "-c " : ""}"${r.prompt}"`;
  for (const ch of text) { await page.evaluate((c) => { document.querySelectorAll("#cmd").forEach((e, i, a) => { if (i === a.length - 1) e.textContent += c; }); }, ch); await sleep(14); }
  await add("\n");
  await sleep(700);
  await add(`<span class=dim>… el agente trabaja (${r.secs} s reales)</span>\n`);
  await sleep(900);
  for (const l of r.tools) {
    await add(`<span class="tool">${esc(l.length > 150 ? l.slice(0, 147) + "…" : l)}</span>\n`);
    await sleep(520);
  }
  await sleep(500);
  for (const l of r.answer) {
    await add(`<span class="ans">${esc(l)}</span>\n`);
    await sleep(l ? 230 : 120);
  }
  await add("\n");
  await sleep(2600);
}
await sleep(1500);
console.log(await s.close());
