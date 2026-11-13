import fs from "fs";
import { execFileSync, spawnSync } from "child_process";
import { newSession, caption, sleep } from "./lib.mjs";
const out = "out";
const token = fs.readFileSync(`${out}/token`, "utf8").trim();
if (!token.startsWith("alfil_mcp_")) throw new Error("sin token");
fs.writeFileSync("oc.json", JSON.stringify({ $schema: "https://opencode.ai/config.json", mcp: { alfil: { type: "remote", url: "http://localhost:8090/mcp", enabled: true, oauth: false, headers: { Authorization: "Bearer {env:ALFIL_MCP_TOKEN}" } } } }));
// el servicio de opencode cachea configuración y entorno: reiniciarlo para que lea el token nuevo
try { execFileSync("sh", ["-c", "pgrep -f '[o]pencode serve' | xargs -r kill"]); } catch {}
await sleep(1500);
const env = { ...process.env, ALFIL_MCP_TOKEN: token, OPENCODE_CONFIG: process.cwd() + "/oc.json" };
const strip = (t) => t.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").replace(/\r/g, "");
const PROMPTS = JSON.parse(process.env.PROMPTS_JSON);
const runs = [];
for (const [i, p] of PROMPTS.entries()) {
  const args = ["run", "-m", "opencode/big-pickle", ...(p.cont ? ["-c"] : []), p.text];
  const t0 = Date.now();
  const r = spawnSync(process.env.OPENCODE_BIN || "opencode", args, { env, encoding: "utf8", timeout: 280000 });
  const raw = strip((r.stdout || "") + (r.stderr || ""));
  fs.writeFileSync(`${out}/agent_${i}.txt`, raw);
  // Solo líneas legibles: llamadas a herramientas y respuesta (sin volcados JSON)
  const lines = raw.split("\n").filter((l) => l.trim() && !/^\s*[\[\]{}"]/.test(l) && !/^\s*[,]/.test(l) && !/^>\s*build/.test(l));
  runs.push({ prompt: p.text, lines, secs: Math.round((Date.now() - t0) / 1000), cont: !!p.cont });
  console.log(`run ${i}: ${runs[i].secs}s, ${lines.length} líneas`);
}
fs.writeFileSync(`${out}/agent_runs.json`, JSON.stringify(runs, null, 1));
