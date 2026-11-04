import { buildAgents, urlWarning, TOKEN_PLACEHOLDER } from "../src/components/agentSnippets.js";
const url = "https://alfil.example.com/mcp", token = "alfil_mcp_ABC123";
let ok = true; const check = (c, m) => { if (!c) { ok = false; console.log("FALLA:", m); } };
const agents = buildAgents({ url, token });
check(agents.length === 7, "siete pestañas");
for (const a of agents) for (const b of a.blocks) {
  if (b.lang === "json") { try { JSON.parse(b.code); } catch (e) { check(false, `${a.id}/${b.title} no es JSON válido`); } }
  if (!["opencode", "codex"].includes(a.id) && b.title !== "Verificar") check(b.code.includes(token) || b.code.includes("verificar") || b.title === "Verificar" || b.title === "Comando" && a.id === "codex", `${a.id}/${b.title} sin token`);
}
const get = (id) => agents.find((a) => a.id === id).blocks;
check(get("claude")[0].code === `claude mcp add --transport http alfil ${url} --header "Authorization: Bearer ${token}"`, "comando claude exacto");
check(JSON.parse(get("opencode")[0].code).mcp.alfil.headers.Authorization === "Bearer {env:ALFIL_MCP_TOKEN}", "opencode usa variable de entorno");
check(get("opencode")[1].code === `export ALFIL_MCP_TOKEN=${token}`, "opencode exporta el token");
check(get("codex")[1].code.includes("--bearer-token-env-var ALFIL_MCP_TOKEN") && get("codex")[2].code.includes("[mcp_servers.alfil]"), "codex");
check(JSON.parse(get("cursor")[0].code).mcpServers.alfil.headers.Authorization === `Bearer ${token}`, "cursor");
check(JSON.parse(get("vscode")[0].code).servers.alfil.type === "http", "vscode type http");
check(JSON.parse(get("gemini")[0].code).mcpServers.alfil.httpUrl === url && agents.find((a) => a.id === "gemini").unverified, "gemini marcado sin verificar");
check(get("prompt")[0].code.includes(url) && get("prompt")[0].code.includes(token), "prompt con url y token");
const noTok = buildAgents({ url, token: null });
check(noTok.every((a) => a.blocks.every((b) => !b.code.includes("null"))) && noTok[1].blocks[0].code.includes(TOKEN_PLACEHOLDER), "marcador sin token");
check(urlWarning("http://alfil.example.com/mcp").includes("HTTPS") && urlWarning("http://localhost:8081/mcp") === "" && urlWarning("https://x.com/mcp") === "" && urlWarning("no es url") !== "", "avisos de URL");
console.log(ok ? "snippets OK" : "HAY FALLAS");
