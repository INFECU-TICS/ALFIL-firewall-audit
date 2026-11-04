// Configuración de un servidor MCP remoto para cada agente. Función pura: se prueba sin DOM.
// Formatos verificados el 2026-11-05 en la documentación de cada herramienta. "tested": comprobado contra ALFIL con la
// herramienta instalada; el resto está sin probar (no instalada) y puede cambiar con las versiones.

export const TOKEN_PLACEHOLDER = "<TU_TOKEN>";
const q = (s) => JSON.stringify(s);
const pretty = (o) => JSON.stringify(o, null, 2);

export function buildAgents({ url, token }) {
  const t = token || TOKEN_PLACEHOLDER;
  const bearer = `Bearer ${t}`;
  return [
    {
      id: "prompt", name: "Cualquier agente (prompt)", tested: true,
      about: "Péguelo en el chat de su agente. Cada agente lo traduce a su propio formato de configuración.",
      blocks: [{ title: "Prompt de instalación", lang: "text", code:
`Instala y configura este servidor MCP remoto en tu configuración de MCP:
- Nombre: alfil
- Transporte: HTTP (streamable HTTP)
- URL: ${url}
- Autenticación: cabecera "Authorization: Bearer ${t}" (no uses OAuth)

Cuando termine, recarga los servidores MCP si es necesario y lista las herramientas de "alfil".
Son de solo lectura: list_connections, list_api_endpoints, api_get, list_firewall_rules, get_firewall_rule y audit_firewall.
Para probarlo, ejecuta list_connections.` }],
    },
    {
      id: "claude", name: "Claude Code", tested: true,
      about: "Registra el servidor en su configuración. Verifique con `claude mcp list` (debe decir Connected).",
      blocks: [
        { title: "Comando", lang: "bash", code: `claude mcp add --transport http alfil ${url} --header ${q(`Authorization: ${bearer}`)}` },
        { title: "Verificar", lang: "bash", code: "claude mcp list" },
      ],
    },
    {
      id: "opencode", name: "opencode", tested: true,
      about: "Añada el bloque a su opencode.json. El token va por variable de entorno para no dejarlo en el archivo. Verifique con `opencode mcp list`.",
      blocks: [
        { title: "opencode.json", lang: "json", code: pretty({
          $schema: "https://opencode.ai/config.json",
          mcp: { alfil: { type: "remote", url, enabled: true, oauth: false, headers: { Authorization: "Bearer {env:ALFIL_MCP_TOKEN}" } } },
        }) },
        { title: "Variable de entorno", lang: "bash", code: `export ALFIL_MCP_TOKEN=${t}` },
        { title: "Verificar", lang: "bash", code: "opencode mcp list" },
      ],
    },
    {
      id: "codex", name: "Codex", tested: false,
      about: "Según la documentación de Codex (no probado aquí). El token va por variable de entorno.",
      blocks: [
        { title: "Variable de entorno", lang: "bash", code: `export ALFIL_MCP_TOKEN=${t}` },
        { title: "Comando", lang: "bash", code: `codex mcp add alfil --url ${url} --bearer-token-env-var ALFIL_MCP_TOKEN` },
        { title: "O en ~/.codex/config.toml", lang: "toml", code: `[mcp_servers.alfil]\nurl = ${q(url)}\nbearer_token_env_var = "ALFIL_MCP_TOKEN"` },
      ],
    },
    {
      id: "cursor", name: "Cursor", tested: false,
      about: "Según la documentación de Cursor (no probado aquí). Archivo ~/.cursor/mcp.json (global) o .cursor/mcp.json (proyecto).",
      blocks: [{ title: "mcp.json", lang: "json", code: pretty({ mcpServers: { alfil: { url, headers: { Authorization: bearer } } } }) }],
    },
    {
      id: "vscode", name: "VS Code", tested: false,
      about: "Según la documentación de VS Code (no probado aquí). Archivo .vscode/mcp.json; el campo type es obligatorio.",
      blocks: [{ title: "mcp.json", lang: "json", code: pretty({ servers: { alfil: { type: "http", url, headers: { Authorization: bearer } } } }) }],
    },
    {
      id: "gemini", name: "Gemini CLI", tested: false, unverified: true,
      about: "Formato pendiente de confirmar en la documentación de Gemini CLI (no probado aquí). Archivo ~/.gemini/settings.json.",
      blocks: [{ title: "settings.json", lang: "json", code: pretty({ mcpServers: { alfil: { httpUrl: url, headers: { Authorization: bearer } } } }) }],
    },
  ];
}

/** Aviso si la URL no es HTTPS y no es local: el token viaja en cada petición. */
export function urlWarning(url) {
  try {
    const u = new URL(url);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    return u.protocol === "http:" && !local ? "La URL usa HTTP sin cifrar: el token viajaría en claro. Use HTTPS." : "";
  } catch {
    return "La URL no es válida.";
  }
}
