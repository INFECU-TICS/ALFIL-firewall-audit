import { useCallback, useEffect, useState } from "react";
import { Bot, Loader2, Plug, ShieldCheck, Trash2 } from "lucide-react";
import { api } from "../api";
import AgentConnectModal from "./AgentConnectModal";

const STATES = {
  en_linea: { label: "En línea", dot: "bg-green-500", badge: "bg-green-100 text-green-800" },
  fuera_de_linea: { label: "Fuera de línea", dot: "bg-red-500", badge: "bg-red-100 text-red-800" },
  sin_actividad: { label: "Sin actividad", dot: "bg-amber-400", badge: "bg-amber-100 text-amber-800" },
  sin_token: { label: "Sin token", dot: "bg-gray-300", badge: "bg-gray-100 text-gray-700" },
};

const ago = (s) => (s == null ? "—" : s < 60 ? `hace ${s} s` : s < 3600 ? `hace ${Math.floor(s / 60)} min` : `hace ${Math.floor(s / 3600)} h`);
const secondsSince = (iso) => (iso ? Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000)) : null);

export default function McpStatusCard({ refreshKey = 0 }) {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState(null);       // solo existe justo después de generarlo
  const [connectOpen, setConnectOpen] = useState(false);

  const load = useCallback(async () => {
    try { setStatus(await api.mcpStatus()); setError(""); } catch (e) { setError(e.message); }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load, refreshKey]);

  const generate = async () => {
    if (status?.token_configured && !window.confirm("Ya existe un token. Al generar uno nuevo, el actual dejará de funcionar. ¿Continuar?")) return;
    setBusy(true);
    try { setToken((await api.mcpGenerateToken()).token); await load(); } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  const revoke = async () => {
    if (!window.confirm("¿Revocar el token? Los agentes conectados dejarán de poder usar las conexiones de ALFIL.")) return;
    setBusy(true);
    try { await api.mcpRevokeToken(); setToken(null); await load(); } catch (e) { setError(e.message); } finally { setBusy(false); }
  };

  const remote = status?.remote || { configured: false };
  const info = status?.info || {};
  // Estado principal: el servicio remoto (contenedor) si existe; si no, el MCP local (stdio) por sus latidos.
  const stateKey = !status ? null : remote.configured ? (remote.reachable ? "en_linea" : "fuera_de_linea") : status.state;
  const st = STATES[stateKey] || STATES.sin_token;
  const version = remote.version || info.version;
  const tools = remote.tools ?? info.tools;
  const used = secondsSince(status?.last_used_at);

  let subtitle = "";
  if (status) {
    if (remote.configured) subtitle = remote.reachable ? "Servicio remoto activo en /mcp" : "El servicio remoto no responde.";
    else if (status.state === "sin_token") subtitle = "Genere un token para conectar un asistente de IA.";
    else if (status.state === "sin_actividad") subtitle = "Token generado; el MCP aún no se ha conectado.";
    else if (status.state === "en_linea") subtitle = `MCP local · último latido ${ago(status.seconds_since_seen)}`;
    else subtitle = `MCP local sin latidos desde ${ago(status.seconds_since_seen)}.`;
  }

  return (
    <section className="card mb-6 !p-4">
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-brand-50 text-brand-800"><Bot className="w-5 h-5" /></div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="font-semibold text-gray-900">Servidor MCP</h2>
              {status ? (
                <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold ${st.badge}`}>
                  <span className={`inline-block w-2 h-2 rounded-full ${st.dot}`} /> {st.label}
                </span>
              ) : <Loader2 className="w-4 h-4 animate-spin text-gray-400" />}
            </div>
            <p className="text-xs text-gray-500">{subtitle}{error && <span className="text-red-600"> {error}</span>}</p>
          </div>
        </div>

        {status && (
          <dl className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-gray-600 ml-auto">
            <div><dt className="text-gray-400">Versión</dt><dd className="font-medium">{version || "—"}</dd></div>
            <div><dt className="text-gray-400">Herramientas</dt><dd className="font-medium">{tools ?? "—"}</dd></div>
            <div>
              <dt className="text-gray-400">Modo</dt>
              <dd className="font-medium flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-600" />{info.read_only === false ? "Escritura" : "Solo lectura"}</dd>
            </div>
            <div><dt className="text-gray-400">Conexiones habilitadas</dt><dd className="font-medium">{status.enabled_connections}</dd></div>
            <div><dt className="text-gray-400">Último uso de un agente</dt><dd className="font-medium">{ago(used)}</dd></div>
            {status.token_prefix && <div><dt className="text-gray-400">Token</dt><dd className="font-mono font-medium">{status.token_prefix}…</dd></div>}
          </dl>
        )}

        <div className="flex gap-2">
          <button className="btn-primary text-xs py-1.5 px-3" onClick={() => setConnectOpen(true)}>
            <Plug className="w-3.5 h-3.5" /> Conectar un agente
          </button>
          {status?.token_configured && (
            <button className="btn-secondary text-xs py-1.5 px-3 text-red-700" onClick={revoke} disabled={busy} title="Revocar token">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
      {connectOpen && (
        <AgentConnectModal token={token} tokenConfigured={!!status?.token_configured} onGenerate={generate} busy={busy}
          onClose={() => { setConnectOpen(false); setToken(null); }} />
      )}
    </section>
  );
}
