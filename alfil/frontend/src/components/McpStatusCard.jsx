import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Bot, Check, Copy, KeyRound, Loader2, ShieldCheck, Trash2, TriangleAlert } from "lucide-react";
import { api } from "../api";
import Modal from "./Modal";

const STATES = {
  en_linea: { label: "En línea", dot: "bg-green-500", badge: "bg-green-100 text-green-800" },
  fuera_de_linea: { label: "Fuera de línea", dot: "bg-red-500", badge: "bg-red-100 text-red-800" },
  sin_actividad: { label: "Sin actividad", dot: "bg-amber-400", badge: "bg-amber-100 text-amber-800" },
  sin_token: { label: "No configurado", dot: "bg-gray-300", badge: "bg-gray-100 text-gray-700" },
};

const ago = (s) => (s == null ? "—" : s < 60 ? `hace ${s} s` : s < 3600 ? `hace ${Math.floor(s / 60)} min` : `hace ${Math.floor(s / 3600)} h`);

function snippet(token) {
  return JSON.stringify({
    mcpServers: {
      alfil: {
        command: "/ruta/alfil-mcp/.venv/bin/python",
        args: ["-m", "alfil_mcp.server"],
        env: { ALFIL_URL: window.location.origin, ALFIL_MCP_TOKEN: token },
      },
    },
  }, null, 2);
}

function CopyButton({ text, label }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn-secondary text-xs py-1 px-2" onClick={async () => { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); }}>
      {done ? <Check className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />} {label}
    </button>
  );
}

function TokenModal({ token, onClose }) {
  return (
    <Modal title="Token del MCP" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p className="flex gap-2 p-2.5 rounded-lg bg-amber-50 text-amber-900 text-xs">
          <TriangleAlert className="w-4 h-4 flex-shrink-0 mt-0.5" />
          Cópielo ahora: no se vuelve a mostrar. Si genera otro, el anterior deja de funcionar.
        </p>
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="label !mb-0">Token</span>
            <CopyButton text={token} label="Copiar token" />
          </div>
          <code className="block break-all rounded-lg bg-gray-900 text-green-300 text-xs p-3">{token}</code>
        </div>
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="label !mb-0">Configuración del cliente MCP (stdio)</span>
            <CopyButton text={snippet(token)} label="Copiar JSON" />
          </div>
          <pre className="rounded-lg bg-gray-900 text-gray-100 text-xs p-3 overflow-x-auto">{snippet(token)}</pre>
          <p className="text-xs text-gray-500 mt-1">
            Ajuste la ruta del intérprete. <code>ALFIL_URL</code> debe ser alcanzable desde donde corre el MCP. Más detalles en la{" "}
            <Link to="/docs#5-alfil-mcp" className="text-blue-700 underline" onClick={onClose}>documentación</Link>.
          </p>
        </div>
        <div className="flex justify-end"><button className="btn-primary" onClick={onClose}>Listo</button></div>
      </div>
    </Modal>
  );
}

export default function McpStatusCard({ refreshKey = 0 }) {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState(null);

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
    if (!window.confirm("¿Revocar el token? El MCP dejará de poder usar las conexiones de ALFIL.")) return;
    setBusy(true);
    try { await api.mcpRevokeToken(); await load(); } catch (e) { setError(e.message); } finally { setBusy(false); }
  };

  const st = STATES[status?.state] || STATES.sin_token;
  const info = status?.info || {};
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
            <p className="text-xs text-gray-500">
              {status?.state === "sin_token" && "Genere un token para que un asistente de IA use las conexiones habilitadas."}
              {status?.state === "sin_actividad" && "Token generado; el MCP aún no se ha conectado."}
              {status?.state === "en_linea" && `Último latido ${ago(status.seconds_since_seen)}`}
              {status?.state === "fuera_de_linea" && `Sin latidos desde ${ago(status.seconds_since_seen)}. Se abre desde el cliente MCP.`}
              {error && <span className="text-red-600">{error}</span>}
            </p>
          </div>
        </div>

        {status && (
          <dl className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-gray-600 ml-auto">
            <div><dt className="text-gray-400">Versión</dt><dd className="font-medium">{info.version || "—"}</dd></div>
            <div><dt className="text-gray-400">Herramientas</dt><dd className="font-medium">{info.tools ?? "—"}</dd></div>
            <div>
              <dt className="text-gray-400">Modo</dt>
              <dd className="font-medium flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-600" />{info.read_only === false ? "Escritura" : "Solo lectura"}</dd>
            </div>
            <div><dt className="text-gray-400">Conexiones habilitadas</dt><dd className="font-medium">{status.enabled_connections}</dd></div>
            {status.token_prefix && <div><dt className="text-gray-400">Token</dt><dd className="font-mono font-medium">{status.token_prefix}…</dd></div>}
          </dl>
        )}

        <div className="flex gap-2">
          <button className="btn-secondary text-xs py-1.5 px-3" onClick={generate} disabled={busy}>
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
            {status?.token_configured ? "Nuevo token" : "Generar token"}
          </button>
          {status?.token_configured && (
            <button className="btn-secondary text-xs py-1.5 px-3 text-red-700" onClick={revoke} disabled={busy} title="Revocar token">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
      {token && <TokenModal token={token} onClose={() => setToken(null)} />}
    </section>
  );
}
