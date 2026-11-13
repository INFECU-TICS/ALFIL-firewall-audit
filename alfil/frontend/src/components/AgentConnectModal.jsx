import { useState } from "react";
import { Check, Copy, KeyRound, Loader2, TriangleAlert, CircleCheck, CircleHelp } from "lucide-react";
import Modal from "./Modal";
import { buildAgents, urlWarning } from "./agentSnippets";

function CopyButton({ text }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn-secondary text-xs py-1 px-2" onClick={async () => { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); }}>
      {done ? <Check className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />} Copiar
    </button>
  );
}

const EXPIRY = [
  { value: "1", label: "1 día" }, { value: "7", label: "7 días" }, { value: "30", label: "30 días" },
  { value: "90", label: "90 días" }, { value: "365", label: "1 año" }, { value: "never", label: "Sin caducidad" },
];

export default function AgentConnectModal({ token, tokenName, tokenConfigured, defaultDays = 7, writeAllowed = false, onCreate, busy, error, onClose }) {
  const [name, setName] = useState("");
  const [days, setDays] = useState(String(defaultDays));
  const [canWrite, setCanWrite] = useState(false);
  const [url, setUrl] = useState(`${window.location.origin}/mcp`);
  const [tab, setTab] = useState("prompt");
  const agents = buildAgents({ url, token });
  const agent = agents.find((a) => a.id === tab);
  const warning = urlWarning(url);

  return (
    <Modal title="Conectar un agente de IA" onClose={onClose} wide>
      <div className="space-y-4 text-sm">
        <p className="text-gray-600">
          Registre este servidor MCP remoto en su agente con la URL y un token. No necesita instalar nada: el agente lee sus firewalls
          habilitados en modo <strong>solo lectura</strong>. Opcionalmente, un token con permiso de escritura puede <em>proponer</em> cambios acotados
          que solo se aplican con una confirmación explícita y quedan en el registro de auditoría.
        </p>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label">URL del servidor MCP</label>
            <input className="input font-mono text-xs" value={url} onChange={(e) => setUrl(e.target.value.trim())} />
            <p className="text-[11px] text-gray-500 mt-1">Debe ser alcanzable desde donde corre el agente.</p>
          </div>
          <div>
            <label className="label">Token</label>
            {token ? (
              <div className="rounded-lg bg-green-50 text-green-900 text-xs p-2.5 flex items-center gap-2">
                <CircleCheck className="w-4 h-4 flex-shrink-0" />
                Token «{tokenName}» incluido en los fragmentos. Cópielo ahora: no se vuelve a mostrar.
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex gap-2">
                  <input className="input text-xs flex-1" placeholder="Nombre del agente (p. ej. claude-ana)" maxLength={80}
                    value={name} onChange={(e) => setName(e.target.value)} />
                  <select className="input text-xs w-36" value={days} onChange={(e) => setDays(e.target.value)} title="Caducidad">
                    {EXPIRY.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <label className={`flex items-start gap-2 text-[11px] ${writeAllowed ? "text-gray-700" : "text-gray-400"}`} title={writeAllowed ? "" : "El servidor tiene la escritura deshabilitada (MCP_ALLOW_WRITE)"}>
                  <input type="checkbox" className="mt-0.5" disabled={!writeAllowed} checked={writeAllowed && canWrite} onChange={(e) => setCanWrite(e.target.checked)} />
                  <span>Permitir proponer cambios (reglas y objetos; nunca borrados). {!writeAllowed && "Deshabilitado por el administrador del servidor."}</span>
                </label>
                <button className="btn-secondary text-xs py-2 px-3 w-full justify-center" disabled={busy || !name.trim()}
                  onClick={() => onCreate({ name: name.trim(), expires_days: days === "never" ? null : Number(days), can_write: writeAllowed && canWrite })}>
                  {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                  Crear token para este agente
                </button>
                {error && <p className="text-[11px] text-red-600">{error}</p>}
              </div>
            )}
            {!token && tokenConfigured && <p className="text-[11px] text-gray-500 mt-1">Los tokens existentes no pueden mostrarse; los fragmentos usan un marcador. Cree uno por agente y revóquelos de forma individual.</p>}
          </div>
        </div>

        {warning && (
          <p className="flex gap-2 p-2.5 rounded-lg bg-amber-50 text-amber-900 text-xs"><TriangleAlert className="w-4 h-4 flex-shrink-0 mt-0.5" />{warning}</p>
        )}

        <div className="flex flex-wrap gap-1.5 border-b border-gray-200 pb-2">
          {agents.map((a) => (
            <button key={a.id} onClick={() => setTab(a.id)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium ${tab === a.id ? "bg-brand-800 text-white" : "bg-gray-100 text-gray-700 hover:bg-gray-200"}`}>
              {a.name}
            </button>
          ))}
        </div>

        <div className="space-y-3">
          <p className="flex items-start gap-1.5 text-xs text-gray-600">
            {agent.tested
              ? <CircleCheck className="w-3.5 h-3.5 text-green-600 flex-shrink-0 mt-0.5" />
              : <CircleHelp className="w-3.5 h-3.5 text-amber-600 flex-shrink-0 mt-0.5" />}
            <span>{agent.about}{agent.tested ? " Probado contra ALFIL." : ""}</span>
          </p>
          {agent.blocks.map((b) => (
            <div key={b.title}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-gray-700">{b.title}</span>
                <CopyButton text={b.code} />
              </div>
              <pre className="rounded-lg bg-gray-900 text-gray-100 text-xs p-3 overflow-x-auto whitespace-pre-wrap break-all">{b.code}</pre>
            </div>
          ))}
        </div>

        <p className="text-[11px] text-gray-400">
          Formatos verificados en la documentación de cada herramienta el 2026-11-05; pueden cambiar con las versiones de cada agente.
        </p>
        <div className="flex justify-end"><button className="btn-primary" onClick={onClose}>Cerrar</button></div>
      </div>
    </Modal>
  );
}
