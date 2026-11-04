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

export default function AgentConnectModal({ token, tokenConfigured, onGenerate, busy, onClose }) {
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
          habilitados en modo <strong>solo lectura</strong>.
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
                Token nuevo incluido en los fragmentos. Cópielo ahora: no se vuelve a mostrar.
              </div>
            ) : (
              <button className="btn-secondary text-xs py-2 px-3 w-full justify-center" onClick={onGenerate} disabled={busy}>
                {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                {tokenConfigured ? "Generar token nuevo (invalida el actual)" : "Generar token"}
              </button>
            )}
            {!token && tokenConfigured && <p className="text-[11px] text-gray-500 mt-1">El token existente no puede mostrarse; los fragmentos usan un marcador.</p>}
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
