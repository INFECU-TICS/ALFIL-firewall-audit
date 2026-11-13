import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ReactFlow, ReactFlowProvider, Background, Controls, MiniMap, useNodesState, useEdgesState, useReactFlow,
  getNodesBounds, getViewportForBounds,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { toPng } from "html-to-image";
import { ArrowLeft, Copy, Download, Loader2, AlertTriangle, Info, Check, Grid3x3 } from "lucide-react";
import { api } from "../api";
import { filterTopology, layoutTopology, toMermaid, ROLE_COLORS } from "../topology/layout";
import { nodeTypes, SEV_COLOR } from "../topology/TopoNodes";
import ZoneMatrix from "../topology/ZoneMatrix";

const LEGEND = [["lan", "LAN"], ["wan", "WAN"], ["dmz", "DMZ"], ["vpn", "VPN"], ["wifi", "WiFi"], ["other", "Otras zonas"]];
const TYPE_LABEL = {
  firewall: "Firewall", interface: "Interfaz", network: "Red conectada", router: "Router / gateway",
  remote_network: "Red remota", internet: "Internet", vpn_tunnel: "Túnel VPN", remote_site: "Sitio remoto", blackhole: "Ruta descartada", zone: "Zona",
};

function Toggle({ checked, onChange, children }) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer select-none">
      <input type="checkbox" className="rounded" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {children}
    </label>
  );
}

const SEV_LABEL = { critical: "Crítico", warning: "Advertencia", info: "Informativo" };

function Findings({ items }) {
  if (!items?.length) return null;
  return (
    <section className="card p-3">
      <p className="text-xs font-semibold text-gray-700 mb-2">Hallazgos de este elemento ({items.length})</p>
      <ul className="space-y-1.5">
        {items.map((f, i) => (
          <li key={i} className="text-xs rounded px-2 py-1.5 border-l-4 bg-gray-50" style={{ borderColor: SEV_COLOR[f.severity] }}>
            <span className="font-semibold" style={{ color: SEV_COLOR[f.severity] }}>{SEV_LABEL[f.severity] || f.severity}</span> · {f.title}
            {f.recommendation && <span className="block text-gray-500 mt-0.5">{f.recommendation}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}

function Details({ node }) {
  if (!node) return <p className="text-xs text-gray-400">Seleccione un elemento del grafo para ver sus datos.</p>;
  const d = node.data;
  const rows = Object.entries(d.data || {}).filter(([k, v]) => v !== "" && v !== null && v !== undefined && !(Array.isArray(v) && !v.length) && k !== "role");
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wide text-gray-400">{TYPE_LABEL[d.type] || d.type}</p>
      <p className="text-sm font-semibold text-gray-900 break-all">{d.label}</p>
      <dl className="mt-2 space-y-1">
        {rows.map(([k, v]) => (
          <div key={k} className="flex gap-2 text-xs">
            <dt className="text-gray-500 w-24 flex-shrink-0 break-words">{k}</dt>
            <dd className="text-gray-800 break-all">{Array.isArray(v) ? v.join(", ") : typeof v === "boolean" ? (v ? "sí" : "no") : String(v)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function Viewer() {
  const { auditId } = useParams();
  const navigate = useNavigate();
  const rf = useReactFlow();
  const [topo, setTopo] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);
  const [opts, setOpts] = useState({ showUnconfigured: false, showEmptyZones: false, edgeLabels: true, byFindings: true });
  const [showMatrix, setShowMatrix] = useState(false);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let alive = true;
    api.getTopology(auditId).then((t) => alive && setTopo(t)).catch((e) => alive && (setError(e.message), setBusy(false)));
    return () => { alive = false; };
  }, [auditId]);

  const visible = useMemo(() => (topo ? filterTopology(topo, opts) : null), [topo, opts.showUnconfigured, opts.showEmptyZones]);

  useEffect(() => {
    if (!visible) return;
    let alive = true;
    setBusy(true);
    layoutTopology(visible)
      .then(({ nodes: n, edges: e }) => {
        if (!alive) return;
        setNodes(n);
        setEdges(e);
        setBusy(false);
        setTimeout(() => rf.fitView({ padding: 0.12 }), 50);
      })
      .catch((err) => { if (alive) { setError(`No se pudo calcular el diagrama: ${err.message}`); setBusy(false); } });
    return () => { alive = false; };
  }, [visible]);

  const shownEdges = useMemo(() => edges.map((e) => ({ ...e, label: opts.edgeLabels ? e.data?.label || undefined : undefined })), [edges, opts.edgeLabels]);
  const findings = topo?.findings || {};
  const shownNodes = useMemo(() => nodes.map((n) => ({ ...n, data: { ...n.data, findings: opts.byFindings ? findings[n.id] : undefined } })), [nodes, findings, opts.byFindings]);
  const selected = shownNodes.find((n) => n.id === selectedId);
  const totalFindings = Object.values(findings).reduce((a, l) => a + l.length, 0);

  const exportPng = useCallback(async () => {
    const el = document.querySelector(".react-flow__viewport");
    if (!el) return;
    const bounds = getNodesBounds(rf.getNodes());
    const w = Math.max(1200, Math.round(bounds.width + 160)), h = Math.max(700, Math.round(bounds.height + 160));
    const vp = getViewportForBounds(bounds, w, h, 0.3, 2, 0.05);
    const url = await toPng(el, {
      backgroundColor: "#ffffff", width: w, height: h,
      style: { width: `${w}px`, height: `${h}px`, transform: `translate(${vp.x}px, ${vp.y}px) scale(${vp.zoom})` },
    });
    const a = document.createElement("a");
    a.href = url; a.download = `topologia_auditoria_${auditId}.png`; a.click();
  }, [rf, auditId]);

  const copyMermaid = async () => {
    await navigator.clipboard.writeText(toMermaid(visible));
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  if (error) {
    return (
      <div className="max-w-xl mx-auto mt-10 text-center">
        <AlertTriangle className="w-8 h-8 text-yellow-500 mx-auto" />
        <p className="mt-3 text-sm text-gray-700">{error}</p>
        <button className="btn-secondary mt-4" onClick={() => navigate(-1)}>Volver</button>
      </div>
    );
  }

  const warnings = topo?.meta?.warnings || [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <button className="btn-secondary flex items-center gap-1" onClick={() => navigate(-1)}><ArrowLeft className="w-4 h-4" /> Volver</button>
        <h1 className="text-lg font-bold text-gray-900">Topología de red</h1>
        <span className="text-xs text-gray-500">Auditoría #{auditId} · basada en la configuración</span>
        <div className="flex-1" />
        <Toggle checked={opts.showUnconfigured} onChange={(v) => setOpts((o) => ({ ...o, showUnconfigured: v }))}>Puertos sin configurar</Toggle>
        <Toggle checked={opts.showEmptyZones} onChange={(v) => setOpts((o) => ({ ...o, showEmptyZones: v }))}>Zonas vacías</Toggle>
        <Toggle checked={opts.byFindings} onChange={(v) => setOpts((o) => ({ ...o, byFindings: v }))}>Hallazgos{totalFindings ? ` (${totalFindings})` : ""}</Toggle>
        <Toggle checked={opts.edgeLabels} onChange={(v) => setOpts((o) => ({ ...o, edgeLabels: v }))}>Etiquetas</Toggle>
        <button className={`btn-secondary flex items-center gap-1 ${showMatrix ? "ring-2 ring-blue-400" : ""}`} onClick={() => setShowMatrix((v) => !v)}>
          <Grid3x3 className="w-4 h-4" /> Matriz de zonas
        </button>
        <button className="btn-secondary flex items-center gap-1" onClick={copyMermaid} disabled={!visible}>
          {copied ? <Check className="w-4 h-4 text-green-600" /> : <Copy className="w-4 h-4" />} Mermaid
        </button>
        <button className="btn-secondary flex items-center gap-1" onClick={exportPng} disabled={busy}><Download className="w-4 h-4" /> PNG</button>
      </div>

      <div className="flex gap-3 items-stretch">
        <div className="relative flex-1 border border-gray-200 rounded-xl bg-white overflow-hidden" style={{ height: "calc(100vh - 220px)", minHeight: 460 }}>
          {busy && (
            <div className="absolute inset-0 z-10 bg-white/70 flex items-center justify-center text-sm text-gray-600">
              <Loader2 className="w-5 h-5 animate-spin mr-2" /> Calculando diagrama…
            </div>
          )}
          <ReactFlow
            nodes={shownNodes} edges={shownEdges} nodeTypes={nodeTypes}
            onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
            onNodeClick={(_, n) => setSelectedId(n.id)} onPaneClick={() => setSelectedId(null)}
            nodesConnectable={false} minZoom={0.1} maxZoom={2} fitView proOptions={{ hideAttribution: true }}
          >
            <Background gap={20} color="#e2e8f0" />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable nodeStrokeWidth={2} nodeColor={(n) => (n.type === "zoneGroup" ? "#e2e8f0" : ROLE_COLORS[n.data?.data?.role] || "#94a3b8")} />
          </ReactFlow>
        </div>

        <aside className="w-72 flex-shrink-0 space-y-3 overflow-y-auto" style={{ maxHeight: "calc(100vh - 220px)", minHeight: 460 }}>
          <section className="card p-3"><Details node={selected} /></section>
          <Findings items={selected ? findings[selected.id] : null} />
          {warnings.length > 0 && (
            <section className="card p-3">
              <p className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5 text-yellow-600" /> Advertencias de topología ({warnings.length})</p>
              <ul className="space-y-1.5">
                {warnings.map((w, i) => (
                  <li key={i} className={`text-xs rounded px-2 py-1 cursor-pointer ${w.severity === "critical" ? "bg-red-50 text-red-800" : "bg-yellow-50 text-yellow-800"}`}
                      onClick={() => w.node && setSelectedId(w.node)}>{w.message}</li>
                ))}
              </ul>
            </section>
          )}
          <section className="card p-3">
            <p className="text-xs font-semibold text-gray-700 mb-2">Leyenda</p>
            <div className="grid grid-cols-2 gap-1">
              {LEGEND.map(([k, label]) => (
                <span key={k} className="flex items-center gap-1.5 text-xs text-gray-600">
                  <span className="inline-block w-3 h-3 rounded-sm" style={{ background: ROLE_COLORS[k] }} /> {label}
                </span>
              ))}
            </div>
            {opts.byFindings && <p className="text-[11px] text-gray-500 mt-2">El círculo y el halo indican hallazgos de la auditoría: <span style={{ color: SEV_COLOR.critical }}>crítico</span>, <span style={{ color: SEV_COLOR.warning }}>advertencia</span>, <span style={{ color: SEV_COLOR.info }}>informativo</span> (color = el más grave).</p>}
            <p className="text-[11px] text-gray-500 mt-2">Línea punteada: túnel inactivo o salto inalcanzable. Las VLAN se muestran como interfaces.</p>
          </section>
          {(topo?.meta?.notes || []).map((n, i) => (
            <p key={i} className="text-[11px] text-gray-500 flex gap-1.5"><Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" /> {n}</p>
          ))}
        </aside>
      </div>
      {showMatrix && <ZoneMatrix auditId={auditId} />}
    </div>
  );
}

export default function TopologyPage() {
  return (
    <ReactFlowProvider>
      <Viewer />
    </ReactFlowProvider>
  );
}
