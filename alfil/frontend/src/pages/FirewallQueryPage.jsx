import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft, Shield, Loader2, AlertCircle, Code, List, Copy, Check, Server,
  ChevronDown, ChevronRight, RefreshCw, Users,
} from "lucide-react";
import { api } from "../api";

// ---------------------------------------------------------------------------
// Renderer jerárquico para Interfaces
// ---------------------------------------------------------------------------
function InterfaceRow({ iface }) {
  const [open, setOpen] = useState(false);
  const hasSub = iface.vlans?.length || iface.aliases?.length || iface.lags?.length;
  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden mb-2">
      {/* Fila principal */}
      <div
        className={`flex items-center gap-2 px-3 py-2 bg-gray-50 ${hasSub ? "cursor-pointer hover:bg-gray-100" : ""}`}
        onClick={() => hasSub && setOpen(o => !o)}
      >
        {hasSub
          ? (open ? <ChevronDown className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />)
          : <span className="w-3.5 flex-shrink-0" />
        }
        <span className="font-mono text-xs font-semibold text-gray-800 w-28 flex-shrink-0">{iface.name}</span>
        {iface.hardware && iface.hardware !== iface.name && (
          <span className="text-[10px] text-gray-400 w-20 flex-shrink-0">({iface.hardware})</span>
        )}
        {iface.zone && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-brand-50 text-brand-700 border border-brand-100 flex-shrink-0">
            {iface.zone}
          </span>
        )}
        <span className={`text-[10px] px-1.5 py-0.5 rounded flex-shrink-0 ${
          iface.interface_status === "ON" ? "bg-green-50 text-green-700" : "bg-gray-100 text-gray-500"
        }`}>
          {iface.interface_status || "—"}
        </span>
        {iface.ip_address && (
          <span className="font-mono text-[10px] text-gray-500 flex-shrink-0">{iface.ip_address}/{iface.netmask}</span>
        )}
        {iface.ipv4_assignment && (
          <span className="text-[10px] text-gray-400 flex-shrink-0">{iface.ipv4_assignment}</span>
        )}
        {iface.mtu && <span className="text-[10px] text-gray-400 ml-auto flex-shrink-0">MTU {iface.mtu}</span>}
        {hasSub && (
          <span className="text-[9px] text-gray-400 ml-auto flex-shrink-0">
            {[
              iface.vlans?.length && `${iface.vlans.length} VLAN${iface.vlans.length > 1 ? "s" : ""}`,
              iface.aliases?.length && `${iface.aliases.length} Alias`,
              iface.lags?.length && `${iface.lags.length} LAG`,
            ].filter(Boolean).join(" · ")}
          </span>
        )}
      </div>

      {/* Sub-items */}
      {open && (
        <div className="bg-white px-3 pb-2 pt-1 space-y-1">
          {iface.vlans?.map((v, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px] pl-4 py-1 border-l-2 border-blue-200">
              <span className="font-semibold text-blue-700 w-4">V</span>
              <span className="font-mono text-gray-700 w-28">{v.name}</span>
              <span className="text-blue-500 w-16">VLAN {v.vlan_id}</span>
              {v.zone && <span className="px-1 py-0.5 rounded bg-brand-50 text-brand-600 border border-brand-100">{v.zone}</span>}
              <span className={`px-1 py-0.5 rounded ${v.status === "ON" ? "bg-green-50 text-green-700" : "bg-gray-100 text-gray-500"}`}>{v.status || "—"}</span>
              {v.ip_address && <span className="font-mono text-gray-500">{v.ip_address}/{v.netmask}</span>}
            </div>
          ))}
          {iface.aliases?.map((a, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px] pl-4 py-1 border-l-2 border-amber-200">
              <span className="font-semibold text-amber-700 w-4">A</span>
              <span className="font-mono text-gray-700 w-28">{a.name}</span>
              {a.ip_address && <span className="font-mono text-gray-500">{a.ip_address}/{a.netmask}</span>}
            </div>
          ))}
          {iface.lags?.map((l, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px] pl-4 py-1 border-l-2 border-purple-200">
              <span className="font-semibold text-purple-700 w-4">L</span>
              <span className="font-mono text-gray-700 w-28">{l.name}</span>
              {l.members?.length > 0 && (
                <span className="text-gray-500">Puertos: {l.members.join(", ")}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function InterfacesView({ data }) {
  if (!data?.length) return <p className="text-sm text-gray-400 italic py-6 text-center">Sin datos</p>;
  return (
    <div className="overflow-y-auto">
      {data.map((iface, i) => <InterfaceRow key={i} iface={iface} />)}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Catálogo de consultas disponibles
// ---------------------------------------------------------------------------
const QUERIES = [
  {
    type: "firewall_rules",
    label: "Firewall Rules",
    icon: Shield,
    description: "Reglas de filtrado de tráfico (NetworkPolicy / HTTPBasedPolicy)",
    headers: ["#", "Nombre", "Estado", "Tipo", "Acción", "Src Zones", "Src Redes", "Dst Zones", "Dst Redes", "Servicios", "Web Filter", "IPS", "Log"],
    row: (r, i) => [
      i + 1,
      r.name,
      r.status,
      r.policy_type,
      r.action,
      r.source_zones?.length ? r.source_zones.join(", ") : "Any",
      r.source_networks?.length ? r.source_networks.join(", ") : "Any",
      r.destination_zones?.length ? r.destination_zones.join(", ") : "Any",
      r.destination_networks?.length ? r.destination_networks.join(", ") : "Any",
      r.services?.length ? r.services.join(", ") : "Any",
      r.web_filter || "None",
      r.intrusion_prevention || "None",
      r.log_traffic,
    ],
  },
  {
    type: "interface_info",
    label: "Interfaces",
    icon: Server,
    description: "Interfaces físicas con VLANs, Aliases y LAGs asociados",
    render: (data) => <InterfacesView data={data} />,
  },
  {
    type: "users",
    label: "Usuarios",
    icon: Users,
    description: "Usuarios de autenticación locales y de directorio",
    headers: ["Usuario", "Nombre", "Tipo", "Grupo", "Estado", "SSL VPN Policy", "Política tiempo", "Cuota navegación", "Restricción login", "Logins simult."],
    row: (r) => [
      r.username,
      r.name,
      r.user_type,
      r.group,
      r.status,
      r.ssl_vpn_policy || "—",
      r.access_time_policy || "—",
      r.surfing_quota || "—",
      r.login_restriction || "—",
      r.simultaneous_logins || "—",
    ],
  },
];

// Clave de sessionStorage por conexión + tipo de consulta
const cacheKey = (connectionId, queryType) =>
  `fwquery_${connectionId}_${queryType}`;

// ---------------------------------------------------------------------------
// Helpers UI
// ---------------------------------------------------------------------------
function DataTable({ headers, rows }) {
  if (!rows?.length)
    return <p className="text-sm text-gray-400 italic py-6 text-center">Sin datos</p>;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-xs border-collapse">
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h} className="text-left px-3 py-2 bg-gray-50 text-gray-600 font-semibold border-b whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b last:border-0 hover:bg-gray-50">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2 text-gray-700 max-w-xs truncate" title={String(cell ?? "")}>
                  {cell ?? "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={handleCopy}
      title="Copiar XML"
      className={`flex items-center gap-1 text-[10px] px-2 py-1 rounded transition-colors ${
        copied
          ? "bg-green-700 text-white"
          : "bg-gray-800 text-gray-300 hover:bg-gray-700"
      }`}
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? "Copiado" : "Copiar"}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Página principal
// ---------------------------------------------------------------------------
export default function FirewallQueryPage() {
  const { id: connectionId } = useParams();
  const navigate = useNavigate();

  const [connectionName, setConnectionName] = useState("");
  const [activeQuery, setActiveQuery] = useState(null);
  const [view, setView] = useState("table");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    api.getConnection(connectionId).then((c) => setConnectionName(c.name)).catch(() => {});
  }, [connectionId]);

  // Restaurar última consulta cacheada al entrar a la página
  useEffect(() => {
    for (const q of QUERIES) {
      const cached = sessionStorage.getItem(cacheKey(connectionId, q.type));
      if (cached) {
        try {
          setActiveQuery(q);
          setResult(JSON.parse(cached));
          break;
        } catch { /* ignore */ }
      }
    }
  }, [connectionId]);

  // Carga desde caché si existe, si no hace la petición
  const selectQuery = useCallback((query) => {
    if (activeQuery?.type === query.type) return; // ya está activa, no hacer nada
    const cached = sessionStorage.getItem(cacheKey(connectionId, query.type));
    setActiveQuery(query);
    setError("");
    if (cached) {
      try { setResult(JSON.parse(cached)); return; } catch { /* ignore */ }
    }
    // Sin caché: hacer petición
    fetchQuery(query);
  }, [connectionId, activeQuery]);

  // Fuerza una petición nueva y actualiza caché
  const fetchQuery = useCallback(async (query) => {
    setResult(null);
    setError("");
    setLoading(true);
    try {
      const res = await api.queryFirewall(connectionId, query.type);
      sessionStorage.setItem(cacheKey(connectionId, query.type), JSON.stringify(res));
      setResult(res);
      setView("table");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [connectionId]);

  return (
    <div className="flex flex-col h-full">
      {/* Cabecera */}
      <div className="flex items-center gap-4 mb-6">
        <button className="btn-secondary py-1.5 px-3 text-sm" onClick={() => navigate("/")}>
          <ArrowLeft className="w-4 h-4" /> Volver
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-gray-900">Consultas al Firewall</h1>
          {connectionName && <p className="text-sm text-gray-500">{connectionName}</p>}
        </div>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Panel izquierdo: botones de consulta */}
        <div className="w-56 flex-shrink-0 flex flex-col gap-2">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
            Consultas disponibles
          </p>
          {QUERIES.map((q) => {
            const Icon = q.icon;
            const isActive = activeQuery?.type === q.type;
            const hasCached = !!sessionStorage.getItem(cacheKey(connectionId, q.type));
            return (
              <button
                key={q.type}
                onClick={() => selectQuery(q)}
                disabled={loading}
                className={`w-full flex items-start gap-3 text-left px-3 py-3 rounded-lg border transition-colors ${
                  isActive
                    ? "bg-brand-50 border-brand-300 text-brand-800"
                    : "bg-white border-gray-200 text-gray-700 hover:border-brand-200 hover:bg-gray-50"
                }`}
              >
                <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${isActive ? "text-brand-700" : "text-gray-400"}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold leading-tight">{q.label}</p>
                  <p className="text-[10px] text-gray-400 mt-0.5 leading-snug">{q.description}</p>
                  {hasCached && (
                    <span className="text-[9px] text-brand-500 font-medium mt-1 block">● en caché</span>
                  )}
                </div>
              </button>
            );
          })}
        </div>

        {/* Panel derecho: resultado */}
        <div className="flex-1 min-w-0 card flex flex-col">
          {/* Estado inicial */}
          {!activeQuery && !loading && (
            <div className="flex-1 flex items-center justify-center text-gray-300">
              <div className="text-center">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-40" />
                <p className="text-sm">Selecciona una consulta para comenzar</p>
              </div>
            </div>
          )}

          {/* Cargando */}
          {loading && (
            <div className="flex-1 flex items-center justify-center text-brand-700">
              <div className="text-center">
                <Loader2 className="w-8 h-8 mx-auto animate-spin mb-2" />
                <p className="text-sm text-gray-500">Consultando firewall…</p>
              </div>
            </div>
          )}

          {/* Error */}
          {error && !loading && (
            <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <span className="text-sm">{error}</span>
            </div>
          )}

          {/* Resultado */}
          {result && !loading && (
            <>
              {/* Barra superior: título + toggle */}
              <div className="flex items-center gap-3 mb-4 pb-4 border-b">
                <div className="flex-1">
                  <h2 className="font-semibold text-gray-800">{activeQuery.label}</h2>
                  <p className="text-xs text-gray-400">{result.count ?? result.data?.length} registros</p>
                </div>
                <button
                  onClick={() => fetchQuery(activeQuery)}
                  disabled={loading}
                  title="Actualizar datos desde el firewall"
                  className="p-1.5 rounded-lg border border-gray-200 text-gray-400 hover:text-brand-700 hover:border-brand-200 transition-colors"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
                <div className="flex rounded-lg border border-gray-200 overflow-hidden text-xs">
                  <button
                    onClick={() => setView("table")}
                    className={`flex items-center gap-1.5 px-3 py-1.5 transition-colors ${
                      view === "table" ? "bg-brand-700 text-white" : "text-gray-600 hover:bg-gray-50"
                    }`}
                  >
                    <List className="w-3.5 h-3.5" /> Tabla
                  </button>
                  <button
                    onClick={() => setView("xml")}
                    className={`flex items-center gap-1.5 px-3 py-1.5 transition-colors border-l border-gray-200 ${
                      view === "xml" ? "bg-brand-700 text-white" : "text-gray-600 hover:bg-gray-50"
                    }`}
                  >
                    <Code className="w-3.5 h-3.5" /> XML
                  </button>
                </div>
              </div>

              {/* Vista tabla / custom render */}
              {view === "table" && (
                activeQuery.render
                  ? activeQuery.render(result.data)
                  : <DataTable
                      headers={activeQuery.headers}
                      rows={result.data?.map((r, i) => activeQuery.row(r, i))}
                    />
              )}

              {/* Vista XML */}
              {view === "xml" && (
                <div className="flex-1 flex flex-col min-h-0">
                  <div className="flex justify-end mb-1">
                    <CopyButton text={result.raw_xml || ""} />
                  </div>
                  <pre className="flex-1 overflow-auto text-[11px] font-mono bg-gray-950 text-green-300 rounded-lg p-4 leading-relaxed whitespace-pre-wrap break-words">
                    {result.raw_xml || "Sin respuesta XML"}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
