import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft, Play, Download, FileSpreadsheet, FileText, FileArchive,
  Loader2, AlertCircle, CheckCircle, ChevronDown, ChevronRight,
  Users, Server, FileWarning, Trash2, Eye, Clock,
  Route, Settings, Network
} from "lucide-react";
import { api } from "../api";
import { SeverityBadge, ScoreRing } from "../components/IssuesBadge";
import ConfirmModal from "../components/ConfirmModal";

// ---------------------------------------------------------------------------
// Helpers de fecha — backend guarda en UTC, mostrar en GMT-5 (Ecuador)
const fmtDate = (iso) => {
  if (!iso) return "—";
  // El historial llega sin zona horaria (SQLite guarda UTC "naive"): sin «Z» el navegador lo tomaría como hora local
  const utc = /(Z|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : iso.replace(" ", "T") + "Z";
  return new Date(utc).toLocaleString("es-EC", { timeZone: "America/Guayaquil" });
};

// ---------------------------------------------------------------------------
// Helpers de UI
// ---------------------------------------------------------------------------
function Section({ icon: Icon, title, count, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="card mb-4">
      <button className="w-full flex items-center gap-3 text-left" onClick={() => setOpen(o => !o)}>
        <Icon className="w-5 h-5 text-brand-700 flex-shrink-0" />
        <span className="font-semibold text-gray-800 flex-1">{title}</span>
        {count !== undefined && <span className="text-xs bg-gray-100 text-gray-600 rounded-full px-2 py-0.5">{count}</span>}
        {open ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />}
      </button>
      {open && <div className="mt-4 border-t pt-4">{children}</div>}
    </div>
  );
}

const HEALTH_SEV = { high: "Alta", medium: "Media", low: "Baja", veryLow: "Muy baja" };

function IssueRow({ issue }) {
  const bg = { critical: "bg-red-50 border-red-100", warning: "bg-yellow-50 border-yellow-100", info: "bg-blue-50 border-blue-100" };
  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg mb-2 text-sm border ${bg[issue.severity] || "bg-gray-50"}`}>
      <SeverityBadge severity={issue.severity} />
      <div className="flex-1 min-w-0">
        <p className="font-medium text-gray-800">{issue.title}</p>
        <p className="text-gray-600 text-xs mt-0.5">{issue.detail}</p>
        {issue.recommendation && <p className="text-gray-700 text-xs mt-1"><span className="font-semibold">Recomendación:</span> {issue.recommendation}</p>}
      </div>
    </div>
  );
}

function DataTable({ headers, rows }) {
  if (!rows?.length) return <p className="text-sm text-gray-400 italic">Sin datos disponibles</p>;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-xs">
        <thead>
          <tr>{headers.map(h => <th key={h} className="text-left px-3 py-2 bg-gray-50 text-gray-600 font-semibold border-b">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b last:border-0 hover:bg-gray-50">
              {row.map((cell, j) => <td key={j} className="px-3 py-2 text-gray-700 max-w-xs truncate" title={String(cell ?? "")}>{cell ?? "—"}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const SEV_ORDER = { critical: 0, warning: 1, info: 2, ok: 3 };

function StatusBadge({ status }) {
  const map = {
    running:   "bg-blue-100 text-blue-700",
    completed: "bg-green-100 text-green-700",
    failed:    "bg-red-100 text-red-700",
  };
  const labels = { running: "Ejecutando", completed: "Completada", failed: "Fallida" };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold ${map[status] || "bg-gray-100 text-gray-600"}`}>
      {status === "running" && <Loader2 className="w-3 h-3 animate-spin" />}
      {status === "completed" && <CheckCircle className="w-3 h-3" />}
      {labels[status] || status}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Página principal
// ---------------------------------------------------------------------------
export default function AuditPage() {
  const { id: connectionId } = useParams();
  const navigate = useNavigate();

  const [connectionName, setConnectionName] = useState("");
  const [audits, setAudits] = useState([]);
  const [selectedAuditId, setSelectedAuditId] = useState(null);
  const [report, setReport] = useState(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(null); // {id}

  const pollingRef = useRef(null);

  // ---- Cargar historial ----
  const fetchHistory = useCallback(async () => {
    try {
      const data = await api.listAudits(connectionId);
      setAudits(data);
      return data;
    } catch (e) {
      setError(e.message);
      return [];
    }
  }, [connectionId]);

  // ---- Iniciar/detener polling ----
  const startPolling = useCallback(() => {
    if (pollingRef.current) return;
    pollingRef.current = setInterval(async () => {
      const data = await fetchHistory();
      const hasRunning = data.some(a => a.status === "running");
      if (!hasRunning) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
        // Si el audit seleccionado acaba de completarse, recargar el reporte
        setSelectedAuditId(prev => {
          if (prev) {
            const found = data.find(a => a.id === prev);
            if (found?.status === "completed") {
              loadReport(prev);
            }
          }
          return prev;
        });
      }
    }, 3000);
  }, [fetchHistory]);

  useEffect(() => {
    // Obtener nombre de conexión
    api.getConnection(connectionId).then(c => setConnectionName(c.name)).catch(() => {});
    fetchHistory().then(data => {
      if (data.some(a => a.status === "running")) startPolling();
    });
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
  }, [connectionId]);

  // ---- Cargar reporte completo ----
  const loadReport = async (auditId) => {
    setSelectedAuditId(auditId);
    setLoadingReport(true);
    setReport(null);
    try {
      const data = await api.getAuditReport(auditId);
      setReport(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoadingReport(false);
    }
  };

  // ---- Iniciar auditoría ----
  const handleStart = async () => {
    setStarting(true);
    setError("");
    try {
      const { audit_id } = await api.startAudit(connectionId);
      await fetchHistory();
      setSelectedAuditId(audit_id);
      setReport(null);
      startPolling();
    } catch (e) {
      setError(e.message);
    } finally {
      setStarting(false);
    }
  };

  // ---- Eliminar auditoría ----
  const handleDeleteAudit = async () => {
    const { id } = confirmDelete;
    setConfirmDelete(null);
    try {
      await api.deleteAudit(id);
      if (selectedAuditId === id) { setSelectedAuditId(null); setReport(null); }
      await fetchHistory();
    } catch (e) {
      setError(e.message);
    }
  };

  const dl = (url) => window.open(url, "_blank");

  const selectedAudit = audits.find(a => a.id === selectedAuditId);

  return (
    <div>
      {/* Cabecera */}
      <div className="flex items-center gap-4 mb-6">
        <button className="btn-secondary py-1.5 px-3 text-sm" onClick={() => navigate("/")}>
          <ArrowLeft className="w-4 h-4" /> Volver
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-gray-900">Auditoría de Firewall</h1>
          {connectionName && <p className="text-sm text-gray-500">{connectionName}</p>}
        </div>
        <button className="btn-primary" onClick={handleStart} disabled={starting}>
          {starting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          Nueva auditoría
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 mb-4">
          <AlertCircle className="w-5 h-5 flex-shrink-0" /><span className="text-sm">{error}</span>
        </div>
      )}

      {/* Tabla de historial */}
      <div className="card mb-6">
        <h2 className="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">
          <Clock className="w-4 h-4 text-brand-700" /> Historial de auditorías
        </h2>

        {audits.length === 0 ? (
          <p className="text-sm text-gray-400 italic py-4 text-center">
            Sin auditorías registradas. Haz clic en "Nueva auditoría" para comenzar.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">#</th>
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">Fecha</th>
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">Estado</th>
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">Score</th>
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">Críticos</th>
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">Warnings</th>
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">Info</th>
                  <th className="text-left px-3 py-2 text-gray-600 font-semibold">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((a) => (
                  <tr key={a.id}
                    className={`border-b last:border-0 transition-colors ${selectedAuditId === a.id ? "bg-brand-50" : "hover:bg-gray-50"}`}>
                    <td className="px-3 py-2 text-gray-500 text-xs">{a.seq ?? a.id}</td>
                    <td className="px-3 py-2 text-gray-700 whitespace-nowrap">
                      {fmtDate(a.created_at)}
                    </td>
                    <td className="px-3 py-2"><StatusBadge status={a.status} /></td>
                    <td className="px-3 py-2 font-bold">
                      {a.summary
                        ? <span className={a.summary.score >= 80 ? "text-green-600" : a.summary.score >= 50 ? "text-yellow-600" : "text-red-600"}>
                            {a.summary.score}
                          </span>
                        : "—"}
                    </td>
                    <td className="px-3 py-2 text-red-600 font-semibold">{a.summary?.critical ?? "—"}</td>
                    <td className="px-3 py-2 text-yellow-700 font-semibold">{a.summary?.warning ?? "—"}</td>
                    <td className="px-3 py-2 text-blue-600 font-semibold">{a.summary?.info ?? "—"}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1">
                        {a.status === "completed" && (
                          <>
                            <button title="Ver reporte" className="p-1 text-gray-400 hover:text-brand-700 transition-colors" onClick={() => loadReport(a.id)}>
                              <Eye className="w-4 h-4" />
                            </button>
                            <button title="Topología de red" className="p-1 text-gray-400 hover:text-teal-600 transition-colors" onClick={() => navigate(`/topology/${a.id}`)}>
                              <Network className="w-4 h-4" />
                            </button>
                            <button title="Excel" className="p-1 text-gray-400 hover:text-green-600 transition-colors" onClick={() => dl(api.exportExcelUrl(a.id))}>
                              <FileSpreadsheet className="w-4 h-4" />
                            </button>
                            <button title="PDF" className="p-1 text-gray-400 hover:text-red-600 transition-colors" onClick={() => dl(api.exportPdfUrl(a.id))}>
                              <FileText className="w-4 h-4" />
                            </button>
                            <button title="ZIP" className="p-1 text-gray-400 hover:text-indigo-600 transition-colors" onClick={() => dl(api.exportZipUrl(a.id))}>
                              <FileArchive className="w-4 h-4" />
                            </button>
                          </>
                        )}
                        {a.status === "running" && (
                          <span className="text-xs text-blue-500 flex items-center gap-1">
                            <Loader2 className="w-3 h-3 animate-spin" /> en progreso…
                          </span>
                        )}
                        {a.status === "failed" && (
                          <span className="text-xs text-red-500" title={a.error}>Error</span>
                        )}
                        <button title="Eliminar" className="p-1 text-gray-300 hover:text-red-600 transition-colors ml-1"
                          onClick={() => setConfirmDelete({ id: a.id })}>
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Reporte seleccionado */}
      {loadingReport && (
        <div className="card text-center py-12 text-gray-400">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-brand-700 mb-2" />
          <p className="text-sm">Cargando reporte…</p>
        </div>
      )}

      {selectedAudit?.status === "running" && !report && !loadingReport && (
        <div className="card text-center py-12 text-blue-600">
          <Loader2 className="w-10 h-10 mx-auto animate-spin mb-3" />
          <p className="font-medium">Auditoría en ejecución en segundo plano…</p>
          <p className="text-sm text-gray-400 mt-1">El resultado aparecerá aquí al completarse.</p>
        </div>
      )}

      {report && report.generated_at && !loadingReport && (
        <div>
          {/* Panel de resumen */}
          <div className="card mb-6">
            <div className="flex flex-wrap items-center gap-6">
              <div className="text-center">
                <p className="text-xs text-gray-500 mb-1 font-medium uppercase tracking-wide">Puntaje de salud</p>
                <ScoreRing score={report.summary.score} />
              </div>
              <div className="flex-1 grid grid-cols-3 gap-3 min-w-0">
                {[
                  { label: "Críticos",     key: "critical", cls: "text-red-600 bg-red-50 border-red-100" },
                  { label: "Advertencias", key: "warning",  cls: "text-yellow-700 bg-yellow-50 border-yellow-100" },
                  { label: "Informativos", key: "info",     cls: "text-blue-700 bg-blue-50 border-blue-100" },
                ].map(({ label, key, cls }) => (
                  <div key={key} className={`rounded-xl p-4 border text-center ${cls}`}>
                    <div className="text-3xl font-bold">{report.summary[key]}</div>
                    <div className="text-xs font-medium mt-1">{label}</div>
                  </div>
                ))}
              </div>
              <div className="flex flex-col gap-2 items-start">
                <p className="text-xs text-gray-500 font-medium uppercase tracking-wide">Exportar</p>
                <button className="btn-secondary text-xs py-1.5 px-3 w-full" onClick={() => dl(api.exportExcelUrl(selectedAuditId))}>
                  <FileSpreadsheet className="w-4 h-4 text-green-600" /> Excel
                </button>
                <button className="btn-secondary text-xs py-1.5 px-3 w-full" onClick={() => dl(api.exportPdfUrl(selectedAuditId))}>
                  <FileText className="w-4 h-4 text-red-600" /> PDF
                </button>
                <button className="btn-secondary text-xs py-1.5 px-3 w-full" onClick={() => dl(api.exportZipUrl(selectedAuditId))}>
                  <FileArchive className="w-4 h-4 text-indigo-600" /> ZIP
                </button>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm text-gray-600">
              <div><span className="font-medium text-gray-800">Hostname:</span> {report.system?.hostname || "—"}</div>
              <div><span className="font-medium text-gray-800">Modelo:</span> {report.system?.model || "—"}</div>
              <div><span className="font-medium text-gray-800">Firmware:</span> {report.system?.firmware || "—"}</div>
              <div><span className="font-medium text-gray-800">Timezone:</span> {report.system?.timezone || "—"}</div>
            </div>
            <p className="text-xs text-gray-400 mt-3">Auditoría: {fmtDate(report.generated_at)}</p>
          </div>

          {/* Hallazgos */}
          <Section icon={FileWarning} title="Todos los hallazgos" count={report.issues?.length} defaultOpen={report.summary.critical > 0}>
            {!report.issues?.length
              ? <div className="flex items-center gap-2 text-green-700"><CheckCircle className="w-5 h-5" /> Sin hallazgos detectados</div>
              : [...report.issues].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)).map((issue, i) => <IssueRow key={i} issue={issue} />)
            }
          </Section>

          {report.vendor_health && (
            <Section icon={CheckCircle} title="Verificación de políticas del equipo (Sophos Health Check)" count={`${report.vendor_health.non_compliant} no conformes`}>
              <p className="text-xs text-gray-500 mb-3">
                {report.vendor_health.non_compliant} de {report.vendor_health.total} políticas no conformes
                ({Object.entries(report.vendor_health.by_severity).map(([k, v]) => `${HEALTH_SEV[k] || k}: ${v}`).join(", ") || "ninguna"}).
                Es la evaluación del propio firewall y no forma parte del puntaje de ALFIL.
              </p>
              <DataTable headers={["Severidad", "Módulo", "Política"]}
                rows={report.vendor_health.non_compliant_policies.map(p => [HEALTH_SEV[p.severity] || p.severity, p.module, p.policy])} />
            </Section>
          )}

          {report.coverage?.length > 0 && (
            <Section icon={AlertCircle} title="Alcance de la revisión: secciones no evaluadas" count={report.coverage.length}>
              <p className="text-xs text-gray-500 mb-3">El reporte no afirma nada sobre estas secciones.</p>
              <DataTable headers={["Sección", "Estado", "Motivo"]}
                rows={report.coverage.map(c => [c.label, c.status === "no_disponible" ? "No disponible" : "Error de consulta", c.reason])} />
            </Section>
          )}

          <Section icon={Users} title="Administradores" count={report.sections?.admin_users?.data?.length}>
            {report.sections?.admin_users?.issues?.map((i, idx) => <IssueRow key={idx} issue={i} />)}
            <DataTable headers={["Nombre", "Perfil", "Email", "MFA/OTP", "Restricción"]}
              rows={report.sections?.admin_users?.data?.map(u => [u.name, u.profile, u.email, u.otp_enabled ? "✅ Activo" : "❌ Inactivo", u.login_restriction])} />
          </Section>

          <Section icon={Server} title="Interfaces" count={report.sections?.interfaces?.data?.length}>
            {report.sections?.interfaces?.data?.map((iface, idx) => (
              <div key={idx} className="mb-4 border border-gray-100 rounded-lg overflow-hidden">
                <div className="flex items-center gap-3 px-3 py-2 bg-gray-50 border-b">
                  <span className="font-mono text-sm font-semibold text-gray-800">{iface.name}</span>
                  {iface.hardware && iface.hardware !== iface.name && (
                    <span className="text-xs text-gray-400">({iface.hardware})</span>
                  )}
                  {iface.zone && (
                    <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-brand-50 text-brand-700 border border-brand-200">
                      {iface.zone}{iface.zone_type ? ` · ${iface.zone_type}` : ""}
                    </span>
                  )}
                  <span className={`text-xs px-2 py-0.5 rounded-full ${iface.interface_status === "ON" ? "bg-green-50 text-green-700" : "bg-gray-100 text-gray-500"}`}>
                    {iface.interface_status}
                  </span>
                  {iface.ip_address && (
                    <span className="ml-auto font-mono text-xs text-gray-600">{iface.ip_address}/{iface.netmask}</span>
                  )}
                  <span className="text-xs text-gray-400 max-w-xs truncate">{iface.status}</span>
                </div>
                {/* VLANs */}
                {iface.vlans?.length > 0 && (
                  <div className="px-3 py-1.5 bg-blue-50 border-b">
                    <span className="text-xs font-semibold text-blue-700 mr-2">VLANs:</span>
                    {iface.vlans.map((v, vi) => (
                      <span key={vi} className="inline-flex items-center gap-1 text-xs bg-white border border-blue-200 text-blue-800 rounded px-2 py-0.5 mr-1 font-mono">
                        {v.name} <span className="text-blue-400">VLAN {v.vlan_id}</span>
                        {v.zone && <span className="text-green-700">· {v.zone}</span>}
                        {v.ip_address && <span className="text-gray-500">· {v.ip_address}</span>}
                      </span>
                    ))}
                  </div>
                )}
                {/* Aliases */}
                {iface.aliases?.length > 0 && (
                  <div className="px-3 py-1.5 bg-amber-50">
                    <span className="text-xs font-semibold text-amber-700 mr-2">Aliases:</span>
                    {iface.aliases.map((a, ai) => (
                      <span key={ai} className="inline-flex items-center gap-1 text-xs bg-white border border-amber-200 text-amber-800 rounded px-2 py-0.5 mr-1 font-mono">
                        {a.name} · {a.ip_address}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </Section>

          <Section icon={Route} title="Rutas SD-WAN" count={report.sections?.sdwan_policy_routes?.data?.length}>
            <DataTable headers={["Nombre", "Estado", "Gateway", "Backup GW", "Src Redes", "Dst Redes", "Servicios"]}
              rows={report.sections?.sdwan_policy_routes?.data?.map(r => [r.name, r.status, r.gateway, r.backup_gateway, r.source_networks?.join(", "), r.destination_networks?.join(", "), r.services?.join(", ")])} />
          </Section>

          <Section icon={Settings} title="Acceso al Dispositivo (ACLs Locales)" count={report.sections?.device_access?.data?.length}>
            <DataTable headers={["Nombre regla", "Zona origen", "Hosts", "Servicios", "Acción"]}
              rows={report.sections?.device_access?.data?.map(a => [a.rule_name, a.source_zone, a.hosts?.join(", "), a.services?.join(", "), a.action])} />
          </Section>
        </div>
      )}

      {confirmDelete && (
        <ConfirmModal
          title="Eliminar auditoría"
          message="¿Eliminar este registro de auditoría? Se perderán todos los datos del reporte."
          confirmLabel="Sí, eliminar"
          onConfirm={handleDeleteAudit}
          onCancel={() => setConfirmDelete(null)}
        />
      )}
    </div>
  );
}
