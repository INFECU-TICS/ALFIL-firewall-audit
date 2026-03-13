import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft, Play, Download, FileSpreadsheet, FileText,
  Loader2, AlertCircle, CheckCircle, ChevronDown, ChevronRight,
  Shield, Users, Globe, Server, List, FileWarning
} from "lucide-react";
import { api } from "../api";
import { SeverityBadge, ScoreRing } from "../components/IssuesBadge";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function Section({ icon: Icon, title, count, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="card mb-4">
      <button className="w-full flex items-center gap-3 text-left" onClick={() => setOpen((o) => !o)}>
        <Icon className="w-5 h-5 text-brand-700 flex-shrink-0" />
        <span className="font-semibold text-gray-800 flex-1">{title}</span>
        {count !== undefined && (
          <span className="text-xs bg-gray-100 text-gray-600 rounded-full px-2 py-0.5">{count}</span>
        )}
        {open ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />}
      </button>
      {open && <div className="mt-4 border-t pt-4">{children}</div>}
    </div>
  );
}

function IssueRow({ issue }) {
  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg mb-2 text-sm ${
      issue.severity === "critical" ? "bg-red-50 border border-red-100" :
      issue.severity === "warning"  ? "bg-yellow-50 border border-yellow-100" :
                                      "bg-blue-50 border border-blue-100"
    }`}>
      <SeverityBadge severity={issue.severity} />
      <div className="flex-1 min-w-0">
        <p className="font-medium text-gray-800">{issue.title}</p>
        <p className="text-gray-600 text-xs mt-0.5">{issue.detail}</p>
      </div>
    </div>
  );
}

function DataTable({ headers, rows }) {
  if (!rows || rows.length === 0) return <p className="text-sm text-gray-400 italic">Sin datos disponibles</p>;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-xs">
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h} className="text-left px-3 py-2 bg-gray-50 text-gray-600 font-semibold border-b">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b last:border-0 hover:bg-gray-50">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2 text-gray-700 max-w-xs truncate" title={String(cell)}>{cell ?? "—"}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Página
// ---------------------------------------------------------------------------
export default function AuditPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");

  const runAudit = async () => {
    setRunning(true);
    setError("");
    setReport(null);
    try {
      const data = await api.runAudit(id);
      setReport(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  };

  const download = (url) => { window.open(url, "_blank"); };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <button className="btn-secondary py-1.5 px-3 text-sm" onClick={() => navigate("/")}>
          <ArrowLeft className="w-4 h-4" /> Volver
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-gray-900">Auditoría de Firewall</h1>
          {report && <p className="text-sm text-gray-500">{report.connection?.name} — {report.connection?.host}</p>}
        </div>
        <button className="btn-primary" onClick={runAudit} disabled={running}>
          {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {running ? "Auditando…" : report ? "Re-auditar" : "Iniciar auditoría"}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 mb-4">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Waiting state */}
      {!running && !report && !error && (
        <div className="card text-center py-20 text-gray-400">
          <Shield className="w-12 h-12 mx-auto mb-3 text-gray-200" />
          <p className="text-lg font-medium mb-1">Listo para auditar</p>
          <p className="text-sm">Haz clic en "Iniciar auditoría" para analizar el firewall.</p>
        </div>
      )}

      {/* Running indicator */}
      {running && (
        <div className="card text-center py-20 text-gray-500">
          <Loader2 className="w-10 h-10 mx-auto mb-4 animate-spin text-brand-700" />
          <p className="font-medium">Recolectando datos del firewall…</p>
          <p className="text-sm text-gray-400 mt-1">Esto puede tardar hasta 60 segundos según el equipo.</p>
        </div>
      )}

      {/* Report */}
      {report && !running && (
        <div>
          {/* Summary bar */}
          <div className="card mb-6">
            <div className="flex flex-wrap items-center gap-6">
              <div className="text-center">
                <p className="text-xs text-gray-500 mb-1 font-medium uppercase tracking-wide">Puntaje de salud</p>
                <ScoreRing score={report.summary.score} />
              </div>
              <div className="flex-1 grid grid-cols-3 gap-3 min-w-0">
                {[
                  { label: "Críticos", key: "critical", cls: "text-red-600 bg-red-50 border-red-100" },
                  { label: "Advertencias", key: "warning", cls: "text-yellow-700 bg-yellow-50 border-yellow-100" },
                  { label: "Informativos", key: "info", cls: "text-blue-700 bg-blue-50 border-blue-100" },
                ].map(({ label, key, cls }) => (
                  <div key={key} className={`rounded-xl p-4 border text-center ${cls}`}>
                    <div className="text-3xl font-bold">{report.summary[key]}</div>
                    <div className="text-xs font-medium mt-1">{label}</div>
                  </div>
                ))}
              </div>
              {/* Export buttons */}
              <div className="flex flex-col gap-2 items-start">
                <p className="text-xs text-gray-500 font-medium uppercase tracking-wide">Exportar</p>
                <button className="btn-secondary text-xs py-1.5 px-3 w-full" onClick={() => download(api.exportExcelUrl(id))}>
                  <FileSpreadsheet className="w-4 h-4 text-green-600" /> Excel
                </button>
                <button className="btn-secondary text-xs py-1.5 px-3 w-full" onClick={() => download(api.exportPdfUrl(id))}>
                  <FileText className="w-4 h-4 text-red-600" /> PDF
                </button>
              </div>
            </div>

            {/* System info */}
            <div className="mt-4 pt-4 border-t grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm text-gray-600">
              <div><span className="font-medium text-gray-800">Hostname:</span> {report.system?.hostname || "—"}</div>
              <div><span className="font-medium text-gray-800">Modelo:</span> {report.system?.model || "—"}</div>
              <div><span className="font-medium text-gray-800">Firmware:</span> {report.system?.firmware || "—"}</div>
              <div><span className="font-medium text-gray-800">Timezone:</span> {report.system?.timezone || "—"}</div>
            </div>
            <p className="text-xs text-gray-400 mt-3">Auditoría realizada: {new Date(report.generated_at).toLocaleString()}</p>
          </div>

          {/* All issues */}
          <Section icon={FileWarning} title="Todos los hallazgos" count={report.issues?.length} defaultOpen={report.summary.critical > 0}>
            {report.issues?.length === 0
              ? <div className="flex items-center gap-2 text-green-700"><CheckCircle className="w-5 h-5" /> Sin hallazgos detectados</div>
              : [...report.issues]
                  .sort((a, b) => ({ critical: 0, warning: 1, info: 2 }[a.severity] - ({ critical: 0, warning: 1, info: 2 }[b.severity])))
                  .map((issue, i) => <IssueRow key={i} issue={issue} />)
            }
          </Section>

          {/* Admins */}
          <Section icon={Users} title="Administradores" count={report.sections?.admin_users?.data?.length}>
            {report.sections?.admin_users?.issues?.map((i, idx) => <IssueRow key={idx} issue={i} />)}
            <DataTable
              headers={["Nombre", "Perfil", "Email", "MFA/OTP", "Restricción"]}
              rows={report.sections?.admin_users?.data?.map((u) => [
                u.name, u.profile, u.email,
                u.otp_enabled ? "✅ Activo" : "❌ Inactivo",
                u.login_restriction,
              ])}
            />
          </Section>

          {/* Firewall rules */}
          <Section icon={Shield} title="Reglas de Firewall" count={report.sections?.firewall_rules?.stats?.total}>
            {report.sections?.firewall_rules?.issues?.map((i, idx) => <IssueRow key={idx} issue={i} />)}
            {report.sections?.firewall_rules?.stats && (
              <div className="flex gap-4 text-sm text-gray-600 mb-3">
                <span>Total: <b>{report.sections.firewall_rules.stats.total}</b></span>
                <span>Activas: <b className="text-green-700">{report.sections.firewall_rules.stats.enabled}</b></span>
                <span>Deshabilitadas: <b className="text-gray-500">{report.sections.firewall_rules.stats.disabled}</b></span>
                <span>Sin log: <b className="text-yellow-600">{report.sections.firewall_rules.stats.no_log}</b></span>
                <span>Any→Any: <b className="text-red-600">{report.sections.firewall_rules.stats.any_any}</b></span>
                <span>Duplicadas: <b className="text-orange-600">{report.sections.firewall_rules.stats.duplicates}</b></span>
              </div>
            )}
            <DataTable
              headers={["Nombre", "Estado", "Acción", "Src Zonas", "Dst Zonas", "Src Redes", "Dst Redes", "Log"]}
              rows={report.sections?.firewall_rules?.data?.map((r) => [
                r.name, r.status, r.action,
                r.source_zones?.join(", "), r.destination_zones?.join(", "),
                r.source_networks?.join(", "), r.destination_networks?.join(", "),
                r.log_traffic,
              ])}
            />
          </Section>

          {/* NAT rules */}
          <Section icon={Globe} title="Reglas NAT" count={report.sections?.nat_rules?.stats?.total}>
            {report.sections?.nat_rules?.issues?.map((i, idx) => <IssueRow key={idx} issue={i} />)}
            <DataTable
              headers={["Nombre", "Estado", "Tipo NAT", "Zona Origen", "Orig Src", "Trans Src", "Orig Dst", "Trans Dst", "Log"]}
              rows={report.sections?.nat_rules?.data?.map((r) => [
                r.name, r.status, r.nat_type,
                r.source_zones?.join(", "),
                r.original_source, r.translated_source,
                r.original_destination, r.translated_destination,
                r.log_traffic,
              ])}
            />
          </Section>

          {/* Hosts */}
          <Section icon={Server} title="Objetos de Red (Hosts)" count={report.sections?.hosts?.data?.length}>
            {report.sections?.hosts?.issues?.map((i, idx) => <IssueRow key={idx} issue={i} />)}
            <DataTable
              headers={["Nombre", "Tipo", "IP", "Subred"]}
              rows={report.sections?.hosts?.data?.map((h) => [h.name, h.type, h.ip_address, h.subnet])}
            />
          </Section>

          {/* Zones */}
          <Section icon={List} title="Zonas de Red" count={report.sections?.zones?.data?.length}>
            {report.sections?.zones?.issues?.map((i, idx) => <IssueRow key={idx} issue={i} />)}
            <DataTable
              headers={["Nombre", "Tipo", "Descripción"]}
              rows={report.sections?.zones?.data?.map((z) => [z.name, z.type, z.description])}
            />
          </Section>

          {/* Web filter */}
          <Section icon={Shield} title="Políticas de Control Web" count={report.sections?.web_filter?.data?.length}>
            <DataTable
              headers={["Nombre", "Descripción", "Acción por defecto"]}
              rows={report.sections?.web_filter?.data?.map((p) => [p.name, p.description, p.default_action])}
            />
          </Section>

          {/* App filter */}
          <Section icon={Shield} title="Políticas de Control de Aplicaciones" count={report.sections?.app_filter?.data?.length}>
            <DataTable
              headers={["Nombre", "Descripción"]}
              rows={report.sections?.app_filter?.data?.map((p) => [p.name, p.description])}
            />
          </Section>
        </div>
      )}
    </div>
  );
}
