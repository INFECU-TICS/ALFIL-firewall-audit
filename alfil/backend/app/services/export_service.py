"""
Generación de reportes exportables: Excel, PDF, ZIP.
Todas las funciones reciben el dict `report` de audit_service y devuelven io.BytesIO.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
SEVERITY_LABEL = {"critical": "Crítico", "warning": "Advertencia", "info": "Informativo"}
HEALTH_SEVERITY_LABEL = {"high": "Alta", "medium": "Media", "low": "Baja", "veryLow": "Muy baja"}
CATEGORY_LABEL = {
    "admin_users": "Administradores", "device_access": "Acceso al dispositivo", "system": "Sistema", "firewall_rules": "Reglas de firewall",
    "nat_rules": "Reglas NAT", "hosts": "Objetos (hosts)", "zones": "Zonas", "notifications": "Notificaciones",
}
COVERAGE_STATUS_LABEL = {"no_disponible": "No disponible", "error": "Error de consulta"}


def fmt_date(value: str) -> str:
    """ISO 8601 -> «2026-11-13 15:53 UTC» (si no se puede interpretar, se devuelve tal cual)."""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M") + (" UTC" if dt.utcoffset() is not None else "")
    except ValueError:
        return str(value or "")


def sev_label(sev: str) -> str:
    return SEVERITY_LABEL.get(sev, str(sev).capitalize())


def category_label(cat: str) -> str:
    return CATEGORY_LABEL.get(cat, str(cat).replace("_", " ").capitalize())


def join(value) -> str:
    return ", ".join(str(v) for v in value) if isinstance(value, (list, tuple)) else ("" if value is None else str(value))


def sorted_issues(report: dict) -> list:
    return sorted(report.get("issues", []), key=lambda i: SEVERITY_ORDER.get(i["severity"], 9))


# Hojas de datos del Excel: (título, sección del reporte, columnas [(encabezado, función(fila) -> valor)])
def _g(key):
    return lambda r: join(r.get(key))


DATA_SHEETS = [
    ("Reglas Firewall", "firewall_rules", [("Nombre", _g("name")), ("Estado", _g("status")), ("Acción", _g("action")), ("Zonas origen", _g("source_zones")),
        ("Zonas destino", _g("destination_zones")), ("Redes origen", _g("source_networks")), ("Redes destino", _g("destination_networks")),
        ("Servicios", _g("services")), ("Log", _g("log_traffic")), ("Descripción", _g("description"))]),
    ("Reglas NAT", "nat_rules", [("Nombre", _g("name")), ("Estado", _g("status")), ("Tipo NAT", _g("nat_type")), ("Zonas origen", _g("source_zones")),
        ("Origen original", _g("original_source")), ("Origen traducido", _g("translated_source")), ("Destino original", _g("original_destination")),
        ("Destino traducido", _g("translated_destination")), ("Servicio original", _g("original_service")),
        ("Servicio traducido", _g("translated_service")), ("Log", _g("log_traffic"))]),
    ("Administradores", "admin_users", [("Nombre", _g("name")), ("Perfil", _g("profile")), ("Correo", _g("email")),
        ("MFA/OTP", lambda u: "Sí" if u.get("otp_enabled") else "NO"), ("Restricción", _g("login_restriction")), ("Redes permitidas", _g("allowed_networks"))]),
    ("Acceso al dispositivo", "device_access", [("Regla / zona", _g("rule_name")), ("Zona origen", _g("source_zone")), ("Servicios", _g("services")),
        ("Redes", _g("hosts")), ("Acción", _g("action"))]),
    ("Usuarios", "auth_users", [("Usuario", _g("username")), ("Nombre", _g("name")), ("Tipo", _g("user_type")), ("Grupo", _g("group")), ("Estado", _g("status"))]),
    ("Zonas", "zones", [("Nombre", _g("name")), ("Tipo", _g("type")), ("Descripción", _g("description"))]),
    ("Interfaces", "interfaces", [("Nombre", _g("name")), ("Tipo", _g("type")), ("IP", _g("ip_address")), ("Máscara", _g("netmask")),
        ("Zona", _g("zone")), ("Estado", _g("status"))]),
    ("VLAN", "vlans", [("Nombre", _g("name")), ("ID", _g("vlan_id")), ("Interfaz", _g("interface")), ("Zona", _g("zone")), ("IP", _g("ip_address")), ("Máscara", _g("netmask"))]),
    ("Rutas", "static_routes", [("Nombre", _g("Name")), ("Destino", _g("DestinationIP")), ("Máscara", _g("Netmask")), ("Gateway", _g("Gateway")), ("Interfaz", _g("Interface")), ("Métrica", _g("Distance"))]),
    ("VPN IPsec", "vpn_ipsec_connections", [("Nombre", _g("name")), ("Estado", _g("status")), ("Tipo", _g("connection_type")), ("Gateway remoto", _g("remote_gateway"))]),
    ("Hosts", "hosts", [("Nombre", _g("name")), ("Tipo", _g("type")), ("IP", _g("ip_address")), ("Subred", _g("subnet")), ("IP inicio", _g("start_ip")), ("IP fin", _g("end_ip"))]),
    ("Grupos de hosts", "host_groups", [("Nombre", _g("name")), ("Miembros", _g("hosts")), ("Descripción", _g("description"))]),
    ("Hosts FQDN", "fqdn_hosts", [("Nombre", _g("name")), ("FQDN", _g("fqdn")), ("Grupos", _g("groups"))]),
    ("Servicios", "services", [("Nombre", _g("name")), ("Tipo", _g("type")), ("Protocolo", _g("protocol"))]),
    ("Horarios", "schedules", [("Nombre", _g("name")), ("Tipo", _g("type")), ("Días", _g("days")), ("Desde", _g("start_time")), ("Hasta", _g("stop_time"))]),
    ("Filtrado web", "web_filter", [("Política", _g("name")), ("Acción por defecto", _g("default_action")), ("Descripción", _g("description"))]),
    ("Control de apps", "app_filter", [("Política", _g("name")), ("Descripción", _g("description"))]),
    ("Inspección TLS", "ssl_tls_rules", [("Regla", _g("name")), ("Estado", _g("enabled")), ("Acción", _g("decrypt_action")), ("Perfil", _g("decryption_profile")),
        ("Zonas origen", _g("source_zones")), ("Zonas destino", _g("destination_zones"))]),
]


def _rows(report: dict, section: str) -> list:
    data = report.get("sections", {}).get(section, {}).get("data", [])
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def _system_rows(report: dict) -> list:
    sys = report.get("system", {}) or {}
    pairs = [("Nombre del equipo", sys.get("hostname")), ("Modelo", sys.get("model")), ("Firmware", sys.get("firmware")),
             ("Tiempo en línea", sys.get("uptime")), ("Zona horaria", sys.get("timezone"))]
    return [(k, v) for k, v in pairs if v]


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

def generate_excel(report: dict) -> io.BytesIO:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    COLORS = {"critical": "FFCCCC", "warning": "FFF2CC", "info": "DAE8FC", "header": "1F3864"}
    HEADER_FONT = Font(bold=True, color="FFFFFF")
    WRAP = Alignment(wrap_text=True, vertical="top")

    def header_row(ws, headers):
        ws.append(headers)
        for cell in ws[ws.max_row]:
            cell.font = HEADER_FONT
            cell.fill = PatternFill("solid", fgColor=COLORS["header"])
            cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.freeze_panes = "A2"

    def auto_width(ws, cap=60):
        for col in ws.columns:
            w = max((len(str(c.value or "")) for c in col), default=10)
            ws.column_dimensions[get_column_letter(col[0].column)].width = min(w + 3, cap)

    def finish(ws, wrap_cols=()):
        auto_width(ws)
        if ws.max_row > 1:
            ws.auto_filter.ref = ws.dimensions
        for row in ws.iter_rows(min_row=2):
            for c in row:
                if c.column in wrap_cols:
                    c.alignment = WRAP

    wb = openpyxl.Workbook()
    summary = report["summary"]

    # ---- Resumen ----
    ws = wb.active
    ws.title = "Resumen"
    ws["A1"] = "Reporte de Salud – ALFIL Firewall Audit"
    ws["A1"].font = Font(bold=True, size=14)
    ws.append(["Equipo", report["connection"]["name"]])
    ws.append(["Host", report["connection"]["host"]])
    ws.append(["Tipo de API", {"rest": "REST (SFOS v23)", "xml": "XML"}.get(report["connection"].get("api_type"), "")])
    ws.append(["Fecha", fmt_date(report["generated_at"])])
    ws.append(["Puntaje", f"{summary['score']} / 100"])
    for k, v in _system_rows(report):
        ws.append([k, v])
    ws.append([])
    ws.append(["Severidad", "Cantidad"])
    ws[f"A{ws.max_row}"].font = ws[f"B{ws.max_row}"].font = Font(bold=True)
    for sev in ("critical", "warning", "info"):
        ws.append([sev_label(sev), summary[sev]])
        ws[f"A{ws.max_row}"].fill = PatternFill("solid", fgColor=COLORS[sev])
    ws.append(["Total", summary["total_issues"]])
    ws[f"A{ws.max_row}"].font = ws[f"B{ws.max_row}"].font = Font(bold=True)
    vh = report.get("vendor_health")
    if vh:
        ws.append([])
        ws.append(["Verificación de políticas del equipo (Sophos)", f"{vh['non_compliant']} no conformes de {vh['total']}"])
    cov = report.get("coverage") or []
    if cov:
        ws.append([])
        ws.append(["Secciones no evaluadas", f"{len(cov)} (ver hoja «Alcance»)"])
    ws.append([])
    ws.append(["Nota", "La revisión se basa en la configuración del equipo; debe ser validada por una persona antes de entregarse a un cliente."])
    auto_width(ws, cap=90)

    # ---- Hallazgos ----
    ws_i = wb.create_sheet("Hallazgos")
    header_row(ws_i, ["Severidad", "Categoría", "Hallazgo", "Detalle", "Recomendación", "Referencia"])
    for issue in sorted_issues(report):
        ws_i.append([sev_label(issue["severity"]), category_label(issue["category"]), issue["title"], issue["detail"],
                     issue.get("recommendation", ""), issue.get("reference", "")])
        color = COLORS.get(issue["severity"])
        if color:
            for col in range(1, 7):
                ws_i.cell(row=ws_i.max_row, column=col).fill = PatternFill("solid", fgColor=color)
    finish(ws_i, wrap_cols=(3, 4, 5, 6))
    for col, w in (("C", 45), ("D", 60), ("E", 60), ("F", 40)):
        ws_i.column_dimensions[col].width = w

    # ---- Verificación del fabricante ----
    if vh:
        ws_v = wb.create_sheet("Verificación Sophos")
        header_row(ws_v, ["Severidad", "Módulo", "Política (no conforme)", "Estándares"])
        for p in vh["non_compliant_policies"]:
            ws_v.append([HEALTH_SEVERITY_LABEL.get(p["severity"], p["severity"]), p["module"], p["policy"], join(p["standards"])])
        finish(ws_v, wrap_cols=(3,))
        ws_v.column_dimensions["C"].width = 90

    # ---- Datos ----
    for title, section, columns in DATA_SHEETS:
        rows = _rows(report, section)
        if not rows:
            continue
        w = wb.create_sheet(title)
        header_row(w, [h for h, _ in columns])
        for r in rows:
            w.append([fn(r) for _, fn in columns])
            if section == "admin_users" and not r.get("otp_enabled"):
                for col in range(1, len(columns) + 1):
                    w.cell(w.max_row, col).fill = PatternFill("solid", fgColor=COLORS["critical"])
        finish(w)

    # ---- Alcance ----
    if cov:
        w = wb.create_sheet("Alcance")
        header_row(w, ["Sección", "Estado", "Motivo"])
        for c in cov:
            w.append([c["label"], COVERAGE_STATUS_LABEL.get(c["status"], c["status"]), c["reason"]])
        finish(w, wrap_cols=(3,))

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def generate_pdf(report: dict) -> io.BytesIO:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether

    SEV_COLORS = {"critical": colors.HexColor("#FFCCCC"), "warning": colors.HexColor("#FFF2CC"), "info": colors.HexColor("#DAE8FC")}
    HEADER_BG = colors.HexColor("#1F3864")

    buf = io.BytesIO()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(2 * cm, 1.2 * cm, f"ALFIL · {report['connection']['name']} · {fmt_date(report['generated_at'])}")
        canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm,
                            title="Reporte de Salud – ALFIL", author="ALFIL")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18, textColor=HEADER_BG)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"], textColor=HEADER_BG, spaceBefore=12)
    body = styles["Normal"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    note = ParagraphStyle("note", parent=body, fontSize=8, textColor=colors.grey)

    def P(text, style=small):  # los nombres de reglas/objetos pueden traer «&», «<»: nunca pasarlos crudos a Paragraph
        return Paragraph(escape(str(text or "")), style)

    def tbl(data, col_widths, extra_styles=None):
        t = Table(data, colWidths=col_widths, repeatRows=1)
        base = [("BACKGROUND", (0, 0), (-1, 0), HEADER_BG), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey), ("FONTSIZE", (0, 0), (-1, -1), 8)]
        t.setStyle(TableStyle(base + (extra_styles or [])))
        return t

    summary = report["summary"]
    story = [Paragraph("Reporte de Salud – ALFIL Firewall Audit", title_style), Spacer(1, 0.3 * cm)]
    story.append(Paragraph(f"<b>Equipo:</b> {escape(report['connection']['name'])} ({escape(str(report['connection']['host']))})", body))
    story.append(Paragraph(f"<b>Fecha:</b> {fmt_date(report['generated_at'])}", body))
    story.append(Paragraph(f"<b>Puntaje:</b> {summary['score']} / 100", body))
    story += [Spacer(1, 0.3 * cm), HRFlowable(width="100%"), Spacer(1, 0.3 * cm)]

    story.append(Paragraph("Resumen de hallazgos", h2_style))
    story.append(tbl([["Severidad", "Cantidad"], ["Crítico", str(summary["critical"])], ["Advertencia", str(summary["warning"])],
                      ["Informativo", str(summary["info"])], ["Total", str(summary["total_issues"])]], [8 * cm, 4 * cm],
                     [("BACKGROUND", (0, 1), (-1, 1), SEV_COLORS["critical"]), ("BACKGROUND", (0, 2), (-1, 2), SEV_COLORS["warning"]),
                      ("BACKGROUND", (0, 3), (-1, 3), SEV_COLORS["info"]), ("FONTNAME", (0, 4), (-1, 4), "Helvetica-Bold")]))

    issues = sorted_issues(report)
    story.append(Paragraph("Hallazgos detallados", h2_style))
    if issues:
        rows, extra = [["Severidad", "Categoría", "Hallazgo", "Detalle y recomendación"]], []
        for idx, i in enumerate(issues, 1):
            text = escape(i["detail"]) + (f"<br/><b>Recomendación:</b> {escape(i['recommendation'])}" if i.get("recommendation") else "")
            rows.append([sev_label(i["severity"]), P(category_label(i["category"])), P(i["title"]), Paragraph(text, small)])
            if SEV_COLORS.get(i["severity"]):
                extra.append(("BACKGROUND", (0, idx), (0, idx), SEV_COLORS[i["severity"]]))
        story.append(tbl(rows, [2 * cm, 2.6 * cm, 5.2 * cm, 7.2 * cm], extra))
    else:
        story.append(Paragraph("Sin hallazgos detectados.", body))

    vh = report.get("vendor_health")
    if vh:
        story.append(Paragraph("Verificación de políticas del equipo (Sophos Health Check)", h2_style))
        by_sev = ", ".join(f"{HEALTH_SEVERITY_LABEL.get(k, k)}: {v}" for k, v in vh["by_severity"].items())
        story.append(Paragraph(f"{vh['non_compliant']} de {vh['total']} políticas no conformes ({by_sev or 'ninguna'}). Es la evaluación del propio "
                               "firewall y no forma parte del puntaje de ALFIL. Se listan las de severidad alta; el detalle completo está en el Excel.", body))
        top = [p for p in vh["non_compliant_policies"] if p["severity"] == "high"][:15]
        if top:
            story += [Spacer(1, 0.2 * cm), tbl([["Módulo", "Política (severidad alta)"]] + [[P(p["module"]), P(p["policy"])] for p in top], [4.5 * cm, 12.5 * cm])]

    cov = report.get("coverage") or []
    story.append(Paragraph("Alcance de la revisión", h2_style))
    if cov:
        story.append(Paragraph("Estas secciones <b>no se evaluaron</b>; el reporte no afirma nada sobre ellas:", body))
        story += [Spacer(1, 0.2 * cm), tbl([["Sección", "Estado", "Motivo"]] + [[P(c["label"]), COVERAGE_STATUS_LABEL.get(c["status"], c["status"]), P(c["reason"])] for c in cov],
                                          [5 * cm, 3 * cm, 9 * cm])]
    else:
        story.append(Paragraph("Todas las secciones se consultaron correctamente.", body))

    sys_rows = _system_rows(report)
    if sys_rows:
        story.append(KeepTogether([Paragraph("Información del sistema", h2_style), tbl([["Campo", "Valor"]] + [[k, P(v)] for k, v in sys_rows], [5 * cm, 12 * cm])]))
    story += [Spacer(1, 0.5 * cm), Paragraph("Revisión basada en la configuración del equipo. Debe ser validada por una persona antes de entregarse a un cliente.", note)]

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------

# Mapeo de sección del reporte → nombre de archivo JSON en el ZIP
_SECTION_JSON_FILES = {
    "admin_users":            "admin_users.json",
    "auth_users":             "auth_users.json",
    "device_access":          "local_acl.json",
    "zones":                  "zones.json",
    "interfaces":             "interfaces.json",
    "vlans":                  "vlans.json",
    "aliases":                "aliases.json",
    "lags":                   "lags.json",
    "dns":                    "dns.json",
    "dns_request_routes":     "dns_routes.json",
    "gateways":               "gateways.json",
    "static_routes":          "static_routes.json",
    "sdwan_policy_routes":    "sdwan_routes.json",
    "sdwan_profiles":         "sdwan_profiles.json",
    "health_check_profiles":  "health_checks.json",
    "hosts":                  "ip_hosts.json",
    "host_groups":            "ip_host_groups.json",
    "mac_hosts":              "mac_hosts.json",
    "fqdn_hosts":             "fqdn_hosts.json",
    "fqdn_host_groups":       "fqdn_host_groups.json",
    "services":               "services.json",
    "service_groups":         "service_groups.json",
    "firewall_rules":         "fw_rules.json",
    "firewall_rule_groups":   "fw_rule_groups.json",
    "nat_rules":              "nat_rules.json",
    "ssl_tls_rules":          "ssl_tls_rules.json",
    "ssl_tls_settings":       "ssl_tls_settings.json",
    "web_filter":             "web_filter_policies.json",
    "web_filter_exceptions":  "web_filter_exceptions.json",
    "app_filter":             "app_filter_policies.json",
    "vpn_ipsec_connections":  "vpn_ipsec.json",
    "schedules":              "schedules.json",
    "decryption_profiles":    "decryption_profiles.json",
    "access_time_policies":   "access_time_policies.json",
    "surfing_quota_policies":  "surfing_quotas.json",
    "data_transfer_policies":  "data_transfer_policies.json",
    "backup_restore":          "backup_restore.json",
    "notifications":           "notifications.json",
}


def _extract_raw_data(section_data) -> list | dict | None:
    """
    Extrae los datos crudos de una sección del reporte para exportar al ZIP.
    - Si es una lista de objetos con campo 'raw', devuelve la lista de 'raw'.
    - Si es una lista sin 'raw', devuelve la lista tal cual.
    - Si es un dict (ej. configuración global), lo devuelve tal cual.
    """
    if section_data is None:
        return None
    if isinstance(section_data, dict):
        return section_data
    if isinstance(section_data, list):
        if section_data and isinstance(section_data[0], dict) and "raw" in section_data[0]:
            return [item["raw"] for item in section_data]
        return section_data
    return section_data


def generate_zip(report: dict, connection_name: str) -> io.BytesIO:
    buf = io.BytesIO()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    sections = report.get("sections", {})

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Reporte completo
        zf.writestr(f"alfil_audit_{connection_name}_{ts}.json",
                    json.dumps(report, ensure_ascii=False, indent=2, default=str))

        # Archivos JSON individuales por entidad
        for section_key, filename in _SECTION_JSON_FILES.items():
            sec = sections.get(section_key, {})
            raw = _extract_raw_data(sec.get("data"))
            if raw is None:
                continue
            try:
                zf.writestr(
                    f"data/{filename}",
                    json.dumps(raw, ensure_ascii=False, indent=2, default=str),
                )
            except Exception:
                pass

        # Excel y PDF
        try:
            excel_buf = generate_excel(report)
            zf.writestr(f"alfil_audit_{connection_name}_{ts}.xlsx", excel_buf.read())
        except Exception:
            pass
        try:
            pdf_buf = generate_pdf(report)
            zf.writestr(f"alfil_audit_{connection_name}_{ts}.pdf", pdf_buf.read())
        except Exception:
            pass

    buf.seek(0)
    return buf
