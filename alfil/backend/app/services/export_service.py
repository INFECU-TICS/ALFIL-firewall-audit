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


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

def generate_excel(report: dict) -> io.BytesIO:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    COLORS = {
        "critical": "FFCCCC",
        "warning":  "FFF2CC",
        "info":     "DAE8FC",
        "header":   "1F3864",
    }
    HEADER_FONT = Font(bold=True, color="FFFFFF")

    def header_row(ws, headers):
        ws.append(headers)
        for cell in ws[ws.max_row]:
            cell.font = HEADER_FONT
            cell.fill = PatternFill("solid", fgColor=COLORS["header"])
            cell.alignment = Alignment(horizontal="center")

    def auto_width(ws):
        for col in ws.columns:
            w = max((len(str(c.value or "")) for c in col), default=10)
            ws.column_dimensions[get_column_letter(col[0].column)].width = min(w + 4, 60)

    wb = openpyxl.Workbook()

    # ---- Resumen ----
    ws = wb.active
    ws.title = "Resumen"
    ws["A1"] = "Reporte de Salud – ALFIL Firewall Audit"
    ws["A1"].font = Font(bold=True, size=14)
    ws.append(["Equipo", report["connection"]["name"]])
    ws.append(["Host", report["connection"]["host"]])
    ws.append(["Fecha", report["generated_at"]])
    ws.append(["Puntaje", f"{report['summary']['score']} / 100"])
    ws.append([])
    ws.append(["Severidad", "Cantidad"])
    for sev, color in [("critical", COLORS["critical"]), ("warning", COLORS["warning"]), ("info", COLORS["info"])]:
        r = ws.max_row + 1
        ws.append([sev.capitalize(), report["summary"][sev]])
        ws[f"A{r}"].fill = PatternFill("solid", fgColor=color)
    ws.append(["Total", report["summary"]["total_issues"]])

    # ---- Hallazgos ----
    ws_i = wb.create_sheet("Hallazgos")
    header_row(ws_i, ["Severidad", "Categoría", "Título", "Detalle", "Referencia"])
    for issue in sorted(report.get("issues", []), key=lambda i: SEVERITY_ORDER.get(i["severity"], 9)):
        ws_i.append([issue["severity"].upper(), issue["category"], issue["title"], issue["detail"], issue.get("reference", "")])
        row = ws_i.max_row
        color = COLORS.get(issue["severity"])
        if color:
            for col in range(1, 6):
                ws_i.cell(row=row, column=col).fill = PatternFill("solid", fgColor=color)
    auto_width(ws_i)

    # ---- Reglas Firewall ----
    ws_fw = wb.create_sheet("Reglas Firewall")
    header_row(ws_fw, ["Nombre", "Estado", "Acción", "Zonas Origen", "Zonas Destino",
                        "Redes Origen", "Redes Destino", "Servicios", "Log", "Descripción"])
    for r in report.get("sections", {}).get("firewall_rules", {}).get("data", []):
        ws_fw.append([r.get("name"), r.get("status"), r.get("action"),
                      ", ".join(r.get("source_zones", [])), ", ".join(r.get("destination_zones", [])),
                      ", ".join(r.get("source_networks", [])), ", ".join(r.get("destination_networks", [])),
                      ", ".join(r.get("services", [])), r.get("log_traffic"), r.get("description")])
    auto_width(ws_fw)

    # ---- Reglas NAT ----
    ws_nat = wb.create_sheet("Reglas NAT")
    header_row(ws_nat, ["Nombre", "Estado", "Tipo NAT", "Zona Origen", "Orig Src", "Trans Src",
                         "Orig Dst", "Trans Dst", "Orig Svc", "Trans Svc", "Log"])
    for r in report.get("sections", {}).get("nat_rules", {}).get("data", []):
        ws_nat.append([r.get("name"), r.get("status"), r.get("nat_type"),
                       ", ".join(r.get("source_zones", [])),
                       r.get("original_source"), r.get("translated_source"),
                       r.get("original_destination"), r.get("translated_destination"),
                       r.get("original_service"), r.get("translated_service"), r.get("log_traffic")])
    auto_width(ws_nat)

    # ---- Administradores ----
    ws_adm = wb.create_sheet("Administradores")
    header_row(ws_adm, ["Nombre", "Perfil", "Email", "MFA/OTP", "Restricción", "Redes Permitidas"])
    for u in report.get("sections", {}).get("admin_users", {}).get("data", []):
        ws_adm.append([u.get("name"), u.get("profile"), u.get("email"),
                       "Sí" if u.get("otp_enabled") else "NO",
                       u.get("login_restriction"), u.get("allowed_networks")])
        if not u.get("otp_enabled"):
            for col in range(1, 7):
                ws_adm.cell(ws_adm.max_row, col).fill = PatternFill("solid", fgColor=COLORS["critical"])
    auto_width(ws_adm)

    # ---- Hosts ----
    ws_h = wb.create_sheet("Hosts")
    header_row(ws_h, ["Nombre", "Tipo", "IP", "Subred", "IP Inicio", "IP Fin"])
    for h in report.get("sections", {}).get("hosts", {}).get("data", []):
        ws_h.append([h.get("name"), h.get("type"), h.get("ip_address"), h.get("subnet"), h.get("start_ip"), h.get("end_ip")])
    auto_width(ws_h)

    # ---- Zonas ----
    ws_z = wb.create_sheet("Zonas")
    header_row(ws_z, ["Nombre", "Tipo", "Descripción"])
    for z in report.get("sections", {}).get("zones", {}).get("data", []):
        ws_z.append([z.get("name"), z.get("type"), z.get("description")])
    auto_width(ws_z)

    # ---- Interfaces ----
    ws_if = wb.create_sheet("Interfaces")
    header_row(ws_if, ["Nombre", "Tipo", "IP", "Máscara", "Zona", "Estado"])
    for i in report.get("sections", {}).get("interfaces", {}).get("data", []):
        ws_if.append([i.get("name"), i.get("type"), i.get("ip_address"), i.get("netmask"), i.get("zone"), i.get("status")])
    auto_width(ws_if)

    # ---- Servicios ----
    ws_svc = wb.create_sheet("Servicios")
    header_row(ws_svc, ["Nombre", "Tipo", "Protocolo"])
    for s in report.get("sections", {}).get("services", {}).get("data", []):
        ws_svc.append([s.get("name"), s.get("type"), s.get("protocol")])
    auto_width(ws_svc)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def generate_pdf(report: dict) -> io.BytesIO:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER

    SEV_COLORS = {
        "critical": colors.HexColor("#FFCCCC"),
        "warning":  colors.HexColor("#FFF2CC"),
        "info":     colors.HexColor("#DAE8FC"),
    }
    HEADER_BG = colors.HexColor("#1F3864")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18, textColor=HEADER_BG)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"], textColor=HEADER_BG, spaceBefore=12)
    body = styles["Normal"]

    def tbl(data, col_widths, extra_styles=None):
        t = Table(data, colWidths=col_widths)
        base = [
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("GRID",       (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ]
        if extra_styles:
            base.extend(extra_styles)
        t.setStyle(TableStyle(base))
        return t

    story = []
    story.append(Paragraph("Reporte de Salud – ALFIL Firewall Audit", title_style))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(f"<b>Equipo:</b> {report['connection']['name']} ({report['connection']['host']})", body))
    story.append(Paragraph(f"<b>Fecha:</b> {report['generated_at']}", body))
    story.append(Paragraph(f"<b>Puntaje:</b> {report['summary']['score']} / 100", body))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%"))
    story.append(Spacer(1, 0.3*cm))

    # Resumen
    story.append(Paragraph("Resumen de Hallazgos", h2_style))
    summary_data = [["Severidad", "Cantidad"],
                    ["Crítico", str(report["summary"]["critical"])],
                    ["Advertencia", str(report["summary"]["warning"])],
                    ["Informativo", str(report["summary"]["info"])],
                    ["Total", str(report["summary"]["total_issues"])]]
    t = tbl(summary_data, [8*cm, 4*cm], [
        ("BACKGROUND", (0, 1), (-1, 1), SEV_COLORS["critical"]),
        ("BACKGROUND", (0, 2), (-1, 2), SEV_COLORS["warning"]),
        ("BACKGROUND", (0, 3), (-1, 3), SEV_COLORS["info"]),
        ("FONTNAME",   (0, 4), (-1, 4), "Helvetica-Bold"),
    ])
    story.append(t)
    story.append(Spacer(1, 0.4*cm))

    # Hallazgos
    story.append(Paragraph("Hallazgos Detallados", h2_style))
    sorted_issues = sorted(report.get("issues", []), key=lambda i: SEVERITY_ORDER.get(i["severity"], 9))
    if sorted_issues:
        rows = [["Sev.", "Categoría", "Título", "Detalle"]]
        extra = []
        for idx, issue in enumerate(sorted_issues, 1):
            rows.append([issue["severity"].upper(), issue["category"],
                         Paragraph(issue["title"], body), Paragraph(issue["detail"], body)])
            bg = SEV_COLORS.get(issue["severity"])
            if bg:
                extra.append(("BACKGROUND", (0, idx), (1, idx), bg))
        story.append(tbl(rows, [1.5*cm, 3*cm, 6*cm, 7.5*cm], extra))
    else:
        story.append(Paragraph("Sin hallazgos detectados.", body))

    story.append(Spacer(1, 0.4*cm))

    # Sistema
    story.append(Paragraph("Información del Sistema", h2_style))
    sys = report.get("system", {})
    sys_data = [["Campo", "Valor"],
                ["Hostname", sys.get("hostname", "")], ["Modelo", sys.get("model", "")],
                ["Firmware", sys.get("firmware", "")], ["Uptime", sys.get("uptime", "")],
                ["Timezone", sys.get("timezone", "")]]
    story.append(tbl(sys_data, [5*cm, 12*cm]))

    doc.build(story)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------

def generate_zip(report: dict, connection_name: str) -> io.BytesIO:
    buf = io.BytesIO()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"alfil_audit_{connection_name}_{ts}.json",
                    json.dumps(report, ensure_ascii=False, indent=2, default=str))
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
