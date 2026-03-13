import io
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.connection import ConnectionConfig
from app.services.audit_service import generate_audit_report
from app.services.crypto import get_encryption_manager
from app.services.sophos_client import SophosFirewallClient

router = APIRouter(prefix="/audit", tags=["audit"])

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def _get_client(obj: ConnectionConfig) -> SophosFirewallClient:
    password = get_encryption_manager().decrypt(obj.password_encrypted)
    return SophosFirewallClient(
        host=obj.host,
        port=obj.port,
        username=obj.username,
        password=password,
        verify_ssl=obj.verify_ssl,
    )


def _get_connection_or_404(connection_id: int, db: Session) -> ConnectionConfig:
    obj = db.query(ConnectionConfig).filter(ConnectionConfig.id == connection_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    return obj


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/{connection_id}")
def run_audit(connection_id: int, db: Session = Depends(get_db)):
    """Ejecuta la auditoría completa y devuelve el reporte en JSON."""
    obj = _get_connection_or_404(connection_id, db)
    client = _get_client(obj)

    raw_data = client.collect_audit_data()
    connection_info = {
        "id": obj.id,
        "name": obj.name,
        "host": obj.host,
        "port": obj.port,
        "username": obj.username,
        "owner": getattr(obj, "owner", ""),
    }
    report = generate_audit_report(connection_info, raw_data)
    return report


@router.get("/{connection_id}/export/excel")
def export_excel(connection_id: int, db: Session = Depends(get_db)):
    """Exporta el reporte de auditoría como archivo Excel (.xlsx)."""
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl no está instalado")

    obj = _get_connection_or_404(connection_id, db)
    client = _get_client(obj)
    raw_data = client.collect_audit_data()
    connection_info = {"id": obj.id, "name": obj.name, "host": obj.host, "port": obj.port, "username": obj.username}
    report = generate_audit_report(connection_info, raw_data)

    wb = openpyxl.Workbook()

    # ---- Colores ----
    COLORS = {
        "critical": "FFCCCC",
        "warning":  "FFF2CC",
        "info":     "DAE8FC",
        "ok":       "D5E8D4",
        "header":   "1F3864",
    }
    HEADER_FONT = Font(bold=True, color="FFFFFF")

    def make_header_row(ws, headers: list[str]):
        ws.append(headers)
        for cell in ws[ws.max_row]:
            cell.font = HEADER_FONT
            cell.fill = PatternFill("solid", fgColor=COLORS["header"])
            cell.alignment = Alignment(horizontal="center")

    def auto_width(ws):
        for col in ws.columns:
            max_len = max((len(str(c.value or "")) for c in col), default=10)
            ws.column_dimensions[get_column_letter(col[0].column)].width = min(max_len + 4, 60)

    # ---- Hoja: Resumen ----
    ws = wb.active
    ws.title = "Resumen"
    ws.append(["Reporte de Salud - Sophos Firewall"])
    ws["A1"].font = Font(bold=True, size=14)
    ws.append(["Equipo", report["connection"]["name"]])
    ws.append(["Host", report["connection"]["host"]])
    ws.append(["Fecha de auditoría", report["generated_at"]])
    ws.append(["Puntaje de salud", f"{report['summary']['score']} / 100"])
    ws.append([])
    ws.append(["Severidad", "Cantidad"])
    for sev in ("critical", "warning", "info"):
        row = ws.max_row + 1
        ws.append([sev.capitalize(), report["summary"][sev]])
        ws[f"A{row}"].fill = PatternFill("solid", fgColor=COLORS[sev])
    ws.append(["Total hallazgos", report["summary"]["total_issues"]])

    # ---- Hoja: Hallazgos ----
    ws_issues = wb.create_sheet("Hallazgos")
    make_header_row(ws_issues, ["Severidad", "Categoría", "Título", "Detalle", "Referencia"])
    sorted_issues = sorted(report["issues"], key=lambda i: SEVERITY_ORDER.get(i["severity"], 99))
    for issue in sorted_issues:
        ws_issues.append([
            issue["severity"].upper(),
            issue["category"],
            issue["title"],
            issue["detail"],
            issue.get("reference", ""),
        ])
        row_num = ws_issues.max_row
        color = COLORS.get(issue["severity"], "FFFFFF")
        for col in range(1, 6):
            ws_issues.cell(row=row_num, column=col).fill = PatternFill("solid", fgColor=color)
    auto_width(ws_issues)

    # ---- Hoja: Reglas Firewall ----
    ws_fw = wb.create_sheet("Reglas Firewall")
    make_header_row(ws_fw, ["Nombre", "Estado", "Acción", "Zonas Origen", "Zonas Destino",
                             "Redes Origen", "Redes Destino", "Servicios", "Log", "Descripción"])
    for r in report["sections"]["firewall_rules"]["data"]:
        ws_fw.append([
            r.get("name", ""),
            r.get("status", ""),
            r.get("action", ""),
            ", ".join(r.get("source_zones", [])),
            ", ".join(r.get("destination_zones", [])),
            ", ".join(r.get("source_networks", [])),
            ", ".join(r.get("destination_networks", [])),
            ", ".join(r.get("services", [])),
            r.get("log_traffic", ""),
            r.get("description", ""),
        ])
    auto_width(ws_fw)

    # ---- Hoja: Reglas NAT ----
    ws_nat = wb.create_sheet("Reglas NAT")
    make_header_row(ws_nat, ["Nombre", "Estado", "Tipo NAT", "Zona Origen", "Origen Original",
                              "Origen Traducido", "Destino Original", "Destino Traducido",
                              "Servicio Original", "Servicio Traducido", "Log"])
    for r in report["sections"]["nat_rules"]["data"]:
        ws_nat.append([
            r.get("name", ""),
            r.get("status", ""),
            r.get("nat_type", ""),
            ", ".join(r.get("source_zones", [])),
            r.get("original_source", ""),
            r.get("translated_source", ""),
            r.get("original_destination", ""),
            r.get("translated_destination", ""),
            r.get("original_service", ""),
            r.get("translated_service", ""),
            r.get("log_traffic", ""),
        ])
    auto_width(ws_nat)

    # ---- Hoja: Administradores ----
    ws_adm = wb.create_sheet("Administradores")
    make_header_row(ws_adm, ["Nombre", "Perfil", "Email", "MFA/OTP", "Restricción Login", "Redes Permitidas"])
    for u in report["sections"]["admin_users"]["data"]:
        ws_adm.append([
            u.get("name", ""),
            u.get("profile", ""),
            u.get("email", ""),
            "Sí" if u.get("otp_enabled") else "NO",
            u.get("login_restriction", ""),
            u.get("allowed_networks", ""),
        ])
        if not u.get("otp_enabled"):
            row_num = ws_adm.max_row
            for col in range(1, 7):
                ws_adm.cell(row=row_num, column=col).fill = PatternFill("solid", fgColor=COLORS["critical"])
    auto_width(ws_adm)

    # ---- Hoja: Objetos de Red (Hosts) ----
    ws_hosts = wb.create_sheet("Hosts")
    make_header_row(ws_hosts, ["Nombre", "Tipo", "IP", "Subred", "IP Inicio", "IP Fin"])
    for h in report["sections"]["hosts"]["data"]:
        ws_hosts.append([
            h.get("name", ""),
            h.get("type", ""),
            h.get("ip_address", ""),
            h.get("subnet", ""),
            h.get("start_ip", ""),
            h.get("end_ip", ""),
        ])
    auto_width(ws_hosts)

    # ---- Hoja: Zonas ----
    ws_zones = wb.create_sheet("Zonas")
    make_header_row(ws_zones, ["Nombre", "Tipo", "Descripción"])
    for z in report["sections"]["zones"]["data"]:
        ws_zones.append([z.get("name", ""), z.get("type", ""), z.get("description", "")])
    auto_width(ws_zones)

    # ---- Serializar ----
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    filename = f"alfil_audit_{obj.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{connection_id}/export/pdf")
def export_pdf(connection_id: int, db: Session = Depends(get_db)):
    """Exporta el reporte como PDF."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        raise HTTPException(status_code=500, detail="reportlab no está instalado")

    obj = _get_connection_or_404(connection_id, db)
    client = _get_client(obj)
    raw_data = client.collect_audit_data()
    connection_info = {"id": obj.id, "name": obj.name, "host": obj.host, "port": obj.port, "username": obj.username}
    report = generate_audit_report(connection_info, raw_data)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    SEV_COLORS = {
        "critical": colors.HexColor("#FFCCCC"),
        "warning":  colors.HexColor("#FFF2CC"),
        "info":     colors.HexColor("#DAE8FC"),
    }
    HEADER_BG = colors.HexColor("#1F3864")
    HEADER_FG = colors.white

    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18, textColor=HEADER_BG)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"], textColor=HEADER_BG, spaceBefore=12)
    body = styles["Normal"]

    story = []

    # Portada
    story.append(Paragraph("Reporte de Salud – Sophos Firewall", title_style))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(f"<b>Equipo:</b> {report['connection']['name']} ({report['connection']['host']})", body))
    story.append(Paragraph(f"<b>Fecha:</b> {report['generated_at']}", body))
    story.append(Paragraph(f"<b>Puntaje de salud:</b> {report['summary']['score']} / 100", body))
    story.append(Spacer(1, 0.4*cm))
    story.append(HRFlowable(width="100%"))
    story.append(Spacer(1, 0.3*cm))

    # Resumen
    story.append(Paragraph("Resumen de Hallazgos", h2_style))
    summary_data = [
        ["Severidad", "Cantidad"],
        ["Crítico",   str(report["summary"]["critical"])],
        ["Advertencia", str(report["summary"]["warning"])],
        ["Informativo", str(report["summary"]["info"])],
        ["Total", str(report["summary"]["total_issues"])],
    ]
    t = Table(summary_data, colWidths=[8*cm, 4*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), HEADER_FG),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN",      (1, 0), (1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (-1, 1), SEV_COLORS["critical"]),
        ("BACKGROUND", (0, 2), (-1, 2), SEV_COLORS["warning"]),
        ("BACKGROUND", (0, 3), (-1, 3), SEV_COLORS["info"]),
        ("FONTNAME",   (0, 4), (-1, 4), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # Hallazgos
    story.append(Paragraph("Hallazgos Detallados", h2_style))
    sorted_issues = sorted(report["issues"], key=lambda i: SEVERITY_ORDER.get(i["severity"], 99))
    if sorted_issues:
        rows = [["Sev.", "Categoría", "Título", "Detalle"]]
        for issue in sorted_issues:
            rows.append([
                issue["severity"].upper(),
                issue["category"],
                Paragraph(issue["title"], body),
                Paragraph(issue["detail"], body),
            ])
        issue_table = Table(rows, colWidths=[1.5*cm, 3*cm, 6*cm, 7.5*cm])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR",  (0, 0), (-1, 0), HEADER_FG),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("GRID",       (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ]
        for idx, issue in enumerate(sorted_issues, start=1):
            bg = SEV_COLORS.get(issue["severity"])
            if bg:
                style_cmds.append(("BACKGROUND", (0, idx), (1, idx), bg))
        issue_table.setStyle(TableStyle(style_cmds))
        story.append(issue_table)
    else:
        story.append(Paragraph("Sin hallazgos detectados.", body))

    story.append(Spacer(1, 0.5*cm))

    # Info de sistema
    story.append(Paragraph("Información del Sistema", h2_style))
    sys_data = [
        ["Campo", "Valor"],
        ["Hostname",   report["system"].get("hostname", "")],
        ["Modelo",     report["system"].get("model", "")],
        ["Firmware",   report["system"].get("firmware", "")],
        ["Uptime",     report["system"].get("uptime", "")],
        ["Timezone",   report["system"].get("timezone", "")],
    ]
    sys_table = Table(sys_data, colWidths=[5*cm, 12*cm])
    sys_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), HEADER_FG),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
    ]))
    story.append(sys_table)

    doc.build(story)
    buf.seek(0)

    filename = f"alfil_audit_{obj.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
