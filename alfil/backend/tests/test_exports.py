"""Exportes Excel/PDF/ZIP: formato en español, escape de texto, hojas y secciones nuevas."""
import io
import zipfile

import openpyxl

from app.services import audit_service as audit
from app.services import export_service as ex
from app.services import rest_normalizers as nz
from app.services.sophos_rest_client import ALL_KEYS, UNSUPPORTED


def raw_data():
    raw = {k: dict(UNSUPPORTED) for k in ALL_KEYS}
    rule = {"name": "Reglas & <Pruebas>", "description": "a < b & c", "ruleType": "firewall", "enabled": True, "action": "accept", "logTraffic": False,
            "sourceZones": {"any": True}, "destinationZones": {"any": True}, "sourceNetworks": {"any": True}, "destinationNetworks": {"any": True},
            "servicesOrGroups": {"any": True}, "securityFeatures": {}}
    rule["sourceNetworks"] = {"ipv4Groups": [{"name": "GrupoUsado"}]}
    raw["firewall_rules"] = {"success": True, "data": [nz.normalize_firewall_rule(rule, 1)]}
    raw["hosts"] = {"success": True, "data": [{"name": f"h{i}"} for i in range(14)] + [{"name": "enGrupo"}]}
    raw["host_groups"] = {"success": True, "data": [{"name": "GrupoUsado", "hosts": ["enGrupo"]}]}
    raw["nat_rules"] = {"success": True, "data": []}
    raw["admin_users"] = {"success": True, "data": [{"name": "admin", "profile": "Administrator", "otp_enabled": False, "email": "", "login_restriction": "", "allowed_networks": ""}]}
    raw["vendor_health"] = {"success": True, "data": [
        {"policy": "MFA VPN & más", "module": "Authentication", "severity": "high", "status": "nonCompliant", "standards": ["CIS"]},
        {"policy": "IPS", "module": "IPS", "severity": "high", "status": "compliant"}]}
    return raw


def report():
    return audit.generate_audit_report({"name": "lab & co", "host": "fw.test", "api_type": "rest"}, raw_data())


def test_hosts_sin_uso_en_un_solo_hallazgo_y_cuentan_los_grupos():
    rep = report()
    hosts = [i for i in rep["issues"] if i["category"] == "hosts"]
    assert len(hosts) == 1 and hosts[0]["title"].startswith("14 host(s)") and "enGrupo" not in hosts[0]["detail"]


def test_hallazgos_con_recomendacion_y_cobertura_y_salud_del_fabricante():
    rep = report()
    assert all(i.get("recommendation") for i in rep["issues"] if i["severity"] in ("critical", "warning"))
    assert {c["section"] for c in rep["coverage"]} >= {"time_settings", "system_status"} and all(c["status"] == "no_disponible" for c in rep["coverage"] if c["section"] == "time_settings")
    assert rep["vendor_health"]["non_compliant"] == 1 and rep["vendor_health"]["compliant"] == 1
    assert any("NTP y zona horaria no evaluados" in i["title"] for i in rep["issues"])


def test_fmt_date():
    assert ex.fmt_date("2026-11-13T15:53:39.751565+00:00") == "2026-11-13 15:53 UTC"
    assert ex.fmt_date("basura") == "basura" and ex.fmt_date("") == ""


def test_excel_en_espanol_con_hojas_y_recomendaciones():
    wb = openpyxl.load_workbook(ex.generate_excel(report()))
    assert {"Resumen", "Hallazgos", "Verificación Sophos", "Reglas Firewall", "Administradores", "Alcance"} <= set(wb.sheetnames)
    h = wb["Hallazgos"]
    assert [c.value for c in h[1]] == ["Severidad", "Categoría", "Hallazgo", "Detalle", "Recomendación", "Referencia"]
    sevs = {r[0].value for r in h.iter_rows(min_row=2)}
    assert sevs <= {"Crítico", "Advertencia", "Informativo"} and "Crítico" in sevs
    assert h["E2"].value  # recomendación
    resumen = [(r[0].value, r[1].value) for r in wb["Resumen"].iter_rows()]
    assert any(k == "Fecha" and "UTC" in str(v) for k, v in resumen)
    assert wb["Verificación Sophos"]["C2"].value == "MFA VPN & más"
    assert "Hosts" not in wb.sheetnames or wb["Hosts"].max_row >= 2


def test_pdf_se_genera_con_caracteres_especiales():
    pdf = ex.generate_pdf(report()).getvalue()
    assert pdf[:4] == b"%PDF" and len(pdf) > 3000


def test_pdf_con_reporte_minimo_sin_secciones_opcionales():
    rep = report()
    rep.update({"issues": [], "coverage": [], "vendor_health": None, "system": {}})
    rep["summary"].update({"critical": 0, "warning": 0, "info": 0, "total_issues": 0})
    assert ex.generate_pdf(rep).getvalue()[:4] == b"%PDF"
    assert ex.generate_excel(rep).getvalue()[:2] == b"PK"


def test_zip_conserva_el_json_y_el_excel():
    z = zipfile.ZipFile(io.BytesIO(ex.generate_zip(report(), "lab").getvalue()))
    names = z.namelist()
    assert any(n.endswith(".xlsx") for n in names) and any(n.endswith(".json") and "/" not in n for n in names)
