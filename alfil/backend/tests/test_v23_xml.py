"""Regresión de la API XML en SFOS v23 (APIVersion 2300.1): respuestas reales anonimizadas."""
import xmltodict

from app.services import audit_service as audit
from app.services.sophos_client import SophosFirewallClient

MODULE_INVALID = """<Response APIVersion="2300.1"><Login><status>Authentication Successful</status></Login>
<Administrator><Status code="529">Input request module is Invalid</Status></Administrator></Response>"""
NO_RECORDS = """<Response APIVersion="2300.1"><Login><status>Authentication Successful</status></Login>
<User transactionid=""><Status>No. of records Zero.</Status></User></Response>"""


def test_http200_con_529_es_error_de_modulo():
    err = SophosFirewallClient._module_error(xmltodict.parse(MODULE_INVALID))
    assert err and "Administrator" in err and "529" in err


def test_entidad_vacia_no_es_error_ni_registro():
    data = xmltodict.parse(NO_RECORDS)
    assert SophosFirewallClient._module_error(data) is None
    assert SophosFirewallClient._to_list(data["Response"]["User"]) == []


def test_to_list_conserva_registros_reales():
    assert SophosFirewallClient._to_list({"Name": "a"}) == [{"Name": "a"}]
    assert SophosFirewallClient._to_list([{"Name": "a"}, {"Name": "b"}]) == [{"Name": "a"}, {"Name": "b"}]


def test_admin_no_verificable_no_genera_critico():
    issues = audit._analyze_admin_users({"admin_users": {"success": False, "error": "Entidad 'Administrator' no disponible (529)"}})
    assert [i["severity"] for i in issues] == [audit.INFO] and "529" in issues[0]["detail"]


def test_adminsettings_v23_hostname_y_certificado_por_defecto():
    ok = {"HostnameSettings": {"HostName": "fw01"}, "WebAdminSettings": {"Certificate": "MiCertCA"}}
    assert audit._analyze_admin_settings({"admin_settings": {"data": ok}}) == []
    default = {"HostnameSettings": {"HostName": "fw01"}, "WebAdminSettings": {"Certificate": "ApplianceCertificate"}}
    titles = [i["title"] for i in audit._analyze_admin_settings({"admin_settings": {"data": default}})]
    assert any("Certificado" in t for t in titles) and not any("Hostname" in t for t in titles)


def test_zona_horaria_v23_y_ntp_no_afirmado_sin_datos():
    t = {"TimeZone": "Europe/London", "SetDateTime": {}}
    issues = audit._analyze_time_settings({"time_settings": {"data": t}})
    assert any("Europe/London" in i["title"] for i in issues)
    assert not any("NTP" in i["title"] for i in issues)  # v23 no informa NTP en Time
    sin_ntp = audit._analyze_time_settings({"time_settings": {"data": {**t, "PredefinedNTPServer": "Disable"}}})
    assert any("NTP" in i["title"] for i in sin_ntp)


def test_notificaciones_configuradas_segun_canal_habilitado():
    off = {"notification_settings": {"data": [{"SendEmail": "Disable", "SendSnmp": "Disable"}]}}
    on = {"notification_settings": {"data": [{"SendEmail": "Enable", "SendSnmp": "Disable"}]}}
    assert len(audit._analyze_notifications(off)) == 1
    assert audit._analyze_notifications(on) == []
