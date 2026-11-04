"""Modo REST (SFOS v23): normalizadores, auditoría completa desde datos REST y migración de la BD."""
import pytest
from sqlalchemy import create_engine, inspect, text

from app.schemas.connection import ConnectionConfigCreate
from app.services import audit_service as audit
from app.services import rest_normalizers as nz
from app.services.sophos_rest_client import ALL_KEYS, SophosRestClient

ANY = {"any": True}


def rest_rule(name, **kw):
    base = {"name": name, "description": "", "ruleType": "firewall", "enabled": True, "action": "accept", "logTraffic": True,
            "sourceZones": {"zones": [{"name": "LAN"}]}, "destinationZones": {"zones": [{"name": "WAN"}]},
            "sourceNetworks": ANY, "destinationNetworks": ANY,
            "servicesOrGroups": {"services": [{"name": "HTTPS"}], "serviceGroups": []},
            "securityFeatures": {"webPolicy": None, "scanHttpAndDecryptedHttps": False, "decryptHTTPSWebProxyMode": False}}
    return {**base, **kw}


def test_selector_names():
    assert nz.selector_names(ANY) == ["Any"]
    assert nz.selector_names({"zones": [{"name": "LAN"}, {"name": "DMZ"}]}) == ["LAN", "DMZ"]
    assert nz.selector_names({"services": [{"name": "DNS"}], "serviceGroups": []}) == ["DNS"]
    assert nz.selector_names({}) == [] and nz.selector_names(None) == []


def test_regla_rest_se_normaliza_al_formato_xml():
    r = nz.normalize_firewall_rule(rest_rule("web", logTraffic=False, enabled=False), 3)
    assert (r["status"], r["log_traffic"], r["action"], r["position"]) == ("Disable", "Disable", "Accept", "3")
    assert r["source_zones"] == ["LAN"] and r["source_networks"] == ["Any"] and r["services"] == ["HTTPS"]


def test_nat_tipos():
    masq = nz.normalize_nat_rule({"name": "m", "enabled": True, "translatedSource": {"masq": True}, "translatedDestination": None}, 1)
    dnat = nz.normalize_nat_rule({"name": "d", "enabled": True, "translatedDestination": {"name": "srv"}}, 2)
    assert masq["nat_type"] == "MASQ" and dnat["nat_type"] == "DNAT" and dnat["translated_destination"] == "srv"


TOTP_OFF = {"enabled": False, "usersOrGroups": ANY, "enabledFor": ["userPortal", "webAdminPortal"]}
ADMINS = [
    {"name": "admin", "administrativePolicies": {"accessProfile": {"name": "Administrator"}, "allowedNetworksIpv4": ANY}, "group": {"name": "Open Group"}},
    {"name": "Known Users", "administrativePolicies": {"accessProfile": {"name": ""}}},  # pseudo-usuario sin perfil
]


def test_admins_excluye_pseudo_usuarios_y_mfa_inactivo():
    out = nz.normalize_admins(ADMINS, TOTP_OFF)
    assert [a["name"] for a in out] == ["admin"] and out[0]["otp_enabled"] is False


@pytest.mark.parametrize("totp,expected", [
    ({"enabled": True, "usersOrGroups": ANY, "enabledFor": ["webAdminPortal"]}, True),
    ({"enabled": True, "usersOrGroups": ANY, "enabledFor": ["sslVpn"]}, False),  # no cubre la consola admin
    ({"enabled": True, "usersOrGroups": {"users": [{"name": "admin"}]}, "enabledFor": ["webAdminPortal"]}, True),
    ({"enabled": True, "usersOrGroups": {"users": [{"name": "otro"}]}, "enabledFor": ["webAdminPortal"]}, False),
    ({"enabled": True, "usersOrGroups": {"userGroups": [{"name": "Open Group"}]}, "enabledFor": ["webAdminPortal"]}, True),
])
def test_alcance_mfa(totp, expected):
    assert nz.otp_applies_to_admin(totp, ADMINS[0]) is expected


def test_acceso_admin_por_zona_wan_es_critico():
    zones = [{"name": "WAN", "type": "wan", "services": [{"name": "https"}, {"name": "ping"}]},
             {"name": "LAN", "type": "lan", "services": [{"name": "ssh"}]}]
    raw = {"zones": {"success": True, "data": [nz.normalize_zone(z) for z in zones]},
           "device_access": {"success": True, "data": nz.build_device_access(zones, [])}}
    issues = audit._analyze_device_access(raw, raw["zones"]["data"])
    assert len(issues) == 1 and issues[0]["severity"] == audit.CRITICAL and "WAN" in issues[0]["title"]


def test_reporte_completo_desde_datos_rest():
    """Todas las claves que espera el reporte existen y el auditor produce hallazgos coherentes."""
    rules = [rest_rule("a"), rest_rule("b"), rest_rule("todo", sourceZones=ANY, destinationZones=ANY, servicesOrGroups=ANY, logTraffic=False)]
    raw = {k: dict(SophosRestClient.__init__.__globals__["UNSUPPORTED"]) for k in ALL_KEYS}
    raw["firewall_rules"] = {"success": True, "data": [nz.normalize_firewall_rule(r, i + 1) for i, r in enumerate(rules)]}
    raw["admin_users"] = {"success": True, "data": nz.normalize_admins(ADMINS, TOTP_OFF)}
    raw["admin_settings"] = {"success": True, "data": nz.normalize_admin_settings({"hostname": "fw"})}
    raw["notification_settings"] = {"success": True, "data": nz.normalize_notifications({"enableEmailNotifications": False, "enableSnmpTraps": False})}
    rep = audit.generate_audit_report({"name": "lab", "api_type": "rest"}, raw)
    titles = [i["title"] for i in rep["issues"]]
    assert any("sin MFA" in t for t in titles) and any("Any→Any" in t for t in titles) and any("duplicada" in t.lower() for t in titles)
    assert not any("Certificado" in t for t in titles)  # REST no informa el certificado: no se afirma nada
    assert rep["summary"]["critical"] == 1 and 0 <= rep["summary"]["score"] <= 100


def test_create_rest_no_exige_usuario_y_xml_si():
    ok = ConnectionConfigCreate(name="n", host="h", api_type="rest", password="k")
    assert ok.username == "api-key"
    with pytest.raises(ValueError):
        ConnectionConfigCreate(name="n", host="h", api_type="xml", password="p")
    assert ConnectionConfigCreate(name="n", host="h", username="admin", password="p").api_type == "xml"


def test_migracion_agrega_api_type_sin_perder_datos(monkeypatch, tmp_path):
    import app.database as db
    eng = create_engine(f"sqlite:///{tmp_path}/old.db")
    with eng.begin() as c:  # esquema anterior, sin api_type
        c.execute(text("CREATE TABLE connections (id INTEGER PRIMARY KEY, name VARCHAR(100) NOT NULL, host VARCHAR(255) NOT NULL, "
                       "port INTEGER, username VARCHAR(100) NOT NULL, password_encrypted TEXT NOT NULL, verify_ssl BOOLEAN, is_active BOOLEAN)"))
        c.execute(text("INSERT INTO connections (name, host, port, username, password_encrypted, verify_ssl, is_active) VALUES ('lab','h',4444,'admin','x',0,1)"))
    monkeypatch.setattr(db, "engine", eng)
    db.ensure_schema()
    db.ensure_schema()  # idempotente
    assert "api_type" in {c["name"] for c in inspect(eng).get_columns("connections")}
    with eng.connect() as c:
        assert c.execute(text("SELECT name, api_type FROM connections")).one() == ("lab", "xml")


def test_la_app_importa_y_expone_las_rutas():
    """Humo: detecta errores de sintaxis/imports en routers (los tests unitarios no los cargan)."""
    from app.main import app
    paths = {r.path for r in app.routes}
    assert "/api/v1/connections" in paths and "/api/v1/audit/{connection_id}/start" in paths


def test_bloque_system_del_reporte_lee_hostname_y_zona_horaria_v23():
    raw = {"admin_settings": {"data": {"HostnameSettings": {"HostName": "fw01"}}},
           "time_settings": {"data": {"TimeZone": "Europe/London"}}}
    rep = audit.generate_audit_report({"name": "x"}, raw)
    assert rep["system"]["hostname"] == "fw01" and rep["system"]["timezone"] == "Europe/London"


def test_advierte_si_la_clave_de_cifrado_es_insegura(caplog):
    import logging
    from app import main
    with caplog.at_level(logging.CRITICAL):
        main.settings = main.settings.model_copy(update={"encryption_key": "your-encryption-key-here-change-in-production"})
        main._warn_insecure_encryption_key()
    assert any("ENCRYPTION_KEY" in r.message for r in caplog.records)
