"""Colectores REST adicionales: objetos, políticas y ajustes normalizados al formato XML (formas tomadas del equipo v23)."""
from app.services import audit_service as audit
from app.services import rest_normalizers as nz
from app.services.sophos_rest_client import SophosRestClient

PAYLOADS = {
    "/network/address-groups/ipv4": [{"name": "g1", "description": "d", "ipv4Addresses": [{"name": "h1"}, {"name": "h2"}], "ipv4Groups": [{"name": "g0"}]}],
    "/network/addresses/mac": [{"name": "imp", "description": "", "type": "macAddress", "macAddress": "AA:BB:CC:DD:EE:01"}],
    "/network/addresses/fqdn": [{"name": "apple", "fqdn": "*.apple.com", "description": ""}, {"name": "solo", "fqdn": "x.test", "description": ""}],
    "/network/address-groups/fqdn": [{"name": "Apple Services", "description": "", "fqdns": [{"name": "apple"}]}, {"name": "vacio", "fqdns": []}],
    "/administration/schedules": [{"name": "s", "description": "", "type": "recurring",
                                    "timeSlots": [{"dayOfWeek": "sun", "startTime": "00:00", "endTime": "23:59"}, {"dayOfWeek": "mon", "startTime": "08:00", "endTime": "10:00"}]}],
    "/authentication/users": [{"name": "admin", "displayName": "Administrador", "administrativeAccess": True, "active": False, "group": {"name": ""}},
                               {"name": "ana", "displayName": "Ana", "administrativeAccess": False, "active": True, "group": {"name": "Ventas"}}],
    "/tls-inspection/rules/ipv4": [{"name": "r", "enabled": True, "logTraffic": True, "action": "doNotDecrypt", "decryptionProfile": {"name": "p"},
                                    "sourceZones": {"any": True}, "destinationZones": {"zones": [{"name": "WAN"}]}, "sourceNetworks": {"any": True},
                                    "destinationNetworks": {"any": True}, "servicesOrGroups": {"any": True}}],
    "/tls-inspection/decryption-profiles": [{"name": "p", "minTlsVersion": "tls12", "maxTlsVersion": "maximumSupported", "blockSelfSigned": True,
                                              "blockExpiredCertificates": False, "sslV2V3Action": "reject"}],
    "/web/policies": [{"name": "w", "description": "x", "defaultAction": "allow", "rules": []}],
    "/web/exceptions": [{"name": "e", "enabled": True}],
    "/application/policies": [{"name": "a", "description": "Allow All Policy.", "rules": []}],
    "/network/dns/request-routes": [],
    "/authentication/policies/access-times": [{"name": "t", "action": "allow"}],
    "/authentication/policies/surfing-quotas": [{"name": "q"}],
    "/authentication/policies/network-traffic-quotas": [{"name": "d"}],
}
SINGLES = {"/network/dns/settings": {"dnsProtocol": "unencryptedDns"}, "/tls-inspection/settings": {"tlsInspection": True},
           "/system/backup/settings": {"backupStorage": "local", "backupPrefix": "", "schedule": {"frequency": "never"}}}
NOT_IN_REST = {"system_status", "time_settings", "firewall_rule_groups", "sdwan_policy_routes", "sdwan_profiles", "health_check_profiles"}


def client():
    c = SophosRestClient("fw.test", 4444, "k")
    c._get_all = lambda path, params=None: PAYLOADS.get(path, [])
    c._get = lambda path, params=None: SINGLES.get(path, {})
    return c


def test_grupos_y_objetos_se_normalizan():
    c = client()
    assert c.get_host_groups()["data"][0]["hosts"] == ["h1", "h2", "g0"]
    assert c.get_mac_hosts()["data"][0]["mac_address"] == "AA:BB:CC:DD:EE:01"
    fq = {h["name"]: h for h in c.get_fqdn_hosts()["data"]}
    assert fq["apple"]["groups"] == ["Apple Services"] and fq["solo"]["groups"] == []
    assert c.get_fqdn_host_groups()["data"][0]["hosts"] == ["apple"]


def test_horarios_usuarios_y_politicas():
    c = client()
    sch = c.get_schedules()["data"][0]
    assert sch["days"] == "sun; mon" and sch["start_time"] == "00:00" and sch["stop_time"] == "23:59"
    users = {u["username"]: u for u in c.get_auth_users()["data"]}
    assert users["admin"]["user_type"] == "Administrator" and users["admin"]["status"] == "Inactive"
    assert users["ana"]["user_type"] == "User" and users["ana"]["group"] == "Ventas" and users["ana"]["status"] == "Active"
    assert c.get_web_filter_policies()["data"][0]["default_action"] == "allow"
    assert "default_action" not in c.get_app_filter_policies()["data"][0]


def test_tls_ssl_y_perfiles():
    c = client()
    r = c.get_ssl_tls_rules()["data"][0]
    assert r["enabled"] == "Enable" and r["decrypt_action"] == "doNotDecrypt" and r["decryption_profile"] == "p"
    assert r["source_zones"] == ["Any"] and r["destination_zones"] == ["WAN"]
    p = c.get_decryption_profiles()["data"][0]
    assert p["block_self_signed"] == "Enable" and p["block_invalid_date"] == "Disable" and p["min_tls_version"] == "tls12"
    assert c.get_ssl_tls_settings()["data"]["tlsInspection"] is True


def test_backup_y_dns():
    c = client()
    b = c.get_backup_restore()["data"]
    assert b["mode"] == "local" and b["frequency"] == "never"
    assert c.get_dns()["data"]["dnsProtocol"] == "unencryptedDns"


def test_error_de_un_colector_no_tumba_a_los_demas():
    from app.services.sophos_rest_client import RestError
    c = client()
    base = c._get_all

    def flaky(path, params=None):
        if path == "/administration/schedules":
            raise RestError("boom")
        return base(path, params)
    c._get_all = flaky
    out = c.collect_audit_data()
    assert out["schedules"]["success"] is False and out["schedules"]["error"] == "boom"
    assert out["host_groups"]["success"] is True


def test_la_auditoria_trae_los_colectores_nuevos_y_solo_faltan_los_que_la_api_no_expone():
    out = client().collect_audit_data()
    unsupported = {k for k, v in out.items() if v.get("unsupported")}
    assert NOT_IN_REST <= unsupported
    failed = {k for k, v in out.items() if not v.get("success") and not v.get("unsupported")}
    assert not failed, failed
    rep = audit.generate_audit_report({"name": "lab", "api_type": "rest"}, out)
    assert rep["sections"]["host_groups"]["data"][0]["name"] == "g1"


def test_consulta_de_usuarios_ya_disponible_y_host_objects_con_grupos():
    c = client()
    u = c.run_query("users")
    assert u["success"] and u["count"] == 2 and u["data"][0]["username"] == "admin"
    h = c.run_query("host_objects")
    assert h["success"] and h["data"]["fqdn_hosts"][0]["groups"] == ["Apple Services"] and h["data"]["mac_hosts"][0]["mac_address"].startswith("AA")


def test_ruta_que_solo_admite_50_por_pagina_se_reintenta():
    from app.services.sophos_rest_client import RestError
    c = SophosRestClient("fw.test", 4444, "k")
    calls = []

    def fake_get(path, params=None):
        calls.append(params["pageSize"])
        if params["pageSize"] > 50:
            raise RestError("HTTP 400: Invalid page size.")
        return {"items": [{"name": f"p{params['page']}-{i}"} for i in range(50 if params["page"] == 1 else 3)]}
    c._get = fake_get
    assert len(c._get_all("/application/policies")) == 53
    assert calls == [100, 50, 50]


def test_otro_error_400_no_se_reintenta():
    import pytest
    from app.services.sophos_rest_client import RestError
    c = SophosRestClient("fw.test", 4444, "k")
    c._get = lambda path, params=None: (_ for _ in ()).throw(RestError("HTTP 400: Bad filter"))
    with pytest.raises(RestError):
        c._get_all("/x")
