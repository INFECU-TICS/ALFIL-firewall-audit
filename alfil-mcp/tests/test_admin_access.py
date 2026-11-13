"""audit_admin_access: MFA de administradores y exposición de la administración (datos sintéticos)."""
import httpx
import pytest

from alfil_mcp import server
from alfil_mcp.analysis.admin import audit_admin_access, mfa_status
from alfil_mcp.config import AlfilSettings

ANY = {"any": True}
TOKEN = "alfil_mcp_test"


def admin(name, profile="Administrator", group="", allowed=ANY):
    return {"name": name, "group": {"name": group},
            "administrativePolicies": {"accessProfile": {"name": profile} if profile else {"name": ""}, "allowedNetworksIpv4": allowed}}


def totp(enabled=True, enabled_for=("webAdminPortal",), scope=ANY):
    return {"enabled": enabled, "enabledFor": list(enabled_for), "usersOrGroups": scope}


def zone(name, type_, *services):
    return {"name": name, "type": type_, "services": [{"name": s} for s in services]}


def codes(res):
    return [(f["code"], f["target"]) for f in res["findings"]]


def test_mfa_deshabilitado_marca_critico_por_admin():
    r = audit_admin_access([admin("a1"), admin("a2")], totp(enabled=False), [], [])
    assert [c for c, _ in codes(r) if c == "ADMIN_NO_MFA"] == ["ADMIN_NO_MFA"] * 2
    assert "deshabilitado" in r["administrators"][0]["mfa_reason"]


def test_otp_no_aplicado_a_la_consola():
    assert mfa_status(totp(enabled_for=("userPortal",)), admin("a"))[0] is False


def test_alcance_por_usuario_y_grupo():
    scope = {"users": [{"name": "a1"}], "userGroups": [{"name": "Ops"}]}
    t = totp(scope=scope)
    assert mfa_status(t, admin("a1"))[0] is True
    assert mfa_status(t, admin("a2", group="Ops"))[0] is True
    ok, why = mfa_status(t, admin("a3"))
    assert ok is False and "alcance" in why


def test_mfa_efectivo_sin_hallazgo_y_se_ignoran_cuentas_sin_perfil():
    r = audit_admin_access([admin("a1"), admin("Known Users", profile=""), admin("Unknown Users", profile="X")], totp(), [], [])
    assert [a["name"] for a in r["administrators"]] == ["a1"]
    assert not any(f["code"] == "ADMIN_NO_MFA" for f in r["findings"])


def test_admin_desde_cualquier_red_es_informativo():
    r = audit_admin_access([admin("a1"), admin("a2", allowed={"ipv4Addresses": [{"name": "oficina"}]})], totp(), [], [])
    assert codes(r) == [("ADMIN_ANY_NETWORK", "a1")]
    assert r["administrators"][1]["allowed_networks"] == ["oficina"]


def test_zona_wan_con_https_o_ssh_es_critica_y_lan_no():
    zones = [zone("LAN", "lan", "https", "ssh"), zone("Internet", "wan", "ssh", "ping"), zone("DMZ", "dmz", "https")]
    r = audit_admin_access([], totp(), zones, [])
    crit = [f for f in r["findings"] if f["severity"] == "critical"]
    assert [f["target"] for f in crit] == ["Internet"] and "ssh" in crit[0]["message"]
    assert {e["zone"] for e in r["admin_exposure"]} == {"LAN", "Internet", "DMZ"}


def test_servicios_de_usuario_en_wan_son_informativos():
    r = audit_admin_access([], totp(), [zone("WAN", "wan", "userPortal", "sslVpn", "ping")], [])
    assert codes(r) == [("WAN_USER_SERVICES", "WAN")] and r["counts"]["critical"] == 0


def test_regla_de_excepcion_wan_any_critica_y_restringida_advertencia():
    zones = [zone("WAN", "wan")]
    rules = [
        {"name": "Abierta-MAYUS", "action": "accept", "sourceZone": {"name": "WAN"}, "sourceNetworks": ANY, "services": [{"name": "https"}]},
        {"name": "acotada", "action": "accept", "sourceZone": {"name": "WAN"}, "sourceNetworks": {"ipv4Addresses": [{"name": "oficina"}]},
         "services": [{"name": "ssh"}, {"name": "ping"}]},
        {"name": "negada", "action": "drop", "sourceZone": {"name": "WAN"}, "sourceNetworks": ANY, "services": [{"name": "https"}]},
        {"name": "lan", "action": "accept", "sourceZone": {"name": "LAN"}, "sourceNetworks": ANY, "services": [{"name": "https"}]},
        {"name": "solo-ping", "action": "accept", "sourceZone": {"name": "WAN"}, "sourceNetworks": ANY, "services": [{"name": "ping"}]},
    ]
    r = audit_admin_access([], totp(), zones, rules)
    sev = {f["code"]: f for f in r["findings"]}
    assert "«Abierta-MAYUS»" in sev["ADMIN_FROM_WAN"]["message"] and "oficina" in sev["ADMIN_FROM_WAN_RESTRICTED"]["message"]
    assert len(r["findings"]) == 2 and r["findings"][0]["severity"] == "critical"
    assert len(r["admin_exposure"]) == 3  # abierta, acotada y la de LAN (no WAN)


def test_sin_datos_no_inventa_hallazgos():
    r = audit_admin_access([], {}, [], [])
    assert r["findings"] == [] and r["counts"] == {"critical": 0, "warning": 0, "info": 0}


ITEMS = {"/authentication/users/administrators": [admin("admin")], "/network/zones": [zone("WAN", "wan", "https")],
         "/acl-exception-rules/ipv4": [], "/authentication/multi-factor-authentication/totp-settings": totp(enabled=False)}


async def test_tool_lee_solo_rutas_get_del_catalogo(monkeypatch):
    from alfil_mcp.client import is_known_get_path
    for var in ("SFOS_HOST", "SFOS_TOKEN", "API_KEY", "SFOS_ENV_FILE", "ALFIL_URL", "ALFIL_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    server.reset_state()
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v1/mcp/connections":
            return httpx.Response(200, json=[{"id": 1, "name": "lab-rest", "host": "fw.test", "port": 4444, "verify_ssl": False}])
        if req.url.path.endswith("/get"):
            path = req.url.params["path"]
            seen.append((req.method, path))
            body = ITEMS[path]
            return httpx.Response(200, json=body if isinstance(body, dict) else {"items": body})
        return httpx.Response(404, json={"detail": "no"})

    server._hub = server.AlfilHub(AlfilSettings(url="http://alfil.test", token=TOKEN), transport=httpx.MockTransport(handler))
    res = await server.audit_admin_access()
    assert res["connection"] == "lab-rest" and res["counts"]["critical"] == 2  # sin MFA + WAN https
    assert all(m == "GET" for m, _ in seen) and all(is_known_get_path(p) for _, p in seen)
    assert {p for _, p in seen} == set(ITEMS)
    server.reset_state()
