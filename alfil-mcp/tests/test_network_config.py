"""audit_network_config: NAT, interfaces y notificaciones (datos sintéticos)."""
import httpx

from alfil_mcp import server
from alfil_mcp.analysis.netconfig import audit_network_config
from alfil_mcp.config import AlfilSettings

ANY = {"any": True}
ZONES = [{"name": "WAN", "type": "wan"}, {"name": "LAN", "type": "lan"}]
IFACES = [{"name": "PortA", "zone": {"name": "LAN"}, "enabled": True, "type": "physical"},
          {"name": "PortB", "zone": {"name": "WAN"}, "enabled": True, "type": "physical"}]
FW = [{"name": "web", "enabled": True}, {"name": "off", "enabled": False}]
NOTIF_OK = {"enableEmailNotifications": True, "enableSnmpTraps": False,
            "notifications": [{"name": "signInFailed", "group": "admin", "email": True, "snmpTrap": False}]}


def nat(name, **kw):
    base = {"name": name, "enabled": True, "inboundInterfaces": ANY, "originalSourceNetworks": ANY, "translatedDestination": None, "linkedFirewallRule": None}
    return {**base, **kw}


def run(nats=(), fw=FW, ifaces=IFACES, notif=NOTIF_OK):
    return audit_network_config(list(nats), fw, ifaces, ZONES, notif)


def codes(r):
    return [(f["code"], f["target"]) for f in r["findings"]]


def test_dnat_desde_cualquier_origen_por_wan_advierte():
    r = run([nat("dnat-any", translatedDestination={"ipv4Address": {"name": "srv"}}, inboundInterfaces={"interfaces": [{"name": "PortB"}]})])
    assert codes(r) == [("NAT_DNAT_ANY_SOURCE", "dnat-any")]


def test_dnat_por_interfaz_lan_o_origen_acotado_no_advierte():
    lan = nat("lan", translatedDestination={"x": 1}, inboundInterfaces={"interfaces": [{"name": "PortA"}]})
    acotado = nat("acotado", translatedDestination={"x": 1}, originalSourceNetworks={"ipv4Addresses": [{"name": "oficina"}]})
    assert run([lan, acotado])["findings"] == []


def test_snat_masquerade_no_es_dnat():
    assert run([nat("snat", translatedSource={"masq": True})])["findings"] == []


def test_regla_enlazada_inexistente_y_deshabilitada():
    r = run([nat("n1", linkedFirewallRule={"name": "no-existe"}), nat("n2", linkedFirewallRule={"name": "off"}), nat("n3", linkedFirewallRule={"name": "web"})])
    assert codes(r) == [("NAT_LINKED_RULE_MISSING", "n1"), ("NAT_LINKED_RULE_DISABLED", "n2")]


def test_nat_deshabilitado_es_informativo_y_no_evalua_mas():
    r = run([nat("viejo", enabled=False, linkedFirewallRule={"name": "no-existe"})])
    assert codes(r) == [("NAT_DISABLED", "viejo")]


def test_interfaz_habilitada_sin_zona():
    ifaces = IFACES + [{"name": "PortC", "zone": None, "enabled": True, "type": "physical"},
                       {"name": "PortD", "zone": None, "enabled": False, "type": "physical"},
                       {"name": "PortA.10", "zone": None, "enabled": True, "type": "vlan"}]
    assert codes(run(ifaces=ifaces)) == [("IFACE_NO_ZONE", "PortC")]


def test_sin_canales_de_notificacion():
    r = run(notif={"enableEmailNotifications": False, "enableSnmpTraps": False, "notifications": []})
    assert codes(r) == [("NOTIF_NONE", "notificaciones")] and r["counts"]["warning"] == 1


def test_eventos_de_admin_sin_canal_activo():
    n = {"enableEmailNotifications": True, "enableSnmpTraps": False,
         "notifications": [{"name": "signInFailed", "group": "admin", "email": False, "snmpTrap": True},
                           {"name": "critical", "group": "ips", "email": True, "snmpTrap": False}]}
    assert codes(run(notif=n)) == [("NOTIF_ADMIN_EVENTS", "notificaciones")]


def test_orden_por_severidad_y_conteo():
    r = run([nat("viejo", enabled=False), nat("d", translatedDestination={"x": 1})], notif={"enableEmailNotifications": False, "enableSnmpTraps": False})
    assert [f["severity"] for f in r["findings"]] == ["warning", "warning", "info"] and r["counts"] == {"critical": 0, "warning": 2, "info": 1}


ITEMS = {"/nat/rules/ipv4": [nat("d", translatedDestination={"x": 1})], "/firewall/rules/ipv4": FW,
         "/network/interfaces/network-interfaces": IFACES, "/network/zones": ZONES, "/notification/notifications": NOTIF_OK}


async def test_tool_solo_lee_rutas_get_del_catalogo(monkeypatch):
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

    server._hub = server.AlfilHub(AlfilSettings(url="http://alfil.test", token="alfil_mcp_t"), transport=httpx.MockTransport(handler))
    res = await server.audit_network_config()
    assert res["connection"] == "lab-rest" and res["counts"]["warning"] == 1 and res["totals"] == {"nat_rules": 1, "interfaces": 2}
    assert all(m == "GET" for m, _ in seen) and all(is_known_get_path(p) for _, p in seen) and {p for _, p in seen} == set(ITEMS)
    server.reset_state()
