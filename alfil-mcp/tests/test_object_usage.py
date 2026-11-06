"""trace_object_usage / find_unused_objects: índice de referencias sobre datos sintéticos."""
import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from alfil_mcp import server
from alfil_mcp.analysis.usage import UsageIndex, references_in
from alfil_mcp.config import AlfilSettings

ANY = {"any": True}


def sel(**kw):
    return {k: [{"name": n} for n in v] for k, v in kw.items()}


HOSTS = [{"name": "srv-web"}, {"name": "srv-db"}, {"name": "huerfano"}, {"name": "solo-en-grupo-muerto"},
         {"name": "LAN"}, {"name": "interno", "isInternal": True}]
SERVICES = [{"name": "HTTPS"}, {"name": "SSH"}, {"name": "ServicioSuelto"}, {"name": "svc-en-grupo"}]
RULES = [
    {"name": "web", "enabled": True, "sourceZones": {"zones": [{"name": "LAN"}]}, "destinationZones": ANY,
     "sourceNetworks": ANY, "destinationNetworks": sel(ipv4Addresses=["srv-web"], ipv4Groups=["g-servidores"]),
     "servicesOrGroups": {"services": [{"name": "HTTPS"}], "serviceGroups": [{"name": "g-svc"}]},
     "exclusions": {"sourceNetworks": sel(ipv4Addresses=["srv-db"])}},
    {"name": "apagada", "enabled": False, "sourceZones": ANY, "destinationZones": ANY, "sourceNetworks": sel(ipv4Addresses=["srv-db"]),
     "destinationNetworks": ANY, "servicesOrGroups": {"services": [{"name": "SSH"}]}},
]
NAT = [{"name": "dnat-web", "enabled": True, "linkedFirewallRule": {"name": "web"}, "originalDestinationNetworks": sel(ipv4Addresses=["srv-web"]),
        "translatedDestination": {"ipv4Address": {"name": "srv-db"}}, "translatedService": {"name": "HTTPS"},
        "inboundInterfaces": {"interfaces": [{"name": "PortB"}]}, "originalServicesOrGroups": ANY}]
HOST_GROUPS = [{"name": "g-servidores", "ipv4Addresses": [{"name": "srv-db"}], "ipv4Groups": [{"name": "g-anidado"}]},
               {"name": "g-anidado", "ipv4Addresses": [{"name": "srv-web"}]},
               {"name": "g-muerto", "ipv4Addresses": [{"name": "solo-en-grupo-muerto"}]}]
SERVICE_GROUPS = [{"name": "g-svc", "services": [{"name": "svc-en-grupo"}]}]
VPN = [{"name": "sitio-b", "protectedNetworks": {"localNetworksIpv4": sel(ipv4Addresses=["srv-web"]), "remoteNetworksIpv4": ANY}}]


def index(**over):
    args = dict(rules=RULES, nat_rules=NAT, host_groups=HOST_GROUPS, service_groups=SERVICE_GROUPS, vpn_connections=VPN, hosts=HOSTS, services=SERVICES)
    args.update(over)
    return UsageIndex(**args)


def match(result, kind):
    return next(m for m in result["matches"] if m["kind"] == kind)


def test_referencias_de_un_recurso_con_su_campo_y_sin_contar_su_propio_nombre():
    refs = references_in(RULES[0])
    assert ("host", "srv-web", "destinationNetworks.ipv4Addresses") in refs
    assert ("service_group", "g-svc", "servicesOrGroups.serviceGroups") in refs
    assert ("host", "srv-db", "exclusions.sourceNetworks.ipv4Addresses") in refs     # exclusiones
    assert all(name != "web" for _, name, _ in refs)


def test_usos_directos_en_reglas_nat_y_vpn():
    m = match(index().trace("srv-web", "host"), "host")
    fields = {(u["resource"], u["name"], u["field"]) for u in m["direct_uses"]}
    assert ("firewall_rule", "web", "destinationNetworks.ipv4Addresses") in fields
    assert ("nat_rule", "dnat-web", "originalDestinationNetworks.ipv4Addresses") in fields
    assert ("vpn_connection", "sitio-b", "protectedNetworks.localNetworksIpv4.ipv4Addresses") in fields
    assert m["in_groups"] == ["g-anidado"]


def test_nat_traducido_servicio_interfaz_y_regla_enlazada():
    ix = index()
    assert any(u["field"] == "translatedDestination.ipv4Address" for u in match(ix.trace("srv-db", "host"), "host")["direct_uses"])
    assert any(u["field"] == "translatedService" for u in match(ix.trace("HTTPS", "service"), "service")["direct_uses"])
    assert match(ix.trace("PortB"), "interface")["direct_uses"][0]["resource"] == "nat_rule"
    assert match(ix.trace("web", "firewall_rule"), "firewall_rule")["direct_uses"][0]["name"] == "dnat-web"
    assert match(ix.trace("LAN", "zone"), "zone")["direct_uses"][0]["field"] == "sourceZones.zones"


def test_uso_indirecto_por_grupo_con_cadena_y_anidado():
    m = match(index().trace("srv-web", "host"), "host")
    via = {tuple(u["via"]): u["name"] for u in m["indirect_uses"]}
    assert via == {("g-anidado", "g-servidores"): "web"}                    # srv-web ∈ g-anidado ∈ g-servidores, usado por la regla web
    s = match(index().trace("svc-en-grupo", "service"), "service")
    assert [u["via"] for u in s["indirect_uses"]] == [["g-svc"]] and s["direct_uses"] == []


def test_grupos_circulares_no_entran_en_bucle():
    groups = [{"name": "A", "ipv4Groups": [{"name": "B"}], "ipv4Addresses": [{"name": "h"}]}, {"name": "B", "ipv4Groups": [{"name": "A"}]}]
    rules = [{"name": "r", "enabled": True, "destinationNetworks": sel(ipv4Groups=["B"])}]
    ix = UsageIndex(rules=rules, host_groups=groups, hosts=[{"name": "h"}])
    m = match(ix.trace("h", "host"), "host")
    assert [u["name"] for u in m["indirect_uses"]] == ["r"]
    assert ix.unused("host")["total"] == 0


def test_mismo_nombre_en_tipos_distintos_se_separa():
    r = index().trace("LAN")
    assert {m["kind"] for m in r["matches"]} == {"host", "zone"}
    assert match(r, "host")["unused"] is True and match(r, "zone")["total_uses"] == 1
    assert {m["kind"] for m in index().trace("LAN", "zone")["matches"]} == {"zone"}


def test_reglas_deshabilitadas_cuentan_pero_se_marcan():
    m = match(index(rules=[RULES[1]], nat_rules=[]).trace("SSH", "service"), "service")
    assert m["total_uses"] == 1 and m["direct_uses"][0]["enabled"] is False and any("deshabilitadas" in n for n in m["notes"])


def test_objeto_inexistente_sugiere_nombres_parecidos():
    with pytest.raises(LookupError, match="srv-web"):
        index().trace("srv-wbe")
    with pytest.raises(LookupError, match="No existe"):
        index().trace("zzzzzz")
    with pytest.raises(LookupError):
        index().trace("srv-web", "service")


def test_objetos_sin_uso():
    out = index().unused()
    by = {(i["kind"], i["name"]): i["reason"] for i in out["items"]}
    assert by[("host", "huerfano")] == "sin_referencias"
    assert by[("host", "solo-en-grupo-muerto")] == "solo_via_grupo_sin_uso"
    assert by[("service", "ServicioSuelto")] == "sin_referencias"
    assert ("host", "interno") not in by                                  # objeto interno del sistema
    assert ("host", "srv-web") not in by and ("host", "srv-db") not in by and ("service", "svc-en-grupo") not in by
    assert ("host_group", "g-muerto") in by and ("host_group", "g-servidores") not in by
    assert out["by_kind"]["host"] == 3 and out["notes"]   # huerfano, solo-en-grupo-muerto y el host «LAN»


def test_filtro_por_tipo_y_limite():
    only = index().unused("service")
    assert {i["kind"] for i in only["items"]} == {"service"}
    lim = index().unused(limit=2)
    assert len(lim["items"]) == 2 and lim["truncated"] is True and lim["total"] > 2


# -- Herramientas MCP -------------------------------------------------------------------------------

TOKEN = "alfil_mcp_token-de-prueba"
ITEMS = {"/firewall/rules/ipv4": RULES, "/nat/rules/ipv4": NAT, "/network/address-groups/ipv4": HOST_GROUPS, "/network/service-groups": SERVICE_GROUPS,
         "/ipsec-vpn/site-to-site/connections/ipv4": VPN, "/network/addresses/ipv4": HOSTS, "/network/services": SERVICES}


def hub():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        seen.append((req.method, req.url.params.get("path")))
        if p == "/api/v1/mcp/connections":
            return httpx.Response(200, json=[{"id": 1, "name": "lab-rest", "host": "fw.test", "port": 4444, "verify_ssl": False}])
        if p.endswith("/get"):
            return httpx.Response(200, json={"items": ITEMS[req.url.params["path"]]})
        return httpx.Response(404, json={"detail": "no"})

    h = server.AlfilHub(AlfilSettings(url="http://alfil.test", token=TOKEN), transport=httpx.MockTransport(handler))
    h.seen = seen
    return h


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for var in ("SFOS_HOST", "SFOS_TOKEN", "API_KEY", "SFOS_ENV_FILE", "ALFIL_URL", "ALFIL_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    server.reset_state()
    yield
    server.reset_state()


async def test_tools_trace_y_unused_solo_leen_rutas_del_catalogo():
    from alfil_mcp.client import is_known_get_path
    server._hub = h = hub()
    t = await server.trace_object_usage("srv-web", "host")
    assert t["connection"] == "lab-rest" and t["matches"][0]["total_uses"] >= 3
    u = await server.find_unused_objects("host")
    assert {i["name"] for i in u["items"]} == {"huerfano", "solo-en-grupo-muerto", "LAN"}
    assert all(m == "GET" for m, _ in h.seen)
    assert all(is_known_get_path(p) for _, p in h.seen if p)
    assert {p for _, p in h.seen if p} == set(ITEMS)


async def test_tools_errores_legibles():
    server._hub = hub()
    with pytest.raises(ToolError, match="Nombres parecidos"):
        await server.trace_object_usage("srv-wbe")
    with pytest.raises(ToolError, match="kind"):
        await server.find_unused_objects("zone")
