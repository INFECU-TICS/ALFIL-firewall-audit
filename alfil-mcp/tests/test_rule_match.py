"""explain_rule_match: evaluación de reglas contra un flujo (datos sintéticos con rangos de documentación)."""
import ipaddress

import pytest

from alfil_mcp.analysis.match import MATCH, NO_MATCH, POSSIBLE, Objects, evaluate_rule, explain_rule_match, network_match

ANY = {"any": True}


def z(*names):
    return {"zones": [{"name": n} for n in names]}


def nets(**kw):
    return {k: [{"name": n} for n in v] for k, v in kw.items()}


def svcs(services=(), groups=()):
    return {"services": [{"name": n} for n in services], "serviceGroups": [{"name": n} for n in groups]}


def rule(name, action="accept", **over):
    r = {"name": name, "enabled": True, "action": action, "logTraffic": True, "sourceZones": ANY, "destinationZones": ANY,
         "sourceNetworks": ANY, "destinationNetworks": ANY, "servicesOrGroups": ANY}
    r.update(over)
    return r


OBJS = Objects(
    hosts=[
        {"name": "srv-web", "type": "ipv4Address", "ipv4Address": "10.0.10.5"},
        {"name": "lan-net", "type": "ipv4Network", "ipv4NetworkAddress": "10.0.1.0", "cidr": 24},
        {"name": "rango-it", "type": "ipv4Range", "ipv4AddressStart": "10.0.1.100", "ipv4AddressEnd": "10.0.1.120"},
        {"name": "lista-vip", "type": "ipv4List", "ipv4Addresses": ["10.0.1.200", "10.0.1.201"]},
    ],
    host_groups=[{"name": "grupo-serv", "ipv4Addresses": [{"name": "srv-web"}, {"name": "rango-it"}]}],
    services=[
        {"name": "HTTPS", "type": "tcpOrUdp", "services": [{"protocol": "tcp", "destinationPort": {"from": 443, "to": 443}}]},
        {"name": "Altos", "type": "tcpOrUdp", "services": [{"protocol": "tcp", "destinationPort": {"from": 8000, "to": 8999}}]},
        {"name": "DNS", "type": "tcpOrUdp", "services": [{"protocol": "udp", "destinationPort": {"from": 53, "to": 53}},
                                                         {"protocol": "tcp", "destinationPort": {"from": 53, "to": 53}}]},
        {"name": "Ping", "type": "icmp", "services": [{"ipProtocol": "icmp"}]},
        {"name": "GRE", "type": "ip", "services": [{"ipProtocol": "gre"}]},
    ],
    service_groups=[{"name": "web", "services": [{"name": "HTTPS"}, {"name": "Altos"}]}],
)


def ev(r, src="10.0.1.50", dst="8.8.8.8", proto="tcp", port=443, sz="LAN", dz="WAN"):
    flow = {"src": ipaddress.IPv4Address(src), "dst": ipaddress.IPv4Address(dst), "protocol": proto, "port": port, "src_zone": sz, "dst_zone": dz}
    return evaluate_rule(r, flow, OBJS)


def test_zonas():
    assert ev(rule("a", sourceZones=z("DMZ")))["result"] == NO_MATCH
    assert ev(rule("a", sourceZones=z("LAN"), destinationZones=z("WAN")))["result"] == MATCH
    assert ev(rule("a"))["result"] == MATCH                                   # any
    assert ev(rule("a", sourceZones=z("LAN")), sz=None)["result"] == POSSIBLE  # zona desconocida


@pytest.mark.parametrize("sel,ip,esperado", [
    (nets(ipv4Addresses=["srv-web"]), "10.0.10.5", True),
    (nets(ipv4Addresses=["srv-web"]), "10.0.10.6", False),
    (nets(ipv4Addresses=["lan-net"]), "10.0.1.77", True),
    (nets(ipv4Addresses=["lan-net"]), "10.0.2.77", False),
    (nets(ipv4Addresses=["rango-it"]), "10.0.1.110", True),
    (nets(ipv4Addresses=["rango-it"]), "10.0.1.121", False),
    (nets(ipv4Addresses=["lista-vip"]), "10.0.1.201", True),
    (nets(ipv4Addresses=["lista-vip"]), "10.0.1.202", False),
    (nets(ipv4Groups=["grupo-serv"]), "10.0.1.101", True),     # miembro del grupo: rango
    (nets(ipv4Groups=["grupo-serv"]), "10.0.10.5", True),      # miembro del grupo: host
    (nets(ipv4Groups=["grupo-serv"]), "10.0.9.9", False),
    (ANY, "1.2.3.4", True),
])
def test_redes(sel, ip, esperado):
    assert network_match(sel, ipaddress.IPv4Address(ip), OBJS) is esperado


def test_objetos_no_evaluables_dejan_la_regla_en_posible():
    for sel in (nets(fqdnAddresses=["x.example"]), nets(countries=["Ecuador"]), nets(macAddresses=["m"]),
                nets(ipv4Addresses=["no-existe"]), nets(ipv4Groups=["grupo-fantasma"])):
        assert ev(rule("a", destinationNetworks=sel))["result"] == POSSIBLE
    mixto = nets(ipv4Addresses=["srv-web"], fqdnAddresses=["x.example"])   # coincide uno evaluable -> verdadero
    assert ev(rule("a", destinationNetworks=mixto), dst="10.0.10.5")["result"] == MATCH
    assert ev(rule("a", destinationNetworks=mixto), dst="9.9.9.9")["result"] == POSSIBLE   # el FQDN podría ser 9.9.9.9


def test_servicios():
    assert ev(rule("a", servicesOrGroups=svcs(["HTTPS"])))["result"] == MATCH
    assert ev(rule("a", servicesOrGroups=svcs(["HTTPS"])), port=80)["result"] == NO_MATCH
    assert ev(rule("a", servicesOrGroups=svcs(["Altos"])), port=8443)["result"] == MATCH          # rango
    assert ev(rule("a", servicesOrGroups=svcs(["Altos"])), port=9000)["result"] == NO_MATCH
    assert ev(rule("a", servicesOrGroups=svcs(["DNS"])), proto="udp", port=53)["result"] == MATCH
    assert ev(rule("a", servicesOrGroups=svcs(["HTTPS"])), proto="udp", port=443)["result"] == NO_MATCH  # protocolo distinto
    assert ev(rule("a", servicesOrGroups=svcs(["Ping"])), proto="icmp", port=None)["result"] == MATCH
    assert ev(rule("a", servicesOrGroups=svcs(["Ping"])), proto="tcp")["result"] == NO_MATCH
    assert ev(rule("a", servicesOrGroups=svcs(["GRE"])), proto="gre", port=None)["result"] == MATCH
    assert ev(rule("a", servicesOrGroups=svcs(groups=["web"])), port=8080)["result"] == MATCH     # grupo
    assert ev(rule("a", servicesOrGroups=svcs(groups=["web"])), port=22)["result"] == NO_MATCH
    assert ev(rule("a", servicesOrGroups=svcs(["Fantasma"])))["result"] == POSSIBLE


def test_puerto_omitido_con_regla_de_puerto_especifico_es_posible():
    assert ev(rule("a", servicesOrGroups=svcs(["HTTPS"])), port=None)["result"] == POSSIBLE
    assert ev(rule("a", servicesOrGroups=svcs(["HTTPS"])), port=None, proto="udp")["result"] == NO_MATCH  # el protocolo ya descarta
    assert ev(rule("a"), port=None)["result"] == MATCH


def test_exclusiones():
    r = rule("a", exclusions={"sourceNetworks": nets(ipv4Addresses=["rango-it"])})
    assert ev(r, src="10.0.1.110")["result"] == NO_MATCH
    assert ev(r, src="10.0.1.50")["result"] == MATCH
    rs = rule("a", exclusions={"servicesOrGroups": svcs(["HTTPS"])})
    assert ev(rs, port=443)["result"] == NO_MATCH and ev(rs, port=80)["result"] == MATCH
    rz = rule("a", exclusions={"sourceZones": z("LAN")})
    assert ev(rz)["result"] == NO_MATCH and ev(rz, sz="DMZ")["result"] == MATCH
    ru = rule("a", exclusions={"destinationNetworks": nets(fqdnAddresses=["x.example"])})
    assert ev(ru)["result"] == POSSIBLE


def test_horario_e_identidad_dejan_la_regla_en_posible_con_nota():
    h = ev(rule("a", schedule={"name": "Laboral"}))
    assert h["result"] == POSSIBLE and "Laboral" in h["notes"][0]
    assert ev(rule("a", schedule={"name": "All the time"}))["result"] == MATCH
    u = ev(rule("a", userAuthentication={"matchKnownUsers": True, "users": [{"name": "ana"}]}))
    assert u["result"] == POSSIBLE and "usuarios" in u["notes"][0]


def test_orden_primera_coincidencia_definitiva_y_posibles_anteriores():
    rules = [
        rule("fqdn-externo", "drop", destinationNetworks=nets(fqdnAddresses=["x.example"])),     # posible
        rule("solo-dmz", "accept", sourceZones=z("DMZ")),                                        # no
        rule("apagada", "drop", enabled=False),                                                  # se ignora
        rule("lan-https", "accept", sourceZones=z("LAN"), servicesOrGroups=svcs(["HTTPS"])),     # decide
        rule("todo", "drop"),                                                                    # no se alcanza
    ]
    out = explain_rule_match(rules, OBJS, "10.0.1.50", "8.8.8.8", "tcp", 443, "LAN", "WAN")
    assert out["decision"]["name"] == "lan-https" and out["decision"]["position"] == 4
    assert [p["name"] for p in out["possible_earlier"]] == ["fqdn-externo"] and out["possible_earlier"][0]["unknown"] == ["red_destino"]
    assert any(f["severity"] == "warning" for f in out["findings"])
    assert "#4" in out["verdict"]


def test_sin_coincidencia_es_descarte_implicito():
    out = explain_rule_match([rule("solo-dmz", sourceZones=z("DMZ"))], OBJS, "10.0.1.50", "8.8.8.8", "tcp", 443, "LAN", "WAN")
    assert out["decision"] is None and "implícita" in out["verdict"]
    posible = explain_rule_match([rule("p", destinationNetworks=nets(countries=["Ecuador"]))], OBJS, "10.0.1.50", "8.8.8.8", "tcp", 443, "LAN", "WAN")
    assert posible["decision"] is None and "implícita" not in posible["verdict"] and posible["possible_earlier"]


def test_why_not_explica_el_criterio_que_falla():
    rules = [rule("lan-wan-dns", sourceZones=z("LAN"), destinationZones=z("WAN"), servicesOrGroups=svcs(["DNS"])),
             rule("dmz-wan", sourceZones=z("DMZ"), destinationZones=z("WAN")),               # otro par de zonas: no se lista
             rule("lan-wan-srv", sourceZones=z("LAN"), destinationZones=z("WAN"), destinationNetworks=nets(ipv4Addresses=["srv-web"]))]
    out = explain_rule_match(rules, OBJS, "10.0.1.50", "8.8.8.8", "tcp", 443, "LAN", "WAN")
    assert out["decision"] is None
    by = {w["name"]: w["failed"] for w in out["why_not"]}
    assert set(by) == {"lan-wan-dns", "lan-wan-srv"}
    assert list(by["lan-wan-dns"]) == ["servicio"] and list(by["lan-wan-srv"]) == ["red_destino"]


def test_entradas_invalidas():
    for kwargs in ({"source_ip": "no-ip"}, {"destination_ip": "2001:db8::1"}, {"port": 0}, {"port": 70000}, {"protocol": "icmp", "port": 8}):
        args = {"source_ip": "10.0.1.50", "destination_ip": "8.8.8.8", "protocol": "tcp", "port": 443, **kwargs}
        with pytest.raises(ValueError):
            explain_rule_match([], OBJS, args["source_ip"], args["destination_ip"], args["protocol"], args["port"])


def test_sin_zonas_se_avisa():
    out = explain_rule_match([rule("a", sourceZones=z("LAN"))], OBJS, "10.0.1.50", "8.8.8.8", "tcp", 443)
    assert out["decision"] is None and out["possible_earlier"] and any("Zonas no indicadas" in f["message"] for f in out["findings"])


# -- Herramienta MCP ----------------------------------------------------------------------------------

import json
from pathlib import Path

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from alfil_mcp import server
from alfil_mcp.config import AlfilSettings

GRAPH = json.loads((Path(__file__).parent / "fixtures" / "topology_graph.json").read_text(encoding="utf-8"))
TOKEN = "alfil_mcp_token-de-prueba"
RULES = [rule("dmz-fuera", "accept", sourceZones=z("DMZ")),
         rule("lan-https", "accept", sourceZones=z("LAN"), destinationZones=z("WAN"), servicesOrGroups=svcs(["HTTPS"])),
         rule("todo", "drop")]
ITEMS = {"/firewall/rules/ipv4": RULES, "/network/addresses/ipv4": OBJS.hosts.values(), "/network/address-groups/ipv4": OBJS.host_groups.values(),
         "/network/services": OBJS.services.values(), "/network/service-groups": OBJS.service_groups.values()}


def hub(topology=True):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        seen.append((req.method, p, req.url.params.get("path")))
        if p == "/api/v1/mcp/connections":
            return httpx.Response(200, json=[{"id": 1, "name": "lab-rest", "host": "fw.test", "port": 4444, "verify_ssl": False}])
        if p == "/api/v1/mcp/connections/1/topology":
            return httpx.Response(200, json=GRAPH) if topology else httpx.Response(502, json={"detail": "sin red"})
        if p.endswith("/get"):
            return httpx.Response(200, json={"items": list(ITEMS[req.url.params["path"]])})
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


async def test_tool_deduce_zonas_de_la_topologia_y_solo_lee():
    server._hub = h = hub()
    out = await server.explain_rule_match("10.0.1.50", "8.8.8.8", "tcp", 443)
    assert out["flow"]["source_zone"] == "LAN" and out["flow"]["destination_zone"] == "WAN"
    assert out["decision"]["name"] == "lan-https" and out["connection"] == "lab-rest"
    assert any("deducidas de la topología" in f["message"] for f in out["findings"])
    assert all(method == "GET" for method, _, _ in h.seen)                      # solo lectura
    paths = {p for _, _, p in h.seen if p}
    assert paths == set(ITEMS)
    from alfil_mcp.client import is_known_get_path
    assert all(is_known_get_path(p) for p in paths)                              # todas están en el catálogo de la spec


async def test_tool_zonas_manuales_y_sin_topologia():
    server._hub = hub(topology=False)
    manual = await server.explain_rule_match("10.0.1.50", "8.8.8.8", "tcp", 80, source_zone="DMZ", destination_zone="WAN")
    assert manual["decision"]["name"] == "dmz-fuera"                              # no necesitó topología
    sin = await server.explain_rule_match("10.0.1.50", "8.8.8.8", "tcp", 443)     # la topología falla: evalúa sin zonas y avisa
    msgs = " ".join(f["message"] for f in sin["findings"])
    assert "No se pudieron deducir las zonas" in msgs and "Zonas no indicadas" in msgs and sin["possible_earlier"]


async def test_tool_entradas_invalidas_dan_error_legible():
    server._hub = hub()
    with pytest.raises(ToolError, match="Entrada no válida"):
        await server.explain_rule_match("10.0.1.50", "8.8.8.8", "tcp", 99999)
    with pytest.raises(ToolError, match="Entrada no válida"):
        await server.explain_rule_match("nope", "8.8.8.8")
