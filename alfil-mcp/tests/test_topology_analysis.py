"""Resumen y explicación de rutas sobre el grafo de topología de ALFIL (fixture sintético con rangos de documentación)."""
import json
from pathlib import Path

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from alfil_mcp import server
from alfil_mcp.analysis.topology import explain_path, resolve_ip, summarize
from alfil_mcp.config import AlfilSettings

GRAPH = json.loads((Path(__file__).parent / "fixtures" / "topology_graph.json").read_text(encoding="utf-8"))


def kinds(ip):
    return resolve_ip(GRAPH, ip)


def test_resuelve_red_conectada_con_zona_e_interfaz():
    r = kinds("10.0.1.50")
    assert (r["kind"], r["network"], r["zone"], r["interface"]) == ("connected", "10.0.1.0/24", "LAN", "PortA")
    v = kinds("10.0.10.7")  # VLAN como interfaz
    assert (v["zone"], v["interface"]) == ("DMZ", "PortA.10")
    assert kinds("198.51.100.6")["interface"] == "PortB"      # alias (IP secundaria)


def test_ruta_estatica_vpn_blackhole_y_por_defecto():
    r = kinds("172.16.5.5")
    assert (r["kind"], r["network"], r["via"], r["zone"], r["interface"]) == ("route", "172.16.0.0/16", "10.0.1.254", "LAN", "PortA")
    v = kinds("10.200.1.1")
    assert (v["kind"], v["tunnel"], v["zone"]) == ("vpn", "sitio-b", "VPN")
    assert kinds("198.18.4.4")["kind"] == "blackhole"
    d = kinds("8.8.8.8")
    assert (d["kind"], d["via"], d["zone"]) == ("default", "203.0.113.1", "WAN")
    assert kinds("192.168.50.9")["unreachable"] is True


def test_prefijo_mas_largo_y_conectada_gana_a_igual_prefijo():
    assert kinds("10.0.1.254")["kind"] == "connected"   # 10.0.1.0/24 conectada
    assert resolve_ip(GRAPH, "172.16.0.1")["network"] == "172.16.0.0/16"


def test_ip_invalida_o_ipv6():
    with pytest.raises(ValueError):
        resolve_ip(GRAPH, "no-es-ip")
    with pytest.raises(ValueError, match="IPv4"):
        resolve_ip(GRAPH, "2001:db8::1")


def test_explain_path_lan_a_internet_con_reglas_candidatas():
    rules = [
        {"name": "solo-dmz", "enabled": True, "action": "accept", "sourceZones": {"items": [{"name": "DMZ"}]}, "destinationZones": {"any": True}},
        {"name": "lan-to-wan", "enabled": True, "action": "accept", "sourceZones": {"items": [{"name": "LAN"}]}, "destinationZones": {"items": [{"name": "WAN"}]}},
        {"name": "apagada", "enabled": False, "action": "drop", "sourceZones": {"any": True}, "destinationZones": {"any": True}},
        {"name": "cualquiera", "enabled": True, "action": "drop", "sourceZones": {"any": True}, "destinationZones": {"any": True}},
    ]
    out = explain_path(GRAPH, "10.0.1.50", "8.8.8.8", rules)
    assert (out["source_zone"], out["destination_zone"]) == ("LAN", "WAN") and "LAN → WAN" in out["verdict"]
    assert [r["name"] for r in out["candidate_rules"]] == ["lan-to-wan", "cualquiera"]   # sin la de DMZ ni la deshabilitada
    assert [r["position"] for r in out["candidate_rules"]] == [2, 4] and "NO se evaluaron" in out["candidate_rules_note"]
    assert any("ruta por defecto" in s for s in out["steps"])


def test_explain_path_mismo_segmento_y_problemas():
    assert "no pasa por el firewall" in explain_path(GRAPH, "10.0.1.50", "10.0.1.60")["verdict"]
    bh = explain_path(GRAPH, "10.0.1.50", "198.18.0.9")
    assert any(f["severity"] == "critical" and "blackhole" in f["message"] for f in bh["findings"])
    orphan = explain_path(GRAPH, "10.0.1.50", "192.168.50.9")
    assert any("no está en ninguna red conectada" in f["message"] for f in orphan["findings"])
    vpn = explain_path(GRAPH, "10.0.1.50", "10.200.1.1")
    assert vpn["destination_zone"] == "VPN" and "sitio-b" in " ".join(vpn["steps"])
    ext = explain_path(GRAPH, "8.8.8.8", "10.0.1.50")      # origen externo: supuesto explícito
    assert ext["source_zone"] == "WAN" and any("Supuesto" in f["message"] for f in ext["findings"])
    assert "candidate_rules" not in explain_path(GRAPH, "10.0.1.50", "8.8.8.8")   # sin reglas, no se inventan


def test_sin_ruta_por_defecto_no_hay_ruta():
    g = {"nodes": [n for n in GRAPH["nodes"] if n["type"] not in ("internet",) and n["id"] not in ("rt:203.0.113.1",)],
         "edges": [e for e in GRAPH["edges"] if "internet" not in (e["source"], e["target"]) and "rt:203.0.113.1" not in (e["source"], e["target"])],
         "meta": {}}
    out = explain_path(g, "10.0.1.50", "8.8.8.8")
    assert out["destination"]["kind"] == "unknown" and any("No hay ruta" in f["message"] for f in out["findings"])


def test_resumen_legible():
    s = summarize(GRAPH)
    assert s["firewall"] == "fw-lab"
    lan = next(z for z in s["zones"] if z["zone"] == "LAN")
    assert lan["interfaces"][0]["name"] == "PortA" and lan["interfaces"][0]["networks"] == ["10.0.1.0/24"]
    dmz = next(z for z in s["zones"] if z["zone"] == "DMZ")["interfaces"][0]
    assert dmz["kind"] == "vlan" and dmz["vlan_id"] == 10 and dmz["parent_interface"] == "PortA"
    dests = {r["destination"]: r for r in s["routes"]}
    assert dests["172.16.0.0/16"]["via"] == "10.0.1.254" and dests["0.0.0.0/0"]["via"] == "203.0.113.1"
    assert dests["192.168.50.0/24"]["unreachable"] is True and dests["198.18.0.0/16"]["action"] == "descartar"
    vpn = s["vpn_tunnels"][0]
    assert vpn["name"] == "sitio-b" and vpn["remote_gateway"] == "198.51.100.77" and vpn["remote_networks"] == ["10.200.0.0/16"]
    assert any(w["code"] == "route_nexthop_unreachable" for w in s["warnings"]) and s["notes"]


# -- Herramientas MCP -------------------------------------------------------------------------------

TOKEN = "alfil_mcp_token-de-prueba"


def hub_with_topology(topology_status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p == "/api/v1/mcp/connections":
            return httpx.Response(200, json=[{"id": 1, "name": "lab-rest", "host": "fw.test", "port": 4444, "verify_ssl": False}])
        if p == "/api/v1/mcp/connections/1/topology":
            return httpx.Response(topology_status, json=GRAPH if topology_status == 200 else {"detail": "No se pudo leer la configuración de red"})
        if p.endswith("/get"):
            return httpx.Response(200, json={"items": [{"name": "lan-to-wan", "enabled": True, "action": "accept",
                                                       "sourceZones": {"items": [{"name": "LAN"}]}, "destinationZones": {"items": [{"name": "WAN"}]}}]})
        return httpx.Response(404, json={"detail": "no"})
    return server.AlfilHub(AlfilSettings(url="http://alfil.test", token=TOKEN), transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for var in ("SFOS_HOST", "SFOS_TOKEN", "API_KEY", "SFOS_ENV_FILE", "ALFIL_URL", "ALFIL_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    server.reset_state()
    yield
    server.reset_state()


async def test_tool_get_topology_resumen_y_grafo():
    server._hub = hub_with_topology()
    out = await server.get_topology()
    assert out["connection"] == "lab-rest" and out["firewall"] == "fw-lab" and "zones" in out and "nodes" not in out
    graph = await server.get_topology(format="graph")
    assert len(graph["nodes"]) == len(GRAPH["nodes"])
    with pytest.raises(ToolError, match="summary"):
        await server.get_topology(format="otro")


async def test_tool_explain_path_con_reglas_de_la_conexion():
    server._hub = hub_with_topology()
    out = await server.explain_path("10.0.1.50", "8.8.8.8")
    assert out["verdict"].startswith("Flujo LAN → WAN") and out["candidate_rules"][0]["name"] == "lan-to-wan"
    assert "candidate_rules" not in await server.explain_path("10.0.1.50", "8.8.8.8", include_rules=False)
    with pytest.raises(ToolError, match="IP no válida"):
        await server.explain_path("x", "8.8.8.8")


async def test_topologia_exige_conexion_de_alfil_y_traduce_errores(monkeypatch):
    monkeypatch.setenv("SFOS_HOST", "fw-directo.test"); monkeypatch.setenv("SFOS_TOKEN", "t")
    with pytest.raises(ToolError, match="solo está disponible con conexiones de ALFIL"):
        await server.get_topology()
    monkeypatch.delenv("SFOS_HOST"); monkeypatch.delenv("SFOS_TOKEN")
    server.reset_state()
    server._hub = hub_with_topology(502)
    with pytest.raises(ToolError, match="502.*No se pudo leer"):
        await server.get_topology()
