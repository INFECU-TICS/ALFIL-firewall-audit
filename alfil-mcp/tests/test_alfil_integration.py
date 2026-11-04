"""Modo ALFIL: conexiones del dashboard vía proxy, selección de conexión y latido."""
import asyncio
import json

import httpx
import pytest

from alfil_mcp import server
from alfil_mcp.alfil import AlfilHub, AlfilProxyClient, heartbeat_loop
from alfil_mcp import alfil as alfil_module
from alfil_mcp.client import SophosApiError
from alfil_mcp.config import AlfilSettings, ConfigError

TOKEN = "alfil_mcp_token-de-prueba"
CONNS = [{"id": 1, "name": "lab-rest", "host": "fw1.test", "port": 4444, "verify_ssl": False},
         {"id": 2, "name": "sucursal", "host": "fw2.test", "port": 4444, "verify_ssl": True}]


def make_hub(handler=None, conns=CONNS):
    calls = []

    def default(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        assert req.headers["authorization"] == f"Bearer {TOKEN}"
        path = req.url.path
        if path == "/api/v1/mcp/connections":
            return httpx.Response(200, json=conns)
        if path == "/api/v1/mcp/heartbeat":
            return httpx.Response(204)
        if path.endswith("/get"):
            page = int(req.url.params.get("page", 1))
            n = 100 if page == 1 and req.url.params["path"] == "/firewall/rules/ipv4" and "paginar" in req.url.params.get("x", "") else 2
            return httpx.Response(200, json={"items": [{"name": f"r{page}-{i}", "enabled": True, "action": "accept", "logTraffic": True} for i in range(n)]})
        return httpx.Response(404, json={"detail": "no"})

    hub = AlfilHub(AlfilSettings(url="http://alfil.test", token=TOKEN), transport=httpx.MockTransport(handler or default))
    hub.calls = calls
    return hub


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for var in ("SFOS_HOST", "SFOS_TOKEN", "API_KEY", "SFOS_ENV_FILE", "ALFIL_URL", "ALFIL_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    server.reset_state()
    yield
    server.reset_state()


def test_settings_alfil():
    assert AlfilSettings.from_env() is None
    import os
    os.environ["ALFIL_URL"] = "http://localhost:8081/"
    try:
        with pytest.raises(ConfigError):
            AlfilSettings.from_env()
        os.environ["ALFIL_MCP_TOKEN"] = TOKEN
        s = AlfilSettings.from_env()
        assert s.api_base == "http://localhost:8081/api/v1/mcp" and TOKEN not in repr(s)
    finally:
        os.environ.pop("ALFIL_URL"); os.environ.pop("ALFIL_MCP_TOKEN", None)


async def test_hub_busca_por_nombre_o_id_y_lista_las_opciones():
    hub = make_hub()
    assert (await hub.find("sucursal"))["id"] == 2 and (await hub.find("1"))["name"] == "lab-rest"
    with pytest.raises(SophosApiError, match="lab-rest, sucursal"):
        await hub.find("inexistente")


async def test_hub_traduce_errores():
    hub = make_hub(lambda r: httpx.Response(401, json={"detail": "Token MCP inválido o revocado"}))
    with pytest.raises(SophosApiError, match="genere uno nuevo en el dashboard"):
        await hub.list_connections()
    hub = make_hub(lambda r: httpx.Response(502, json={"detail": "API key rechazada (HTTP 401)"}))
    with pytest.raises(SophosApiError, match="502.*API key rechazada"):
        await hub.client_for(1).get("/network/zones")

    def down(r):
        raise httpx.ConnectError("sin red")

    with pytest.raises(SophosApiError, match="ALFIL_URL"):
        await make_hub(down).list_connections()


async def test_proxy_reenvia_ruta_y_parametros_y_valida_la_spec():
    hub = make_hub()
    client = hub.client_for(1)
    data = await client.get("/network/zones", {"pageSize": 50})
    assert data["items"] and hub.calls[-1].url.path == "/api/v1/mcp/connections/1/get"
    assert hub.calls[-1].url.params["path"] == "/network/zones" and hub.calls[-1].url.params["pageSize"] == "50"
    n = len(hub.calls)
    with pytest.raises(SophosApiError, match="no existe en la spec"):
        await client.get("/no/existe")
    assert len(hub.calls) == n  # ni siquiera sale la petición


async def test_proxy_pagina():
    pages = []

    def handler(req):
        page = int(req.url.params["page"]); pages.append(page)
        return httpx.Response(200, json={"items": [{"i": i} for i in (range(100) if page == 1 else range(5))]})

    items = await AlfilProxyClient(make_hub(handler), 1).get_all("/network/zones")
    assert len(items) == 105 and pages == [1, 2]


async def test_resolve_client_con_conexion_explicita(monkeypatch):
    server._hub = make_hub()
    client, label = await server.resolve_client("sucursal")
    assert label == "sucursal" and isinstance(client, AlfilProxyClient)
    with pytest.raises(SophosApiError, match="Disponibles"):
        await server.resolve_client("otra")


async def test_resolve_client_por_defecto():
    server._hub = make_hub(conns=[CONNS[0]])
    assert (await server.resolve_client(None))[1] == "lab-rest"            # una sola conexión: se usa
    server._hub = make_hub()
    with pytest.raises(SophosApiError, match="lab-rest, sucursal"):         # varias: hay que indicarla
        await server.resolve_client(None)


async def test_resolve_client_sin_configuracion_o_sin_alfil():
    with pytest.raises(ConfigError, match="Sin conexión"):
        await server.resolve_client(None)
    with pytest.raises(ConfigError, match="ALFIL_URL"):
        await server.resolve_client("lab-rest")


async def test_conexion_directa_y_alfil_conviven(monkeypatch):
    monkeypatch.setenv("SFOS_HOST", "fw-directo.test"); monkeypatch.setenv("SFOS_TOKEN", "t")
    server._hub = make_hub()
    assert (await server.resolve_client("directa"))[1] == "directa"
    with pytest.raises(SophosApiError, match="directa"):                    # ambigüedad: se pide `connection`
        await server.resolve_client(None)
    server._hub = make_hub(conns=[])
    assert (await server.resolve_client(None))[1] == "directa"              # ALFIL sin habilitadas: la directa
    names = [c["name"] for c in await server.list_connections()]
    assert names == ["directa"]


async def test_tools_list_connections_y_audit_con_conexion():
    server._hub = make_hub()
    conns = await server.list_connections()
    assert [(c["name"], c["source"]) for c in conns] == [("lab-rest", "alfil"), ("sucursal", "alfil")]
    assert all("password" not in c and "token" not in c for c in conns)
    out = await server.audit_firewall(connection="sucursal")
    assert out["connection"] == "sucursal" and out["totalRules"] == 2 and 0 <= out["score"] <= 100
    got = await server.api_get("/network/zones", connection="lab-rest")
    assert got["items"]


async def test_tools_sin_configuracion_dan_error_legible():
    from mcp.server.mcpserver.exceptions import ToolError
    with pytest.raises(ToolError, match="Sin conexión"):
        await server.audit_firewall()


async def test_latido_envia_estado_y_sobrevive_a_fallos(monkeypatch):
    monkeypatch.setattr(alfil_module, "HEARTBEAT_SECONDS", 0.01)
    sent = []

    def handler(req):
        sent.append(json.loads(req.content))
        return httpx.Response(204) if len(sent) > 1 else httpx.Response(500, json={"detail": "caído"})  # el 1.º falla

    hub = make_hub(handler)
    task = asyncio.create_task(heartbeat_loop(hub, {"version": "0.2.0", "tools": 6, "read_only": True, "transport": "stdio"}))
    await asyncio.sleep(0.2)
    task.cancel()
    assert len(sent) >= 2 and sent[0]["tools"] == 6 and sent[0]["read_only"] is True  # siguió enviando tras el fallo
