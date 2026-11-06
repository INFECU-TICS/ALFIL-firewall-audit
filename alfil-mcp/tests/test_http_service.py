"""Servicio MCP remoto (HTTP): autenticación por token, token por petición hacia ALFIL y aislamiento entre tokens."""
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from alfil_mcp import server
from alfil_mcp.alfil import AlfilError, AlfilHub

TOKEN_A, TOKEN_B = "alfil_mcp_token-A", "alfil_mcp_token-B"
BACKEND = {
    TOKEN_A: [{"id": 1, "name": "firewall-a", "host": "fw-a.test", "port": 4444, "verify_ssl": False}],
    TOKEN_B: [{"id": 7, "name": "firewall-b", "host": "fw-b.test", "port": 4444, "verify_ssl": True}],
}


def fake_backend(request: httpx.Request) -> httpx.Response:
    """Simula el backend de ALFIL: cada token ve solo sus conexiones."""
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    if token not in BACKEND:
        return httpx.Response(401, json={"detail": "Token MCP inválido o revocado"})
    path = request.url.path
    if path == "/api/v1/mcp/connections":
        return httpx.Response(200, json=BACKEND[token])
    if path.endswith("/get"):
        return httpx.Response(200, json={"items": [{"name": f"zona-de-{BACKEND[token][0]['name']}"}]})
    return httpx.Response(404, json={"detail": "no"})


@pytest.fixture()
def service(monkeypatch):
    server.reset_state()
    monkeypatch.setenv("ALFIL_URL", "http://alfil.test")
    real_hub = AlfilHub
    monkeypatch.setattr(server, "AlfilHub", lambda settings, **kw: real_hub(settings, transport=httpx.MockTransport(fake_backend)))

    async def validate(token: str) -> None:  # misma lógica que validate_token, contra el backend simulado
        hub = real_hub(server.AlfilSettings(url="http://alfil.test", token=token), transport=httpx.MockTransport(fake_backend))
        try:
            await hub.list_connections()
        finally:
            await hub.aclose()

    app = server.build_http_app(validate)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(timeout=5)
    server.reset_state()


def test_health_sin_token(service):
    r = httpx.get(f"{service}/health")
    assert r.status_code == 200 and r.json()["transport"] == "http" and r.json()["read_only"] is True and r.json()["tools"] == 11


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"}, {"Authorization": "Bearer token-inventado"}])
def test_mcp_exige_token_valido(service, headers):
    r = httpx.post(f"{service}/mcp", headers={"Accept": "application/json, text/event-stream", **headers},
                   json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
    assert "token" in r.json()["message"].lower()


def test_caida_de_alfil_es_503(service, monkeypatch):
    async def down(token):
        raise AlfilError("sin red", None)

    # el middleware ya está montado con el validador del fixture; probamos uno nuevo
    from starlette.testclient import TestClient
    app = server.build_http_app(down)
    with TestClient(app) as c:
        r = c.post("/mcp", headers={"Authorization": "Bearer x", "Accept": "application/json, text/event-stream"}, json={})
    assert r.status_code == 503


async def _call(url, token, tool, args=None):
    async with create_mcp_http_client(headers={"Authorization": f"Bearer {token}"}) as http:
        async with streamable_http_client(f"{url}/mcp", http_client=http) as (r, w, *_):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tools = [t.name for t in (await s.list_tools()).tools]
                res = await s.call_tool(tool, args or {})
                return tools, res


async def test_cliente_mcp_real_lista_herramientas_y_usa_su_token(service):
    tools, res = await _call(service, TOKEN_A, "list_connections")
    assert {"list_connections", "api_get", "audit_firewall", "list_firewall_rules"} <= set(tools)
    assert not res.is_error and "firewall-a" in res.content[0].text and "firewall-b" not in res.content[0].text


async def test_aislamiento_entre_tokens(service):
    _, a = await _call(service, TOKEN_A, "list_connections")
    _, b = await _call(service, TOKEN_B, "list_connections")
    assert "firewall-a" in a.content[0].text and "firewall-b" not in a.content[0].text
    assert "firewall-b" in b.content[0].text and "firewall-a" not in b.content[0].text
    # la conexión por defecto y el proxy también respetan el token de cada petición
    _, za = await _call(service, TOKEN_A, "api_get", {"path": "/network/zones"})
    _, zb = await _call(service, TOKEN_B, "api_get", {"path": "/network/zones"})
    assert "zona-de-firewall-a" in za.content[0].text and "zona-de-firewall-b" in zb.content[0].text


async def test_no_hay_conexion_directa_en_modo_http(service, monkeypatch):
    monkeypatch.setenv("SFOS_HOST", "fw-directo.test"); monkeypatch.setenv("SFOS_TOKEN", "t")
    _, res = await _call(service, TOKEN_A, "list_connections")
    assert "directa" not in res.content[0].text and "fw-directo" not in res.content[0].text
