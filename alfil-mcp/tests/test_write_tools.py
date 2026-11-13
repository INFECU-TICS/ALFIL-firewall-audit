"""Herramientas de la fase 2 en el MCP: proponen y aplican a través de ALFIL; sin confirmación o sin ALFIL no hacen nada."""
import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from alfil_mcp import server
from alfil_mcp.config import AlfilSettings

TOKEN = "alfil_mcp_t"
PLAN = {"change_id": "abc-123", "status": "proposed", "summary": "DESHABILITAR la regla «web».", "request": {"method": "PATCH"}}


def hub(handler, seen):
    def wrapped(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, req.content.decode() if req.content else ""))
        if req.url.path == "/api/v1/mcp/connections":
            return httpx.Response(200, json=[{"id": 7, "name": "lab", "host": "fw.test", "port": 4444, "verify_ssl": False, "write_enabled": True}])
        return handler(req)
    return server.AlfilHub(AlfilSettings(url="http://alfil.test", token=TOKEN), transport=httpx.MockTransport(wrapped))


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for var in ("SFOS_HOST", "SFOS_TOKEN", "API_KEY", "SFOS_ENV_FILE", "ALFIL_URL", "ALFIL_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    server.reset_state()
    yield
    server.reset_state()


async def test_las_herramientas_de_escritura_estan_marcadas_y_las_de_lectura_no():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    for n in ("propose_create_rule", "propose_set_rule_enabled", "propose_move_rule", "propose_create_host", "propose_create_service"):
        a = tools[n].annotations
        assert a.read_only_hint is False and a.destructive_hint is False, n
    assert tools["apply_change"].annotations.read_only_hint is False and tools["apply_change"].annotations.destructive_hint is True
    assert tools["list_changes"].annotations.read_only_hint is True and tools["audit_firewall"].annotations.read_only_hint is True
    assert not any(n.startswith(("delete", "remove", "update")) for n in tools)


async def test_proponer_envia_accion_y_parametros_y_pide_confirmacion():
    seen = []
    server._hub = hub(lambda req: httpx.Response(201, json=dict(PLAN)), seen)
    res = await server.propose_set_rule_enabled("web", False)
    assert res["change_id"] == "abc-123" and "apply_change" in res["next_step"] and "confirm=true" in res["next_step"]
    method, path, body = seen[-1]
    assert (method, path) == ("POST", "/api/v1/mcp/connections/7/changes")
    assert '"action":"set_rule_enabled"' in body.replace(" ", "") and '"name":"web"' in body.replace(" ", "")


async def test_crear_regla_no_envia_parametros_nulos():
    seen = []
    server._hub = hub(lambda req: httpx.Response(201, json=dict(PLAN)), seen)
    await server.propose_create_rule("r", "drop", source_zones=["LAN"])
    body = seen[-1][2].replace(" ", "")
    assert '"source_zones":["LAN"]' in body and "destination_zones" not in body and "reference" not in body and '"enabled":false' in body


async def test_error_de_validacion_de_alfil_llega_al_agente():
    server._hub = hub(lambda req: httpx.Response(422, json={"detail": "Política de ALFIL: Any→Any"}), [])
    with pytest.raises(ToolError, match="Any→Any"):
        await server.propose_create_rule("todo", "accept")


async def test_apply_change_exige_confirm_y_no_llama_a_alfil_sin_el():
    seen = []
    server._hub = hub(lambda req: httpx.Response(200, json={"status": "applied"}), seen)
    with pytest.raises(ToolError, match="confirm=true"):
        await server.apply_change("abc-123")
    assert not any("apply" in p for _, p, _ in seen)
    res = await server.apply_change("abc-123", confirm=True)
    assert res["status"] == "applied" and seen[-1][1] == "/api/v1/mcp/changes/abc-123/apply" and '"confirm":true' in seen[-1][2].replace(" ", "")


async def test_sin_alfil_no_hay_cambios():
    for call in (server.propose_create_host("h", ip="192.0.2.1"), server.apply_change("x", confirm=True), server.list_changes()):
        with pytest.raises(ToolError, match="ALFIL"):
            await call


async def test_en_modo_directo_no_hay_cambios(monkeypatch):
    monkeypatch.setenv("ALFIL_URL", "http://alfil.test")
    monkeypatch.setenv("ALFIL_MCP_TOKEN", TOKEN)
    monkeypatch.setenv("SFOS_HOST", "fw.test")
    monkeypatch.setenv("SFOS_TOKEN", "k")
    server.reset_state()
    server._hub = hub(lambda req: httpx.Response(201, json=dict(PLAN)), [])
    with pytest.raises(ToolError, match="modo directo"):
        await server.propose_create_host("h", ip="192.0.2.1", connection=server.DIRECT_NAME)


async def test_list_changes():
    server._hub = hub(lambda req: httpx.Response(200, json=[PLAN]), [])
    assert (await server.list_changes())[0]["change_id"] == "abc-123"
