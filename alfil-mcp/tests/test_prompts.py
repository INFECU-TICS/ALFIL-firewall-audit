"""Prompts MCP: existen, usan solo herramientas registradas y reciben sus argumentos."""
import re

from alfil_mcp import server


async def test_prompts_registrados():
    names = {p.name for p in await server.mcp.list_prompts()}
    assert names == {"revision_de_salud", "por_que_no_pasa_este_trafico"}


async def test_los_prompts_solo_nombran_herramientas_existentes():
    tools = {t.name for t in await server.mcp.list_tools()}
    for name, args in (("revision_de_salud", {}), ("por_que_no_pasa_este_trafico", {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.2"})):
        res = await server.mcp.get_prompt(name, args)
        text = " ".join(m.content.text for m in res.messages)
        mentioned = set(re.findall(r"\b(?:audit_\w+|explain_\w+|find_\w+|trace_\w+|list_connections|get_topology)\b", text))
        assert mentioned and mentioned <= tools, (name, mentioned - tools)


async def test_argumentos_del_diagnostico():
    res = await server.mcp.get_prompt("por_que_no_pasa_este_trafico", {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.2",
                                                                      "protocol": "udp", "destination_port": "53", "connection": "lab"})
    text = res.messages[0].content.text
    assert "UDP de 192.0.2.1 a 198.51.100.2, puerto de destino 53 en la conexión «lab»" in text
