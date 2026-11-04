"""Servidor MCP ALFIL (solo lectura) para Sophos Firewall v23.

Dos formas de acceder a un firewall:
- **Conexiones de ALFIL**: las habilitadas en el dashboard ("Disponible en MCP"). ALFIL custodia las credenciales y el
  MCP lee a través de su proxy de solo lectura (`ALFIL_URL` + `ALFIL_MCP_TOKEN`). Además envía un latido para que el
  dashboard muestre el estado del MCP.
- **Directa**: `SFOS_HOST` + `SFOS_TOKEN` en el entorno (una sola conexión).
"""
from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .alfil import AlfilHub, heartbeat_loop
from .analysis import rules as rule_analysis
from .client import SophosApiError, SophosClient, search_catalog
from .config import AlfilSettings, ConfigError, Settings

log = logging.getLogger(__name__)
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
DIRECT_NAME = "directa"
_EXPECTED = (SophosApiError, ConfigError)

_direct: SophosClient | None = None
_hub: AlfilHub | None = None
_proxies: dict[int, Any] = {}


def reset_state() -> None:
    """Descarta clientes en caché (pruebas y cambios de configuración)."""
    global _direct, _hub
    _direct = _hub = None
    _proxies.clear()


def get_hub() -> AlfilHub | None:
    global _hub
    if _hub is None:
        settings = AlfilSettings.from_env()
        if settings:
            _hub = AlfilHub(settings)
    return _hub


def get_direct() -> SophosClient | None:
    global _direct
    if _direct is None:
        settings = Settings.try_from_env()
        if settings:
            _direct = SophosClient(settings)
    return _direct


async def resolve_client(connection: str | None = None) -> tuple[Any, str]:
    """Elige el cliente: la conexión de ALFIL indicada, la directa o, si solo hay una en ALFIL, esa."""
    hub = get_hub()
    if connection and connection != DIRECT_NAME:
        if not hub:
            raise ConfigError("Para usar conexiones de ALFIL defina ALFIL_URL y ALFIL_MCP_TOKEN (token del dashboard).")
        found = await hub.find(connection)
        if found["id"] not in _proxies:
            _proxies[found["id"]] = hub.client_for(found["id"])
        return _proxies[found["id"]], found["name"]
    direct = get_direct()
    if direct and (connection == DIRECT_NAME or not hub):
        return direct, DIRECT_NAME
    if hub:
        conns = await hub.list_connections()
        if direct and not conns:
            return direct, DIRECT_NAME
        if len(conns) == 1 and not direct:
            return await resolve_client(conns[0]["name"])
        names = ", ".join([c["name"] for c in conns] + ([DIRECT_NAME] if direct else [])) or "ninguna"
        raise SophosApiError(f"Indique la conexión con el parámetro `connection`. Disponibles: {names}. "
                             "Habilite conexiones REST en el dashboard de ALFIL (\"Disponible en MCP\").")
    raise ConfigError("Sin conexión configurada: defina SFOS_HOST y SFOS_TOKEN, o ALFIL_URL y ALFIL_MCP_TOKEN.")


@contextlib.asynccontextmanager
async def lifespan(server: MCPServer) -> AsyncIterator[dict[str, Any]]:
    """Mientras el MCP está activo avisa a ALFIL (latido) para que el dashboard muestre su estado."""
    task: asyncio.Task[None] | None = None
    try:
        hub = get_hub()
    except ConfigError as exc:
        log.warning("%s", exc)
        hub = None
    if hub:
        tools = len(await server.list_tools())
        payload = {"version": __version__, "tools": tools, "read_only": True, "transport": "stdio"}
        task = asyncio.create_task(heartbeat_loop(hub, payload))
    try:
        yield {}
    finally:
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


mcp = MCPServer(
    "alfil-mcp",
    version=__version__,
    lifespan=lifespan,
    instructions=(
        "Consulta y auditoría de solo lectura de un Sophos Firewall v23 vía REST API v1. "
        "Use list_connections para ver los firewalls disponibles y el parámetro `connection` para elegir uno. "
        "list_api_endpoints y api_get leen cualquier ruta GET; audit_firewall devuelve score y hallazgos de reglas. "
        "Ninguna herramienta modifica el firewall."
    ),
)


def read_tool(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Registra una tool de solo lectura; errores esperados llegan al modelo con su mensaje."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await fn(*args, **kwargs)
        except _EXPECTED as exc:
            raise ToolError(str(exc)) from exc

    return mcp.tool(annotations=READ_ONLY)(wrapper)


@read_tool
async def list_connections() -> list[dict[str, Any]]:
    """Lista los firewalls disponibles: conexiones habilitadas en ALFIL ("Disponible en MCP") y la conexión directa."""
    out: list[dict[str, Any]] = []
    hub = get_hub()
    if hub:
        out += [{**c, "source": "alfil"} for c in await hub.list_connections()]
    direct = get_direct()
    if direct:
        out.append({"name": DIRECT_NAME, "host": direct_host(), "source": "env"})
    if not out:
        raise ConfigError("Sin conexión configurada: defina SFOS_HOST y SFOS_TOKEN, o ALFIL_URL y ALFIL_MCP_TOKEN.")
    return out


def direct_host() -> str:
    settings = Settings.try_from_env()
    return settings.host if settings else ""


@read_tool
async def list_api_endpoints(search: str = "", limit: int = 30) -> list[dict[str, Any]]:
    """Busca endpoints GET disponibles en la API v23 (266 en total). Ej.: search="nat rules"."""
    return search_catalog(search, min(max(limit, 1), 100))


@read_tool
async def api_get(path: str, query: dict[str, Any] | None = None, connection: str | None = None) -> Any:
    """GET genérico sobre una ruta de list_api_endpoints (ej. /network/zones). Solo lectura.

    `query` admite page, pageSize, nameContains, etc. `connection` elige el firewall (ver list_connections).
    """
    client, _ = await resolve_client(connection)
    return await client.get(path, query)


@read_tool
async def list_firewall_rules(only_enabled: bool = False, connection: str | None = None) -> list[dict[str, Any]]:
    """Lista reglas de firewall IPv4 (resumen: nombre, acción, zonas, log, habilitada)."""
    client, _ = await resolve_client(connection)
    rules = await client.get_all("/firewall/rules/ipv4")
    return [
        {
            "name": r.get("name"), "id": r.get("id"), "enabled": r.get("enabled"),
            "action": r.get("action"), "ruleType": r.get("ruleType"), "logTraffic": r.get("logTraffic"),
            "sourceZones": r.get("sourceZones"), "destinationZones": r.get("destinationZones"),
            "sourceNetworks": r.get("sourceNetworks"), "destinationNetworks": r.get("destinationNetworks"),
            "servicesOrGroups": r.get("servicesOrGroups"),
        }
        for r in rules if r.get("enabled") or not only_enabled
    ]


@read_tool
async def get_firewall_rule(id_or_name: str, connection: str | None = None) -> Any:
    """Detalle completo de una regla IPv4 por nombre o UUID."""
    client, _ = await resolve_client(connection)
    return await client.get(f"/firewall/rules/ipv4/{id_or_name}")


@read_tool
async def audit_firewall(connection: str | None = None) -> dict[str, Any]:
    """Audita las reglas IPv4: Any→Any, sin log, duplicadas, deshabilitadas. Score 0-100 (fórmula ALFIL)."""
    client, label = await resolve_client(connection)
    rules = await client.get_all("/firewall/rules/ipv4")
    return {"connection": label, **rule_analysis.audit_rules(rules)}


@mcp.resource("firewall://summary")
async def summary() -> str:
    """Resumen rápido del firewall (conexión por defecto): zonas y cantidad de reglas."""
    try:
        client, label = await resolve_client(None)
        zones = await client.get_all("/network/zones")
        rules = await client.get_all("/firewall/rules/ipv4")
    except _EXPECTED as exc:
        raise ResourceError(str(exc)) from exc
    return json.dumps({"connection": label, "zones": [z.get("name") for z in zones], "ipv4Rules": len(rules)}, ensure_ascii=False)


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
