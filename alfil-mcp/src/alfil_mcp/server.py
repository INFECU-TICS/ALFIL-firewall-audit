"""Servidor MCP ALFIL (fase 1, solo lectura) para Sophos Firewall v23."""
from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .analysis import rules as rule_analysis
from .client import SophosApiError, SophosClient, search_catalog
from .config import ConfigError, Settings

mcp = MCPServer(
    "alfil-mcp",
    version=__version__,
    instructions=(
        "Consulta y auditoría de solo lectura de un Sophos Firewall v23 vía REST API v1. "
        "Usa list_api_endpoints para descubrir rutas y api_get para leerlas; "
        "audit_firewall devuelve score y hallazgos de reglas. Ninguna herramienta modifica el firewall."
    ),
)
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

_client: SophosClient | None = None
_EXPECTED = (SophosApiError, ConfigError)


def read_tool(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Registra una tool de solo lectura; errores esperados llegan al modelo con su mensaje."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await fn(*args, **kwargs)
        except _EXPECTED as exc:
            raise ToolError(str(exc)) from exc

    return mcp.tool(annotations=READ_ONLY)(wrapper)


def get_client() -> SophosClient:
    global _client
    if _client is None:
        _client = SophosClient(Settings.from_env())
    return _client


@read_tool
async def list_api_endpoints(search: str = "", limit: int = 30) -> list[dict[str, Any]]:
    """Busca endpoints GET disponibles en la API v23 (266 en total). Ej.: search="nat rules"."""
    return search_catalog(search, min(max(limit, 1), 100))


@read_tool
async def api_get(path: str, query: dict[str, Any] | None = None) -> Any:
    """GET genérico sobre una ruta de list_api_endpoints (ej. /network/zones). Solo lectura.

    `query` admite page, pageSize, nameContains, etc.
    """
    return await get_client().get(path, query)


@read_tool
async def list_firewall_rules(only_enabled: bool = False) -> list[dict[str, Any]]:
    """Lista reglas de firewall IPv4 (resumen: nombre, acción, zonas, log, habilitada)."""
    rules = await get_client().get_all("/firewall/rules/ipv4")
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
async def get_firewall_rule(id_or_name: str) -> Any:
    """Detalle completo de una regla IPv4 por nombre o UUID."""
    return await get_client().get(f"/firewall/rules/ipv4/{id_or_name}")


@read_tool
async def audit_firewall() -> dict[str, Any]:
    """Audita las reglas IPv4: Any→Any, sin log, duplicadas, deshabilitadas. Score 0-100 (fórmula ALFIL)."""
    rules = await get_client().get_all("/firewall/rules/ipv4")
    return rule_analysis.audit_rules(rules)


@mcp.resource("firewall://summary")
async def summary() -> str:
    """Resumen rápido del firewall: zonas y cantidad de reglas."""
    try:
        client = get_client()
        zones = await client.get_all("/network/zones")
        rules = await client.get_all("/firewall/rules/ipv4")
    except _EXPECTED as exc:
        raise ResourceError(str(exc)) from exc
    return json.dumps({"zones": [z.get("name") for z in zones], "ipv4Rules": len(rules)}, ensure_ascii=False)


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
