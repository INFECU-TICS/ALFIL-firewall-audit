"""Servidor MCP ALFIL (solo lectura) para Sophos Firewall v23.

Dos formas de acceder a un firewall:
- **Conexiones de ALFIL**: las habilitadas en el dashboard ("Disponible en MCP"). ALFIL custodia las credenciales y el
  MCP lee a través de su proxy de solo lectura (`ALFIL_URL` + `ALFIL_MCP_TOKEN`). Además envía un latido para que el
  dashboard muestre el estado del MCP.
- **Directa**: `SFOS_HOST` + `SFOS_TOKEN` en el entorno (una sola conexión).
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import contextvars
import functools
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .alfil import AlfilError, AlfilHub, heartbeat_loop
from .analysis import rules as rule_analysis
from .analysis import topology as topo_analysis
from .client import SophosApiError, SophosClient, search_catalog
from .config import AlfilSettings, ConfigError, Settings

log = logging.getLogger(__name__)
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
DIRECT_NAME = "directa"
_EXPECTED = (SophosApiError, ConfigError)

_direct: SophosClient | None = None
_hub: AlfilHub | None = None
_proxies: dict[tuple[int, int], Any] = {}
_http_mode = False                                  # servicio HTTP: el token llega en cada petición
_request_token: contextvars.ContextVar[str | None] = contextvars.ContextVar("alfil_request_token", default=None)
_token_hubs: "OrderedDict[str, AlfilHub]" = OrderedDict()
MAX_TOKEN_HUBS = 32
TOKEN_CACHE_SECONDS = 30
_valid_tokens: dict[str, float] = {}               # hash del token -> instante de la última validación correcta


def reset_state() -> None:
    """Descarta clientes en caché (pruebas y cambios de configuración)."""
    global _direct, _hub, _http_mode
    _direct = _hub = None
    _http_mode = False
    _proxies.clear()
    _token_hubs.clear()
    _valid_tokens.clear()


def _token_key(token: str) -> str:
    return hashlib.sha256(token.encode("utf8")).hexdigest()


def get_hub() -> AlfilHub | None:
    global _hub
    token = _request_token.get()
    if token:  # servicio HTTP: un cliente de ALFIL por token (el token es el del agente que llama)
        key = _token_key(token)
        if key not in _token_hubs:
            base = AlfilSettings.base_from_env()
            if not base:
                raise ConfigError("El servicio MCP no tiene ALFIL_URL configurado.")
            _token_hubs[key] = AlfilHub(AlfilSettings(url=base.url, token=token, verify_ssl=base.verify_ssl, timeout=base.timeout))
            while len(_token_hubs) > MAX_TOKEN_HUBS:
                _, old = _token_hubs.popitem(last=False)
                asyncio.get_running_loop().create_task(old.aclose())
        _token_hubs.move_to_end(key)
        return _token_hubs[key]
    if _http_mode:
        return None
    if _hub is None:
        settings = AlfilSettings.from_env()
        if settings:
            _hub = AlfilHub(settings)
    return _hub


def get_direct() -> SophosClient | None:
    global _direct
    if _http_mode:  # un servicio compartido no debe exponer una conexión directa con credenciales propias
        return None
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
        key = (id(hub), found["id"])
        if key not in _proxies:
            _proxies[key] = hub.client_for(found["id"])
        return _proxies[key], found["name"]
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
    if hub and not _http_mode:
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
        "list_api_endpoints y api_get leen cualquier ruta GET; audit_firewall devuelve score y hallazgos de reglas; "
        "get_topology y explain_path (solo con conexiones de ALFIL) describen la red y explican la ruta de un flujo. "
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


async def load_topology(connection: str | None) -> tuple[dict[str, Any], str, Any]:
    client, label = await resolve_client(connection)
    if not hasattr(client, "topology"):
        raise SophosApiError("La topología solo está disponible con conexiones de ALFIL (ALFIL_URL + ALFIL_MCP_TOKEN): "
                             "ALFIL calcula el grafo con sus colectores de red.")
    return await client.topology(), label, client


@read_tool
async def get_topology(connection: str | None = None, format: str = "summary") -> dict[str, Any]:
    """Topología de red de configuración: zonas con sus interfaces/VLAN, rutas estáticas, VPN IPsec y advertencias
    (salto inalcanzable, subredes solapadas, interfaz con IP sin zona).

    `format`: "summary" (por defecto, legible) o "graph" (nodos y aristas completos). No incluye ruteo dinámico.
    Requiere una conexión de ALFIL.
    """
    if format not in ("summary", "graph"):
        raise SophosApiError('`format` debe ser "summary" o "graph".')
    graph, label, _ = await load_topology(connection)
    return {"connection": label, **(topo_analysis.summarize(graph) if format == "summary" else graph)}


@read_tool
async def explain_path(source_ip: str, destination_ip: str, connection: str | None = None, include_rules: bool = True) -> dict[str, Any]:
    """Explica por dónde pasa un flujo origen→destino (IPv4): red/interfaz/zona de cada extremo, ruta o VPN que usa,
    problemas (blackhole, sin ruta, salto inalcanzable) y, con `include_rules`, las reglas candidatas del par de zonas.

    Usa la configuración (no tráfico real): no evalúa NAT, SD-WAN ni ruteo dinámico. Requiere una conexión de ALFIL.
    """
    graph, label, client = await load_topology(connection)
    rules = await client.get_all("/firewall/rules/ipv4") if include_rules else None
    try:
        result = topo_analysis.explain_path(graph, source_ip, destination_ip, rules)
    except ValueError as exc:
        raise SophosApiError(f"Dirección IP no válida: {exc}") from exc
    return {"connection": label, **result}


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


async def tool_count() -> int:
    return len(await mcp.list_tools())


@mcp.custom_route("/health", ["GET"])
async def health(request: Any) -> Any:
    """Sin autenticación: ALFIL lo sondea para mostrar el estado del servicio en el dashboard."""
    from starlette.responses import JSONResponse
    return JSONResponse({"status": "ok", "version": __version__, "tools": await tool_count(), "transport": "http", "read_only": True})


async def validate_token(token: str) -> None:
    """Acepta el token si ALFIL lo reconoce (con caché corta). 401 si ALFIL lo rechaza; otros errores -> 503."""
    key = _token_key(token)
    if time.monotonic() - _valid_tokens.get(key, -1e9) < TOKEN_CACHE_SECONDS:
        return
    base = AlfilSettings.base_from_env()
    if not base:
        raise AlfilError("El servicio MCP no tiene ALFIL_URL configurado.", 503)
    hub = AlfilHub(AlfilSettings(url=base.url, token=token, verify_ssl=base.verify_ssl, timeout=15.0))
    try:
        await hub.list_connections()
    finally:
        await hub.aclose()
    _valid_tokens[key] = time.monotonic()
    if len(_valid_tokens) > 256:  # acotar la caché
        _valid_tokens.pop(next(iter(_valid_tokens)))


class BearerAuthMiddleware:
    """ASGI: exige `Authorization: Bearer <token de ALFIL>` y lo deja disponible para las herramientas de esa petición."""

    def __init__(self, app: Any, validate: Callable[[str], Awaitable[None]] = validate_token):
        self.app, self.validate = app, validate

    async def _reply(self, send: Any, status: int, message: str, www: bool = False) -> None:
        body = json.dumps({"error": "unauthorized" if status == 401 else "unavailable", "message": message}).encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        if www:
            headers.append((b"www-authenticate", b'Bearer realm="alfil-mcp"'))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["path"] == "/health":
            return await self.app(scope, receive, send)
        auth = dict(scope.get("headers") or []).get(b"authorization", b"").decode("latin-1")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return await self._reply(send, 401, "Falta el token: envíe la cabecera Authorization: Bearer <token>.", www=True)
        token = token.strip()
        try:
            await self.validate(token)
        except AlfilError as exc:
            if exc.status_code == 401:
                return await self._reply(send, 401, "Token inválido o revocado: genere uno nuevo en el dashboard de ALFIL.", www=True)
            return await self._reply(send, 503, "El servicio MCP no puede contactar con ALFIL.")
        marker = _request_token.set(token)
        try:
            await self.app(scope, receive, send)
        finally:
            _request_token.reset(marker)


def build_http_app(validate: Callable[[str], Awaitable[None]] = validate_token) -> Any:
    """App ASGI del MCP remoto (streamable HTTP sin sesión, respuestas JSON) con autenticación por token."""
    from mcp.server.transport_security import TransportSecuritySettings

    global _http_mode
    _http_mode = True
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True,
        # Detrás del proxy el Host es el del dominio público; el acceso lo protege el token Bearer.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    app.add_middleware(BearerAuthMiddleware, validate=validate)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(prog="alfil-mcp", description="Servidor MCP de ALFIL (solo lectura)")
    parser.add_argument("--transport", choices=("stdio", "http"), default=os.environ.get("MCP_TRANSPORT", "stdio"))
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8765")))
    args = parser.parse_args()
    if args.transport == "http":
        import uvicorn
        logging.basicConfig(level=logging.INFO)
        uvicorn.run(build_http_app(), host=args.host, port=args.port, log_level="info")
    else:
        mcp.run("stdio")


if __name__ == "__main__":
    main()
