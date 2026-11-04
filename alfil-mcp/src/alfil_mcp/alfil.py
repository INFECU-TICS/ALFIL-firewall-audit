"""Integración con ALFIL: conexiones habilitadas en el dashboard, accedidas mediante el proxy de solo lectura del backend.

El MCP nunca recibe las credenciales del firewall: pide a ALFIL "lee esta ruta GET de la conexión X" y ALFIL la ejecuta.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from .client import SophosApiError, get_all_pages, is_known_get_path
from .config import AlfilSettings

log = logging.getLogger(__name__)
HEARTBEAT_SECONDS = 30


def _describe(resp: httpx.Response) -> str:
    try:
        detail = resp.json().get("detail", "")
    except ValueError:
        detail = ""
    if resp.status_code == 401:
        return "ALFIL rechazó el token del MCP (revocado o inválido): genere uno nuevo en el dashboard."
    return f"ALFIL respondió HTTP {resp.status_code}" + (f": {detail}" if detail else "")


class AlfilHub:
    """Cliente del backend de ALFIL: conexiones disponibles, latido y proxy GET."""

    def __init__(self, settings: AlfilSettings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self._http = httpx.AsyncClient(
            base_url=settings.api_base + "/",
            headers={"Authorization": f"Bearer {settings.token}", "Accept": "application/json"},
            verify=settings.verify_ssl, timeout=settings.timeout, transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise SophosApiError(f"No se pudo contactar con ALFIL ({type(exc).__name__}): revise ALFIL_URL.") from exc
        if resp.status_code >= 400:
            raise SophosApiError(_describe(resp))
        return resp

    async def list_connections(self) -> list[dict[str, Any]]:
        return (await self._request("GET", "connections")).json()

    async def find(self, ref: str) -> dict[str, Any]:
        """Busca una conexión habilitada por nombre o id."""
        conns = await self.list_connections()
        match = next((c for c in conns if c["name"] == ref), None) or next((c for c in conns if str(c["id"]) == str(ref)), None)
        if not match:
            names = ", ".join(c["name"] for c in conns) or "ninguna"
            raise SophosApiError(f"La conexión '{ref}' no está habilitada para el MCP. Disponibles: {names}.")
        return match

    async def heartbeat(self, payload: dict[str, Any]) -> None:
        await self._request("POST", "heartbeat", json=payload)

    def client_for(self, connection_id: int) -> "AlfilProxyClient":
        return AlfilProxyClient(self, connection_id)


class AlfilProxyClient:
    """Misma interfaz que SophosClient (get / get_all), pero a través del proxy de ALFIL."""

    def __init__(self, hub: AlfilHub, connection_id: int):
        self._hub, self._id = hub, connection_id

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if not is_known_get_path(path):  # defensa en profundidad: ALFIL también lo valida
            raise SophosApiError(f"Ruta GET no existe en la spec v23: {path}")
        resp = await self._hub._request("GET", f"connections/{self._id}/get", params={**(params or {}), "path": path})
        return resp.json()

    async def get_all(self, path: str, params: dict[str, Any] | None = None, max_items: int = 1000) -> list[Any]:
        return await get_all_pages(self.get, path, params, max_items)

    async def aclose(self) -> None:  # el hub es compartido
        return None


async def heartbeat_loop(hub: AlfilHub, payload: dict[str, Any]) -> None:
    """Avisa a ALFIL cada 30 s mientras el MCP está en ejecución. Un fallo no detiene el servidor."""
    while True:
        try:
            await hub.heartbeat(payload)
        except SophosApiError as exc:
            log.warning("Latido a ALFIL fallido: %s", exc)
        await asyncio.sleep(HEARTBEAT_SECONDS)
