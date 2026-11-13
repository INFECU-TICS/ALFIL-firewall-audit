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


class AlfilError(SophosApiError):
    """Error devuelto por ALFIL; `status_code` permite distinguir token inválido (401) de caída (5xx)."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


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
            raise AlfilError(f"No se pudo contactar con ALFIL ({type(exc).__name__}): revise ALFIL_URL.") from exc
        if resp.status_code >= 400:
            raise AlfilError(_describe(resp), resp.status_code)
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

    async def topology(self, connection_id: int) -> dict[str, Any]:
        """Grafo de topología calculado por ALFIL con la configuración actual del firewall."""
        return (await self._request("GET", f"connections/{connection_id}/topology")).json()

    async def propose_change(self, connection_id: int, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Fase 2: ALFIL valida el cambio y devuelve el diff; no toca el firewall (lo hace `apply_change`)."""
        return (await self._request("POST", f"connections/{connection_id}/changes", json={"action": action, "params": params}, timeout=120)).json()

    async def apply_change(self, change_id: str, confirm: bool) -> dict[str, Any]:
        # El equipo puede tardar decenas de segundos por escritura (~20 s en el de laboratorio)
        return (await self._request("POST", f"changes/{change_id}/apply", json={"confirm": confirm}, timeout=240)).json()

    async def list_changes(self, limit: int) -> list[dict[str, Any]]:
        return (await self._request("GET", "changes", params={"limit": limit})).json()

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

    async def topology(self) -> dict[str, Any]:
        return await self._hub.topology(self._id)

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
