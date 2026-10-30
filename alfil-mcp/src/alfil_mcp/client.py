"""Cliente REST de solo lectura para Sophos Firewall v23.

Fase 1: únicamente GET. Cualquier otro verbo se rechaza antes de salir a la red
(la spec tiene POST de "acción" como borrado masivo, move y test-connection).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources
from typing import Any

import httpx

from .config import Settings

PAGE_SIZE = 100  # máximo documentado en la spec


class SophosApiError(RuntimeError):
    pass


class ReadOnlyError(SophosApiError):
    pass


@lru_cache(maxsize=1)
def _catalog() -> list[dict[str, Any]]:
    return json.loads(resources.files("alfil_mcp.data").joinpath("get_catalog.json").read_text(encoding="utf8"))


@lru_cache(maxsize=1)
def _allowed_patterns() -> list[re.Pattern[str]]:
    # {idOrName} / {name} -> un segmento; el resto es literal.
    return [
        re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(e["path"])) + "$")
        for e in _catalog()
    ]


def search_catalog(query: str = "", limit: int = 50) -> list[dict[str, Any]]:
    terms = query.lower().split()
    hits = [
        e for e in _catalog()
        if all(t in f"{e['path']} {e['tag']} {e['summary']} {e['operationId']}".lower() for t in terms)
    ]
    return hits[:limit]


def is_known_get_path(path: str) -> bool:
    if ".." in path or "?" in path or "#" in path or not path.startswith("/"):
        return False
    return any(p.match(path) for p in _allowed_patterns())


class SophosClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self._client = httpx.AsyncClient(
            base_url=settings.base_url,
            headers={"Authorization": f"Bearer {settings.token}", "Accept": "application/json"},
            verify=settings.verify_ssl,
            timeout=settings.timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(self, method: str, path: str, params: dict[str, Any] | None = None) -> Any:
        if method.upper() != "GET":
            raise ReadOnlyError(f"Fase 1 es solo lectura: {method.upper()} {path} bloqueado.")
        if not is_known_get_path(path):
            raise SophosApiError(f"Ruta GET no existe en la spec v23: {path}")
        try:
            resp = await self._client.get(path.lstrip("/"), params=params)
        except httpx.HTTPError as exc:
            raise SophosApiError(f"Error de conexión con el firewall: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise SophosApiError(_describe_error(resp))
        try:
            return resp.json()
        except ValueError as exc:
            raise SophosApiError("Respuesta no es JSON.") from exc

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params)

    async def get_all(self, path: str, params: dict[str, Any] | None = None, max_items: int = 1000) -> list[Any]:
        """Recorre todas las páginas de un listado `{items, pages}`."""
        items: list[Any] = []
        page = 1
        while len(items) < max_items:
            data = await self.get(path, {**(params or {}), "page": page, "pageSize": PAGE_SIZE})
            batch = data.get("items", []) if isinstance(data, dict) else []
            items.extend(batch)
            if len(batch) < PAGE_SIZE:
                break
            page += 1
        return items[:max_items]


def _describe_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        detail = f"{body.get('error', '')}: {body.get('message', '')}".strip(": ")
    except ValueError:
        detail = "respuesta no JSON (ruta o recurso inexistente)" if resp.status_code == 404 else "respuesta no JSON"
    return f"HTTP {resp.status_code} - {detail}"
