"""Integración con el servidor MCP: estado, token de acceso y proxy de solo lectura hacia los firewalls.

El MCP nunca recibe las credenciales guardadas: pide al backend que lea una ruta GET de una conexión habilitada
(`mcp_enabled`, solo REST) y el backend la ejecuta con la API key que él custodia.
"""
from __future__ import annotations

import hashlib
import hmac
import requests
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.connection import ConnectionConfig
from app.models.mcp_access import McpToken
from app.services.firewall_client import client_for_connection
from app.services.get_catalog import is_known_get_path
from app.services.sophos_rest_client import RestError, SophosRestClient
from app.services.topology import build_topology

router = APIRouter(prefix="/mcp", tags=["mcp"])

ONLINE_SECONDS = 90  # el MCP envía un latido cada ~30 s mientras está en ejecución


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf8")).hexdigest()


DEFAULT_TOKEN_DAYS = 7


def _is_expired(t: McpToken) -> bool:
    exp = _aware(t.expires_at)
    return exp is not None and exp <= _now()


def _active_tokens(db: Session) -> list[McpToken]:
    return [t for t in db.query(McpToken).order_by(McpToken.created_at).all() if not _is_expired(t)]


def require_mcp_token(authorization: Optional[str] = Header(default=None), db: Session = Depends(get_db)) -> McpToken:
    """Autentica a un agente (o al MCP) con uno de los tokens generados en el dashboard (Bearer)."""
    scheme, _, token = (authorization or "").partition(" ")
    row = db.query(McpToken).filter(McpToken.token_hash == _hash(token)).first() if scheme.lower() == "bearer" and token else None
    if row is None:
        raise HTTPException(status_code=401, detail="Token MCP inválido o revocado", headers={"WWW-Authenticate": "Bearer"})
    if _is_expired(row):
        raise HTTPException(status_code=401, detail="Token MCP caducado", headers={"WWW-Authenticate": "Bearer"})
    return row


def _touch_used(access: McpToken, db: Session) -> None:
    """Registra la última lectura de un agente (como mucho cada 10 s para no escribir en cada petición)."""
    last = _aware(access.last_used_at)
    if last is None or (_now() - last).total_seconds() > 10:
        access.last_used_at = _now()
        db.commit()


def _probe_remote() -> dict:
    """Estado del servicio MCP remoto (contenedor amcp) mediante su /health."""
    url = get_settings().mcp_service_url
    if not url:
        return {"configured": False}
    try:
        resp = requests.get(url.rstrip("/") + "/health", timeout=2)
        resp.raise_for_status()
        data = resp.json()
        return {"configured": True, "reachable": True, "version": data.get("version"), "tools": data.get("tools"),
                "transport": data.get("transport")}
    except (requests.RequestException, ValueError) as exc:
        return {"configured": True, "reachable": False, "error": type(exc).__name__}


# ---------------------------------------------------------------------------
# Gestión desde el dashboard
# ---------------------------------------------------------------------------

def _token_view(t: McpToken) -> dict:
    seen, used, exp = _aware(t.last_seen_at), _aware(t.last_used_at), _aware(t.expires_at)
    return {
        "id": t.id, "name": t.name, "token_prefix": t.token_prefix,
        "created_at": _aware(t.created_at).isoformat(),
        "expires_at": exp.isoformat() if exp else None,
        "expired": _is_expired(t),
        "last_seen_at": seen.isoformat() if seen else None,
        "last_used_at": used.isoformat() if used else None,
    }


@router.get("/status")
def mcp_status(db: Session = Depends(get_db)):
    all_tokens = db.query(McpToken).order_by(McpToken.created_at).all()
    active = [t for t in all_tokens if not _is_expired(t)]
    enabled = db.query(ConnectionConfig).filter(ConnectionConfig.mcp_enabled == True, ConnectionConfig.is_active == True).count()  # noqa: E712
    seen_list = [(_aware(t.last_seen_at), t) for t in active if t.last_seen_at]
    last_seen, seen_token = max(seen_list, key=lambda x: x[0]) if seen_list else (None, None)
    seconds = int((_now() - last_seen).total_seconds()) if last_seen else None
    if not active:
        state = "sin_token"
    elif last_seen is None:
        state = "sin_actividad"
    else:
        state = "en_linea" if seconds <= ONLINE_SECONDS else "fuera_de_linea"
    used_list = [_aware(t.last_used_at) for t in active if t.last_used_at]
    return {
        "state": state,
        "token_configured": bool(active),
        "tokens": [_token_view(t) for t in all_tokens],
        "default_expires_days": DEFAULT_TOKEN_DAYS,
        "last_seen_at": last_seen.isoformat() if last_seen else None,
        "seconds_since_seen": seconds,
        "online_window_seconds": ONLINE_SECONDS,
        "info": (seen_token.info if seen_token else None) or {},
        "enabled_connections": enabled,
        "remote": _probe_remote(),
        "last_used_at": max(used_list).isoformat() if used_list else None,
    }


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    expires_days: Optional[int] = Field(default=DEFAULT_TOKEN_DAYS, ge=1, le=365)  # None = sin caducidad


@router.post("/tokens", status_code=201)
def mcp_create_token(payload: TokenCreate, db: Session = Depends(get_db)):
    """Crea el token de un agente. Se muestra una sola vez; en la base solo queda su hash."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="El nombre no puede estar vacío")
    if db.query(McpToken).filter(McpToken.name == name).first():
        raise HTTPException(status_code=409, detail=f"Ya existe un token llamado '{name}'")
    token = "alfil_mcp_" + secrets.token_urlsafe(32)
    now = _now()
    row = McpToken(name=name, token_hash=_hash(token), token_prefix=token[:14], created_at=now,
                   expires_at=now + timedelta(days=payload.expires_days) if payload.expires_days else None)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"token": token, **_token_view(row)}


@router.delete("/tokens/{token_id}", status_code=204)
def mcp_revoke_token(token_id: int, db: Session = Depends(get_db)):
    row = db.get(McpToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="Token no encontrado")
    db.delete(row)
    db.commit()


# ---------------------------------------------------------------------------
# Para el servidor MCP (Bearer)
# ---------------------------------------------------------------------------

class Heartbeat(BaseModel):
    version: str = Field(default="", max_length=40)
    tools: int = Field(default=0, ge=0, le=1000)
    read_only: bool = True
    transport: str = Field(default="stdio", max_length=20)


@router.post("/heartbeat", status_code=204)
def mcp_heartbeat(payload: Heartbeat, access: McpToken = Depends(require_mcp_token), db: Session = Depends(get_db)):
    access.last_seen_at = _now()
    access.info = payload.model_dump()
    db.commit()
    return Response(status_code=204)


def _enabled_connections(db: Session) -> list[ConnectionConfig]:
    return (db.query(ConnectionConfig)
            .filter(ConnectionConfig.mcp_enabled == True, ConnectionConfig.is_active == True)  # noqa: E712
            .order_by(ConnectionConfig.name).all())


@router.get("/connections")
def mcp_list_connections(access: McpToken = Depends(require_mcp_token), db: Session = Depends(get_db)):
    """Conexiones habilitadas para el MCP. Nunca incluye credenciales."""
    _touch_used(access, db)
    return [{"id": c.id, "name": c.name, "host": c.host, "port": c.port, "verify_ssl": c.verify_ssl}
            for c in _enabled_connections(db)]


def _resolve(ref: str, db: Session) -> ConnectionConfig:
    conns = _enabled_connections(db)
    match = next((c for c in conns if c.name == ref), None) or next((c for c in conns if str(c.id) == ref), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Conexión '{ref}' no existe o no está habilitada para el MCP")
    return match


@router.get("/connections/{ref}/get")
def mcp_proxy_get(ref: str, request: Request, path: str, access: McpToken = Depends(require_mcp_token), db: Session = Depends(get_db)):
    """Ejecuta un GET de solo lectura sobre la REST API del firewall de la conexión indicada (nombre o id)."""
    _touch_used(access, db)
    conn = _resolve(ref, db)
    if not is_known_get_path(path):
        raise HTTPException(status_code=400, detail=f"Ruta GET no existe en la spec v23: {path}")
    client = client_for_connection(conn)
    if not isinstance(client, SophosRestClient):  # defensa: mcp_enabled solo se permite en REST
        raise HTTPException(status_code=403, detail="La conexión no usa la API REST")
    params: dict[str, Any] = {k: v for k, v in request.query_params.items() if k != "path"}
    try:
        data = client._get(path, params or None)
    except RestError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return JSONResponse(content=data)


@router.get("/connections/{ref}/topology")
def mcp_topology(ref: str, access: McpToken = Depends(require_mcp_token), db: Session = Depends(get_db)):
    """Grafo de topología calculado al momento con la configuración actual del firewall (solo lectura)."""
    _touch_used(access, db)
    conn = _resolve(ref, db)
    client = client_for_connection(conn)
    if not isinstance(client, SophosRestClient):
        raise HTTPException(status_code=403, detail="La conexión no usa la API REST")
    raw = client.collect_topology_data()
    if not any((raw.get(k) or {}).get("success") for k in ("zones", "interfaces")):
        err = (raw.get("zones") or {}).get("error") or (raw.get("interfaces") or {}).get("error") or "sin datos"
        raise HTTPException(status_code=502, detail=f"No se pudo leer la configuración de red del firewall: {err}")
    return build_topology(raw, {"name": conn.name, "api_type": "rest"})
