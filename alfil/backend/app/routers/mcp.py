"""Integración con el servidor MCP: estado, token de acceso y proxy de solo lectura hacia los firewalls.

El MCP nunca recibe las credenciales guardadas: pide al backend que lea una ruta GET de una conexión habilitada
(`mcp_enabled`, solo REST) y el backend la ejecuta con la API key que él custodia.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.connection import ConnectionConfig
from app.models.mcp_access import McpAccess
from app.services.firewall_client import client_for_connection
from app.services.get_catalog import is_known_get_path
from app.services.sophos_rest_client import RestError, SophosRestClient

router = APIRouter(prefix="/mcp", tags=["mcp"])

ONLINE_SECONDS = 90  # el MCP envía un latido cada ~30 s mientras está en ejecución


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf8")).hexdigest()


def _access(db: Session) -> McpAccess:
    row = db.query(McpAccess).first()
    if not row:
        row = McpAccess(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def require_mcp_token(authorization: Optional[str] = Header(default=None), db: Session = Depends(get_db)) -> McpAccess:
    """Autentica al servidor MCP con el token generado en el dashboard (Bearer)."""
    scheme, _, token = (authorization or "").partition(" ")
    row = _access(db)
    if scheme.lower() != "bearer" or not token or not row.token_hash or not hmac.compare_digest(_hash(token), row.token_hash):
        raise HTTPException(status_code=401, detail="Token MCP inválido o revocado", headers={"WWW-Authenticate": "Bearer"})
    return row


# ---------------------------------------------------------------------------
# Gestión desde el dashboard
# ---------------------------------------------------------------------------

@router.get("/status")
def mcp_status(db: Session = Depends(get_db)):
    row = _access(db)
    enabled = db.query(ConnectionConfig).filter(ConnectionConfig.mcp_enabled == True, ConnectionConfig.is_active == True).count()  # noqa: E712
    seen = _aware(row.last_seen_at)
    seconds = int((_now() - seen).total_seconds()) if seen else None
    if not row.token_hash:
        state = "sin_token"
    elif seen is None:
        state = "sin_actividad"
    else:
        state = "en_linea" if seconds <= ONLINE_SECONDS else "fuera_de_linea"
    return {
        "state": state,
        "token_configured": bool(row.token_hash),
        "token_prefix": row.token_prefix,
        "token_created_at": row.token_created_at.isoformat() if row.token_created_at else None,
        "last_seen_at": seen.isoformat() if seen else None,
        "seconds_since_seen": seconds,
        "online_window_seconds": ONLINE_SECONDS,
        "info": row.info or {},
        "enabled_connections": enabled,
    }


@router.post("/token")
def mcp_generate_token(db: Session = Depends(get_db)):
    """Genera (o rota) el token del MCP. Se muestra una sola vez; en la base solo queda su hash."""
    token = "alfil_mcp_" + secrets.token_urlsafe(32)
    row = _access(db)
    row.token_hash = _hash(token)
    row.token_prefix = token[:14]
    row.token_created_at = _now()
    row.last_seen_at = None
    row.info = None
    db.commit()
    return {"token": token, "token_prefix": row.token_prefix}


@router.delete("/token", status_code=204)
def mcp_revoke_token(db: Session = Depends(get_db)):
    row = _access(db)
    row.token_hash = row.token_prefix = row.token_created_at = row.last_seen_at = row.info = None
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
def mcp_heartbeat(payload: Heartbeat, access: McpAccess = Depends(require_mcp_token), db: Session = Depends(get_db)):
    access.last_seen_at = _now()
    access.info = payload.model_dump()
    db.commit()
    return Response(status_code=204)


def _enabled_connections(db: Session) -> list[ConnectionConfig]:
    return (db.query(ConnectionConfig)
            .filter(ConnectionConfig.mcp_enabled == True, ConnectionConfig.is_active == True)  # noqa: E712
            .order_by(ConnectionConfig.name).all())


@router.get("/connections")
def mcp_list_connections(_: McpAccess = Depends(require_mcp_token), db: Session = Depends(get_db)):
    """Conexiones habilitadas para el MCP. Nunca incluye credenciales."""
    return [{"id": c.id, "name": c.name, "host": c.host, "port": c.port, "verify_ssl": c.verify_ssl}
            for c in _enabled_connections(db)]


def _resolve(ref: str, db: Session) -> ConnectionConfig:
    conns = _enabled_connections(db)
    match = next((c for c in conns if c.name == ref), None) or next((c for c in conns if str(c.id) == ref), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Conexión '{ref}' no existe o no está habilitada para el MCP")
    return match


@router.get("/connections/{ref}/get")
def mcp_proxy_get(ref: str, request: Request, path: str, _: McpAccess = Depends(require_mcp_token), db: Session = Depends(get_db)):
    """Ejecuta un GET de solo lectura sobre la REST API del firewall de la conexión indicada (nombre o id)."""
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
