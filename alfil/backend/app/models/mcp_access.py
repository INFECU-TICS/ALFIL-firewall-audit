from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.types import JSON

from app.database import Base


class McpToken(Base):
    """Token de acceso de un agente al MCP: uno por agente, con nombre y caducidad. Solo se guarda su SHA-256."""
    __tablename__ = "mcp_tokens"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    token_prefix = Column(String(16), nullable=False)   # para reconocerlo en pantalla
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)      # None = no caduca
    last_seen_at = Column(DateTime(timezone=True), nullable=True)    # último latido del MCP local (stdio)
    last_used_at = Column(DateTime(timezone=True), nullable=True)    # última lectura de un agente a través del proxy
    info = Column(JSON, nullable=True)                  # versión, herramientas, solo lectura, transporte
    can_write = Column(Boolean, nullable=False, default=False, server_default="0")  # puede proponer/aplicar cambios (fase 2)


class McpChange(Base):
    """Cambio propuesto por un agente: se revisa (diff) y solo se aplica con una confirmación explícita y a tiempo."""
    __tablename__ = "mcp_changes"

    id = Column(String(36), primary_key=True)
    token_id = Column(Integer, nullable=False, index=True)
    token_name = Column(String(80), nullable=False)
    connection_id = Column(Integer, nullable=False)
    connection_name = Column(String(100), nullable=False)
    action = Column(String(40), nullable=False)
    summary = Column(Text, nullable=False)
    plan = Column(JSON, nullable=False)
    status = Column(String(20), nullable=False, default="proposed")  # proposed | applied | failed | unknown | expired
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    applied_at = Column(DateTime(timezone=True), nullable=True)
    result = Column(JSON, nullable=True)


class McpAuditLog(Base):
    """Registro de auditoría (solo se agrega): quién propuso/aplicó qué, con la carga enviada y la copia previa."""
    __tablename__ = "mcp_audit_log"

    id = Column(Integer, primary_key=True)
    at = Column(DateTime(timezone=True), nullable=False)
    token_name = Column(String(80), nullable=False)
    connection_name = Column(String(100), nullable=False)
    event = Column(String(20), nullable=False)  # proposed | applied | failed | unknown | rejected
    change_id = Column(String(36), nullable=True)
    action = Column(String(40), nullable=True)
    summary = Column(Text, nullable=True)
    detail = Column(JSON, nullable=True)
