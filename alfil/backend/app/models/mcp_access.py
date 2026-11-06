from sqlalchemy import Column, DateTime, Integer, String
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
