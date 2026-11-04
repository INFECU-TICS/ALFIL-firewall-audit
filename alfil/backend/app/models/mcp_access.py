from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.types import JSON

from app.database import Base


class McpAccess(Base):
    """Acceso del servidor MCP a ALFIL (una sola fila): token (solo su hash) y último latido."""
    __tablename__ = "mcp_access"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), nullable=True)      # SHA-256 del token; el token solo se muestra al generarlo
    token_prefix = Column(String(16), nullable=True)    # para reconocerlo en pantalla
    token_created_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)   # último latido del MCP local (stdio)
    last_used_at = Column(DateTime(timezone=True), nullable=True)   # última lectura de un agente a través del proxy
    info = Column(JSON, nullable=True)                  # versión, herramientas, solo lectura, transporte
