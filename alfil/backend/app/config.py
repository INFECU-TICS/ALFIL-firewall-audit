from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application configuration settings"""
    app_name: str = "ALFIL – Automated Layered Firewall Inspection & Logic"
    debug: bool = True
    database_url: str = "sqlite:///./alfil.db"
    api_v1_prefix: str = "/api/v1"
    cors_origins: list = ["http://localhost:5173", "http://localhost:3000"]

    # Encryption key for storing passwords (should be set via env var in production)
    encryption_key: str = "your-encryption-key-here-change-in-production"
    # Clave anterior: solo para rotar ENCRYPTION_KEY (se usa una vez al arrancar para reescribir las credenciales)
    encryption_key_old: str = ""

    # API XML de Sophos: algunos equipos tardan decenas de segundos por entidad (p. ej. FirewallRule ~50 s en v23).
    sophos_request_timeout: int = 90   # segundos por consulta
    sophos_collect_workers: int = 4    # consultas simultáneas durante la auditoría

    # Servicio MCP remoto (opcional): el dashboard sondea su /health para mostrar el estado
    mcp_service_url: str = ""
    # Fase 2 del MCP (escritura con confirmación): apagada por defecto. Además cada token (can_write) y cada conexión
    # (mcp_write_enabled) deben permitirla explícitamente.
    mcp_allow_write: bool = False
    mcp_change_ttl_minutes: int = 15

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
