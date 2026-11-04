"""Configuración por variables de entorno. El token nunca se loguea ni se imprime."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_PATH = "/api/firewall-config/v1"


class ConfigError(RuntimeError):
    pass


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


@dataclass(frozen=True)
class Settings:
    host: str
    port: int = 4444
    token: str = field(default="", repr=False)  # repr=False: no filtrar en logs/tracebacks
    verify_ssl: bool = True
    timeout: float = 20.0

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}{BASE_PATH}"

    @classmethod
    def try_from_env(cls) -> "Settings | None":
        """Modo directo (SFOS_HOST + token). Devuelve None si no se configuró SFOS_HOST; si falta solo el token, falla."""
        file_values = _read_env_file(Path(os.environ["SFOS_ENV_FILE"])) if os.environ.get("SFOS_ENV_FILE") else {}
        if not (os.environ.get("SFOS_HOST") or file_values.get("SFOS_HOST")):
            return None
        return cls.from_env()

    @classmethod
    def from_env(cls) -> "Settings":
        # SFOS_ENV_FILE permite apuntar a un .env (p. ej. el del repo ALFIL, que usa API_KEY).
        file_values = _read_env_file(Path(os.environ["SFOS_ENV_FILE"])) if os.environ.get("SFOS_ENV_FILE") else {}

        def get(*names: str) -> str | None:
            for name in names:
                if os.environ.get(name):
                    return os.environ[name]
            for name in names:
                if file_values.get(name):
                    return file_values[name]
            return None

        host = get("SFOS_HOST")
        token = get("SFOS_TOKEN", "API_KEY")
        if not host:
            raise ConfigError("Falta SFOS_HOST (IP o hostname del firewall).")
        if not token:
            raise ConfigError("Falta SFOS_TOKEN (API key de Administration > API access).")
        return cls(
            host=host,
            port=int(get("SFOS_PORT") or 4444),
            token=token,
            verify_ssl=(get("SFOS_VERIFY_SSL") or "true").lower() not in ("0", "false", "no"),
        )


@dataclass(frozen=True)
class AlfilSettings:
    """Integración con ALFIL: el MCP usa las conexiones habilitadas en el dashboard; ALFIL custodia las credenciales."""
    url: str
    token: str = field(default="", repr=False)
    verify_ssl: bool = True
    timeout: float = 120.0  # ALFIL consulta al firewall en nombre del MCP; los equipos lentos tardan

    @property
    def api_base(self) -> str:
        return f"{self.url.rstrip('/')}/api/v1/mcp"

    @classmethod
    def base_from_env(cls) -> "AlfilSettings | None":
        """URL de ALFIL sin token (modo HTTP: cada petición trae su propio token)."""
        file_values = _read_env_file(Path(os.environ["SFOS_ENV_FILE"])) if os.environ.get("SFOS_ENV_FILE") else {}
        url = os.environ.get("ALFIL_URL") or file_values.get("ALFIL_URL")
        if not url:
            return None
        verify = (os.environ.get("ALFIL_VERIFY_SSL") or file_values.get("ALFIL_VERIFY_SSL") or "true").lower() not in ("0", "false", "no")
        return cls(url=url, token="", verify_ssl=verify)

    @classmethod
    def from_env(cls) -> "AlfilSettings | None":
        file_values = _read_env_file(Path(os.environ["SFOS_ENV_FILE"])) if os.environ.get("SFOS_ENV_FILE") else {}

        def get(name: str) -> str | None:
            return os.environ.get(name) or file_values.get(name)

        url, token = get("ALFIL_URL"), get("ALFIL_MCP_TOKEN")
        if not url and not token:
            return None
        if not url or not token:
            raise ConfigError("La integración con ALFIL requiere ALFIL_URL y ALFIL_MCP_TOKEN (token generado en el dashboard).")
        return cls(url=url, token=token, verify_ssl=(get("ALFIL_VERIFY_SSL") or "true").lower() not in ("0", "false", "no"))
