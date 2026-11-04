"""Fábrica de clientes: elige el cliente XML o REST según `api_type` de la conexión."""
from __future__ import annotations

from typing import Union

from app.services.crypto import get_encryption_manager
from app.services.sophos_client import SophosFirewallClient
from app.services.sophos_rest_client import SophosRestClient

FirewallClient = Union[SophosFirewallClient, SophosRestClient]


def build_client(api_type: str, host: str, port: int, username: str | None, secret: str, verify_ssl: bool) -> FirewallClient:
    """`secret` es la contraseña (xml) o la API key (rest)."""
    if api_type == "rest":
        return SophosRestClient(host=host, port=port, api_key=secret, verify_ssl=verify_ssl)
    return SophosFirewallClient(host=host, port=port, username=username or "", password=secret, verify_ssl=verify_ssl)


def client_for_connection(obj) -> FirewallClient:
    secret = get_encryption_manager().decrypt(obj.password_encrypted)
    return build_client(getattr(obj, "api_type", "xml") or "xml", obj.host, obj.port, obj.username, secret, obj.verify_ssl)
