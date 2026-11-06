"""Cifrado de credenciales guardadas (contraseñas XML / API keys REST).

Formatos de token:
- ``v2:<fernet>``: clave derivada con PBKDF2 y una sal aleatoria propia de cada instalación (tabla ``app_settings``).
- sin prefijo (legado): sal fija pública ``alfil_salt_value``. Se sigue pudiendo descifrar y ``migrate_credentials``
  lo reescribe como v2 al arrancar.
"""
import base64
import logging
import os
import secrets
import shutil
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

V2_PREFIX = "v2:"
LEGACY_SALT = b"alfil_salt_value"
SALT_SETTING = "encryption_salt"
MIN_KEY_LENGTH = 32
_INSECURE_PREFIXES = ("your-encryption-key", "change-me")


def is_insecure_key(key: str | None) -> bool:
    """Clave ausente, de ejemplo (pública en el código o en .env.example) o demasiado corta."""
    return not key or key.startswith(_INSECURE_PREFIXES) or len(key) < MIN_KEY_LENGTH


def validate_encryption_key(key: str | None, debug: bool) -> None:
    """Fuera de desarrollo (DEBUG=false) una clave insegura impide el arranque; en desarrollo solo avisa."""
    if not is_insecure_key(key):
        return
    msg = (
        f"ENCRYPTION_KEY ausente, de ejemplo o con menos de {MIN_KEY_LENGTH} caracteres: las credenciales guardadas "
        "no estarían protegidas. Genere una con: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
    if debug:
        logger.critical(msg + " (modo DEBUG: se permite solo para desarrollo)")
        return
    raise RuntimeError(msg)


def _fernet(secret: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(secret.encode())))


class EncryptionManager:
    """Cifra con v2 (sal propia) y descifra v2 y el formato legado."""

    def __init__(self, key: str, salt: bytes):
        self._v2 = _fernet(key, salt)
        self._legacy = _fernet(key, LEGACY_SALT)

    def encrypt(self, data: str) -> str:
        if not data:
            return ""
        return V2_PREFIX + self._v2.encrypt(data.encode()).decode()

    def decrypt_strict(self, token: str) -> str:
        """Descifra o lanza ``InvalidToken``."""
        if token.startswith(V2_PREFIX):
            return self._v2.decrypt(token[len(V2_PREFIX):].encode()).decode()
        return self._legacy.decrypt(token.encode()).decode()

    def decrypt(self, encrypted_data: str) -> str:
        if not encrypted_data:
            return ""
        try:
            return self.decrypt_strict(encrypted_data)
        except Exception:
            return ""

    @staticmethod
    def is_current_format(token: str) -> bool:
        return token.startswith(V2_PREFIX)


def get_or_create_salt(db) -> bytes:
    """Sal de la instalación: se genera una vez y vive en la BD (viaja con sus respaldos)."""
    from app.models.app_setting import AppSetting
    row = db.get(AppSetting, SALT_SETTING)
    if row is None:
        row = AppSetting(key=SALT_SETTING, value=base64.urlsafe_b64encode(secrets.token_bytes(16)).decode())
        db.add(row)
        db.commit()
    return base64.urlsafe_b64decode(row.value.encode())


_encryption_manager: EncryptionManager | None = None


def reset_encryption_manager() -> None:
    global _encryption_manager
    _encryption_manager = None


def get_encryption_manager(key: str | None = None) -> EncryptionManager:
    """Singleton; la primera vez lee la clave de la configuración y la sal de la BD."""
    global _encryption_manager
    if _encryption_manager is None:
        from app.config import get_settings
        from app.database import SessionLocal
        settings = get_settings()
        db = SessionLocal()
        try:
            _encryption_manager = EncryptionManager(key or settings.encryption_key, get_or_create_salt(db))
        finally:
            db.close()
    return _encryption_manager


def _backup_sqlite(database_url: str) -> str | None:
    """Copia previa del archivo SQLite antes de reescribir credenciales."""
    if not database_url.startswith("sqlite:///"):
        return None
    path = database_url[len("sqlite:///"):]
    if not path or path == ":memory:" or not os.path.isfile(path):
        return None
    dest = f"{path}.bak-cifrado-{datetime.now():%Y%m%d%H%M%S}"
    shutil.copy2(path, dest)
    return dest


def migrate_credentials(db, key: str, old_key: str | None = None, database_url: str = "") -> dict:
    """Reescribe como v2 (sal propia) toda credencial guardada en formato legado o cifrada con ``old_key``.

    Idempotente. Hace copia de la BD antes de modificar algo. Lo que no se pueda descifrar con ninguna clave
    se deja intacto y se informa (la conexión pedirá la credencial de nuevo).
    """
    from app.models.connection import ConnectionConfig
    salt = get_or_create_salt(db)
    current = EncryptionManager(key, salt)
    olds = [EncryptionManager(old_key, salt)] if old_key and old_key != key else []

    pending = []
    for conn in db.query(ConnectionConfig).all():
        token = conn.password_encrypted or ""
        if not token:
            continue
        try:
            current.decrypt_strict(token)
            if current.is_current_format(token):
                continue  # ya es v2 con la clave actual
            plain = current.decrypt_strict(token)
        except (InvalidToken, ValueError):
            plain = None
            for m in olds:
                try:
                    plain = m.decrypt_strict(token)
                    break
                except (InvalidToken, ValueError):
                    continue
            if plain is None:
                pending.append(conn)
                continue
        pending.append((conn, plain))

    todo = [p for p in pending if isinstance(p, tuple)]
    failed = [p for p in pending if not isinstance(p, tuple)]
    result = {"migradas": 0, "sin_descifrar": [c.name for c in failed], "respaldo": None}
    if todo:
        result["respaldo"] = _backup_sqlite(database_url)
        for conn, plain in todo:
            conn.password_encrypted = current.encrypt(plain)
        db.commit()
        result["migradas"] = len(todo)
        logger.warning("Credenciales migradas al cifrado con sal propia: %d (respaldo: %s)", len(todo), result["respaldo"])
    if failed:
        logger.error("No se pudieron descifrar las credenciales de %d conexión(es): %s. Defina ENCRYPTION_KEY_OLD con la "
                     "clave anterior o vuelva a ingresar la credencial.", len(failed), [c.name for c in failed])
    return result
