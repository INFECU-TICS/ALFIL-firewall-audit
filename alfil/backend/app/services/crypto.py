from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


class EncryptionManager:
    """Manages encryption/decryption of sensitive data"""

    def __init__(self, key: str):
        """Initialize with a key (can be any string)"""
        self.key = self._derive_key(key)
        self.fernet = Fernet(self.key)

    def _derive_key(self, password: str) -> bytes:
        """Derive a Fernet key from the provided password"""
        # Use a fixed salt for simplicity (in production, use a proper salt)
        salt = b'alfil_salt_value'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt(self, data: str) -> str:
        """Encrypt a string and return base64 encoded result"""
        if not data:
            return ""
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt an encrypted string"""
        if not encrypted_data:
            return ""
        try:
            return self.fernet.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return ""


# Global encryption manager instance
_encryption_manager = None


def get_encryption_manager(key: str = None) -> EncryptionManager:
    """Get or create the encryption manager singleton"""
    global _encryption_manager
    if _encryption_manager is None:
        if key is None:
            from app.config import get_settings
            settings = get_settings()
            key = settings.encryption_key
        _encryption_manager = EncryptionManager(key)
    return _encryption_manager
