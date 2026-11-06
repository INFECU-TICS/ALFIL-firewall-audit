"""Cifrado de credenciales: sal por instalación, rechazo de clave débil y migración del formato legado."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.connection import ConnectionConfig
from app.services import crypto
from app.services.crypto import (
    EncryptionManager, LEGACY_SALT, V2_PREFIX, _fernet, get_or_create_salt, is_insecure_key,
    migrate_credentials, validate_encryption_key,
)

KEY = "k" * 40
OLD = "o" * 40


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def legacy_token(key, secret):
    return _fernet(key, LEGACY_SALT).encrypt(secret.encode()).decode()


def add_conn(db, name, token):
    db.add(ConnectionConfig(name=name, host="fw.test", port=4444, username="admin", password_encrypted=token,
                            verify_ssl=False, api_type="xml"))
    db.commit()


def test_clave_insegura():
    assert is_insecure_key("")
    assert is_insecure_key(None)
    assert is_insecure_key("your-encryption-key-here-change-in-production")
    assert is_insecure_key("change-me-generate-a-real-secret-0123456789")
    assert is_insecure_key("corta")
    assert not is_insecure_key(KEY)


def test_clave_debil_rechaza_arranque_fuera_de_debug():
    with pytest.raises(RuntimeError):
        validate_encryption_key("corta", debug=False)
    validate_encryption_key("corta", debug=True)   # desarrollo: solo avisa
    validate_encryption_key(KEY, debug=False)


def test_sal_propia_y_estable(db):
    s1 = get_or_create_salt(db)
    assert len(s1) == 16 and s1 != LEGACY_SALT
    assert get_or_create_salt(db) == s1


def test_cifrado_v2_depende_de_la_sal():
    m1 = EncryptionManager(KEY, b"a" * 16)
    m2 = EncryptionManager(KEY, b"b" * 16)
    token = m1.encrypt("secreto")
    assert token.startswith(V2_PREFIX) and "secreto" not in token
    assert m1.decrypt(token) == "secreto"
    assert m2.decrypt(token) == ""      # otra instalación (otra sal) no lo descifra


def test_migra_legado_a_v2_y_es_idempotente(db):
    add_conn(db, "a", legacy_token(KEY, "pass-a"))
    add_conn(db, "b", "")
    r = migrate_credentials(db, KEY)
    assert r["migradas"] == 1 and r["sin_descifrar"] == []
    m = EncryptionManager(KEY, get_or_create_salt(db))
    a = db.query(ConnectionConfig).filter_by(name="a").one()
    assert a.password_encrypted.startswith(V2_PREFIX)
    assert m.decrypt(a.password_encrypted) == "pass-a"
    assert migrate_credentials(db, KEY)["migradas"] == 0


def test_rotacion_con_clave_anterior(db):
    add_conn(db, "a", legacy_token(OLD, "pass-a"))
    sin = migrate_credentials(db, KEY)
    assert sin["migradas"] == 0 and sin["sin_descifrar"] == ["a"]
    con = migrate_credentials(db, KEY, old_key=OLD)
    assert con["migradas"] == 1
    m = EncryptionManager(KEY, get_or_create_salt(db))
    assert m.decrypt(db.query(ConnectionConfig).one().password_encrypted) == "pass-a"


def test_rotacion_de_v2_con_clave_anterior(db):
    salt = get_or_create_salt(db)
    add_conn(db, "a", EncryptionManager(OLD, salt).encrypt("pass-a"))
    assert migrate_credentials(db, KEY, old_key=OLD)["migradas"] == 1
    assert EncryptionManager(KEY, salt).decrypt(db.query(ConnectionConfig).one().password_encrypted) == "pass-a"


def test_respaldo_del_sqlite_antes_de_migrar(tmp_path, db):
    f = tmp_path / "alfil.db"
    f.write_bytes(b"x")
    add_conn(db, "a", legacy_token(KEY, "pass-a"))
    r = migrate_credentials(db, KEY, database_url=f"sqlite:///{f}")
    assert r["respaldo"] and (tmp_path / r["respaldo"].split("/")[-1]).exists()
