from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.connection import ConnectionConfig
from app.schemas.connection import (
    ConnectionConfigCreate,
    ConnectionConfigUpdate,
    ConnectionConfigResponse,
    ConnectionTestRequest,
    ConnectionTestResponse,
)
from app.services.crypto import get_encryption_manager
from app.services.sophos_client import SophosFirewallClient

router = APIRouter(prefix="/connections", tags=["connections"])


def _encrypt(password: str) -> str:
    return get_encryption_manager().encrypt(password)


def _decrypt(encrypted: str) -> str:
    return get_encryption_manager().decrypt(encrypted)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@router.get("", response_model=list[ConnectionConfigResponse])
def list_connections(db: Session = Depends(get_db)):
    return db.query(ConnectionConfig).filter(ConnectionConfig.is_active == True).all()


@router.post("", response_model=ConnectionConfigResponse, status_code=status.HTTP_201_CREATED)
def create_connection(payload: ConnectionConfigCreate, db: Session = Depends(get_db)):
    existing = db.query(ConnectionConfig).filter(ConnectionConfig.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Ya existe una conexión con el nombre '{payload.name}'")

    obj = ConnectionConfig(
        name=payload.name,
        host=payload.host,
        port=payload.port,
        username=payload.username,
        password_encrypted=_encrypt(payload.password),
        verify_ssl=payload.verify_ssl,
        is_active=payload.is_active,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.get("/{connection_id}", response_model=ConnectionConfigResponse)
def get_connection(connection_id: int, db: Session = Depends(get_db)):
    obj = db.query(ConnectionConfig).filter(ConnectionConfig.id == connection_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    return obj


@router.put("/{connection_id}", response_model=ConnectionConfigResponse)
def update_connection(connection_id: int, payload: ConnectionConfigUpdate, db: Session = Depends(get_db)):
    obj = db.query(ConnectionConfig).filter(ConnectionConfig.id == connection_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    update_data = payload.model_dump(exclude_unset=True)
    if "password" in update_data:
        obj.password_encrypted = _encrypt(update_data.pop("password"))

    for field, value in update_data.items():
        setattr(obj, field, value)

    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(connection_id: int, db: Session = Depends(get_db)):
    obj = db.query(ConnectionConfig).filter(ConnectionConfig.id == connection_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    db.delete(obj)
    db.commit()


# ---------------------------------------------------------------------------
# Test de conectividad
# ---------------------------------------------------------------------------

@router.post("/test", response_model=ConnectionTestResponse)
def test_new_connection(payload: ConnectionTestRequest):
    """Prueba una conexión sin guardarla en la base de datos."""
    client = SophosFirewallClient(
        host=payload.host,
        port=payload.port,
        username=payload.username,
        password=payload.password,
        verify_ssl=payload.verify_ssl,
    )
    result = client.test_connection()
    return ConnectionTestResponse(
        success=result["success"],
        message=result.get("message", ""),
        details={k: v for k, v in result.items() if k not in ("success", "message")},
    )


@router.post("/{connection_id}/test", response_model=ConnectionTestResponse)
def test_saved_connection(connection_id: int, db: Session = Depends(get_db)):
    """Prueba la conectividad de una conexión ya guardada."""
    obj = db.query(ConnectionConfig).filter(ConnectionConfig.id == connection_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")

    client = SophosFirewallClient(
        host=obj.host,
        port=obj.port,
        username=obj.username,
        password=_decrypt(obj.password_encrypted),
        verify_ssl=obj.verify_ssl,
    )
    result = client.test_connection()
    return ConnectionTestResponse(
        success=result["success"],
        message=result.get("message", ""),
        details={k: v for k, v in result.items() if k not in ("success", "message")},
    )
