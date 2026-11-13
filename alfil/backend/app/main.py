import logging
import urllib.request
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import Base, engine, SessionLocal, ensure_schema
from app.models.audit_report import AuditReport  # noqa: ensure table is registered
from app.models.mcp_access import McpToken, McpChange, McpAuditLog  # noqa: ensure table is registered
from app.models.app_setting import AppSetting  # noqa: ensure table is registered
from app.services.crypto import migrate_credentials, validate_encryption_key
from app.routers import connections, audit, mcp

Base.metadata.create_all(bind=engine)
ensure_schema()

settings = get_settings()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    debug=settings.debug,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(connections.router, prefix=settings.api_v1_prefix)
app.include_router(audit.router, prefix=settings.api_v1_prefix)
app.include_router(mcp.router, prefix=settings.api_v1_prefix)


@app.on_event("startup")
def _secure_stored_credentials():
    """Exige clave propia fuera de desarrollo y reescribe las credenciales con la sal de la instalación."""
    validate_encryption_key(settings.encryption_key, settings.debug)
    db = SessionLocal()
    try:
        migrate_credentials(db, settings.encryption_key, settings.encryption_key_old or None, settings.database_url)
    finally:
        db.close()


@app.on_event("startup")
def _mark_stale_audits():
    """Marca como 'failed' las auditorías que quedaron en 'running' por un reinicio."""
    db = SessionLocal()
    try:
        stale = db.query(AuditReport).filter(AuditReport.status == "running").all()
        for a in stale:
            a.status = "failed"
            a.error = "El servidor fue reiniciado mientras la auditoría estaba en curso"
        if stale:
            db.commit()
    finally:
        db.close()


@app.get(settings.api_v1_prefix + "/utils/public-ip")
def get_public_ip():
    """Devuelve la IP pública del servidor (para mostrarla en el formulario de conexión)."""
    try:
        with urllib.request.urlopen("https://ipinfo.io/ip", timeout=5) as r:
            ip = r.read().decode().strip()
        return {"ip": ip}
    except Exception:
        return {"ip": None}


@app.get("/health")
def health_check():
    return {"status": "ok", "app": settings.app_name}


@app.get(settings.api_v1_prefix)
def api_root():
    return {"message": "Alfil API v1"}
