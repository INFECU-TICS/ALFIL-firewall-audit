import logging
import urllib.request
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import Base, engine, SessionLocal, ensure_schema
from app.models.audit_report import AuditReport  # noqa: ensure table is registered
from app.routers import connections, audit

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


@app.on_event("startup")
def _warn_insecure_encryption_key():
    """La clave por defecto es pública (está en el código): las credenciales guardadas serían descifrables."""
    key = settings.encryption_key
    if key.startswith("your-encryption-key") or len(key) < 32:
        logger.critical(
            "ENCRYPTION_KEY ausente, de ejemplo o demasiado corta: las credenciales guardadas NO están protegidas. "
            "Defina una clave propia (python -c \"import secrets; print(secrets.token_hex(32))\") antes de guardar conexiones."
        )


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
