from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_db
from app.models.audit_report import AuditReport
from app.models.connection import ConnectionConfig
from app.services.audit_service import generate_audit_report
from app.services.crypto import get_encryption_manager
from app.services.export_service import generate_excel, generate_pdf, generate_zip
from app.services.firewall_client import client_for_connection

router = APIRouter(prefix="/audit", tags=["audit"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_connection_or_404(connection_id: int, db: Session) -> ConnectionConfig:
    obj = db.query(ConnectionConfig).filter(ConnectionConfig.id == connection_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Conexión no encontrada")
    return obj


def _get_audit_or_404(audit_id: int, db: Session) -> AuditReport:
    obj = db.query(AuditReport).filter(AuditReport.id == audit_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada")
    return obj


def _get_client(obj: ConnectionConfig):
    return client_for_connection(obj)


def _audit_summary(report: dict) -> dict:
    return report.get("summary", {})


# ---------------------------------------------------------------------------
# Tarea de fondo
# ---------------------------------------------------------------------------

def _run_audit_task(audit_id: int, connection_id: int) -> None:
    """Ejecuta la auditoría en segundo plano y persiste el resultado."""
    db = SessionLocal()
    try:
        obj = db.query(ConnectionConfig).filter(ConnectionConfig.id == connection_id).first()
        if not obj:
            raise ValueError(f"Conexión {connection_id} no encontrada")

        client = _get_client(obj)
        raw_data = client.collect_audit_data()
        connection_info = {"id": obj.id, "name": obj.name, "host": obj.host,
                           "port": obj.port, "username": obj.username,
                           "api_type": getattr(obj, "api_type", "xml")}
        report = generate_audit_report(connection_info, raw_data)

        audit = db.query(AuditReport).filter(AuditReport.id == audit_id).first()
        if audit:
            audit.status = "completed"
            audit.completed_at = datetime.now(timezone.utc)
            audit.summary = report["summary"]
            audit.report = report
            db.commit()
    except Exception as e:
        audit = db.query(AuditReport).filter(AuditReport.id == audit_id).first()
        if audit:
            audit.status = "failed"
            audit.error = str(e)
            audit.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Endpoints de historial y ejecución
# ---------------------------------------------------------------------------

@router.post("/{connection_id}/start")
def start_audit(connection_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Inicia una auditoría en segundo plano. Devuelve el audit_id inmediatamente."""
    _get_connection_or_404(connection_id, db)

    last_seq = db.query(func.max(AuditReport.seq)).filter(AuditReport.connection_id == connection_id).scalar() or 0
    audit = AuditReport(connection_id=connection_id, status="running", seq=last_seq + 1)
    db.add(audit)
    db.commit()
    db.refresh(audit)

    background_tasks.add_task(_run_audit_task, audit.id, connection_id)

    return {"audit_id": audit.id, "seq": audit.seq, "status": "running",
            "created_at": audit.created_at.isoformat() if audit.created_at else None}


@router.get("/{connection_id}/history")
def list_audits(connection_id: int, db: Session = Depends(get_db)):
    """Lista el historial de auditorías de una conexión (más reciente primero)."""
    _get_connection_or_404(connection_id, db)
    audits = (db.query(AuditReport)
              .filter(AuditReport.connection_id == connection_id)
              .order_by(AuditReport.created_at.desc())
              .all())
    return [
        {
            "id": a.id,
            "seq": a.seq or a.id,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None,
            "summary": a.summary,
            "error": a.error,
        }
        for a in audits
    ]


@router.get("/reports/{audit_id}")
def get_audit_report(audit_id: int, db: Session = Depends(get_db)):
    """Devuelve el reporte completo de una auditoría."""
    audit = _get_audit_or_404(audit_id, db)
    if audit.status != "completed":
        return {"id": audit.id, "status": audit.status, "error": audit.error,
                "created_at": audit.created_at.isoformat() if audit.created_at else None}
    return audit.report


@router.delete("/reports/{audit_id}", status_code=204)
def delete_audit(audit_id: int, db: Session = Depends(get_db)):
    """Elimina una auditoría del historial."""
    audit = _get_audit_or_404(audit_id, db)
    db.delete(audit)
    db.commit()


# ---------------------------------------------------------------------------
# Exportaciones (usan el reporte guardado en BD)
# ---------------------------------------------------------------------------

def _load_completed_report(audit_id: int, db: Session) -> tuple[AuditReport, dict]:
    audit = _get_audit_or_404(audit_id, db)
    if audit.status != "completed" or not audit.report:
        raise HTTPException(status_code=400, detail="La auditoría no está completa o no tiene reporte")
    return audit, audit.report


@router.get("/reports/{audit_id}/export/excel")
def export_excel(audit_id: int, db: Session = Depends(get_db)):
    audit, report = _load_completed_report(audit_id, db)
    buf = generate_excel(report)
    conn_name = report.get("connection", {}).get("name", str(audit.connection_id))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"alfil_audit_{conn_name}_{ts}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/{audit_id}/export/pdf")
def export_pdf(audit_id: int, db: Session = Depends(get_db)):
    audit, report = _load_completed_report(audit_id, db)
    buf = generate_pdf(report)
    conn_name = report.get("connection", {}).get("name", str(audit.connection_id))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"alfil_audit_{conn_name}_{ts}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/{audit_id}/export/zip")
def export_zip(audit_id: int, db: Session = Depends(get_db)):
    audit, report = _load_completed_report(audit_id, db)
    conn_name = report.get("connection", {}).get("name", str(audit.connection_id))
    buf = generate_zip(report, conn_name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"alfil_audit_{conn_name}_{ts}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
