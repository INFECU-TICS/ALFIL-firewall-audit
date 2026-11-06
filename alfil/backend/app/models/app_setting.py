from sqlalchemy import Column, String, Text

from app.database import Base


class AppSetting(Base):
    """Ajustes internos de la instalación (clave/valor). Hoy guarda la sal de cifrado propia de cada instalación."""
    __tablename__ = "app_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)
