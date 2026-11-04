from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal, Optional

from pydantic import model_validator

REST_PLACEHOLDER_USER = "api-key"  # la columna username es NOT NULL; en modo REST no se usa


class ConnectionConfigBase(BaseModel):
    """Base schema for connection configuration"""
    name: str = Field(..., min_length=1, max_length=100, description="Name of the connection")
    host: str = Field(..., min_length=1, max_length=255, description="IP or FQDN of the Sophos Firewall")
    port: int = Field(default=4444, ge=1, le=65535, description="API port (default: 4444)")
    username: str = Field(..., min_length=1, max_length=100, description="API username (en modo REST no se usa)")
    api_type: Literal["xml", "rest"] = Field(default="xml", description="xml: usuario/contraseña; rest: API key (SFOS v23)")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificate")
    is_active: bool = Field(default=True)
    mcp_enabled: bool = Field(default=False, description="Disponible para el servidor MCP (solo conexiones REST)")


class ConnectionConfigCreate(ConnectionConfigBase):
    """Schema for creating a new connection"""
    username: Optional[str] = Field(default=None, min_length=1, max_length=100, description="Obligatorio en modo xml")
    password: str = Field(..., min_length=1, description="Contraseña (xml) o API key (rest); se guarda cifrada")

    @model_validator(mode="after")
    def _username_segun_modo(self):
        if self.api_type == "xml" and not self.username:
            raise ValueError("username es obligatorio en modo xml")
        if self.api_type == "rest":
            self.username = REST_PLACEHOLDER_USER
        if self.mcp_enabled and self.api_type != "rest":
            raise ValueError("mcp_enabled solo está disponible para conexiones REST")
        return self


class ConnectionConfigUpdate(BaseModel):
    """Schema for updating an existing connection"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    host: Optional[str] = Field(None, min_length=1, max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)
    username: Optional[str] = Field(None, min_length=1, max_length=100)
    password: Optional[str] = Field(None, min_length=1)
    verify_ssl: Optional[bool] = None
    is_active: Optional[bool] = None
    api_type: Optional[Literal["xml", "rest"]] = None
    mcp_enabled: Optional[bool] = None


class ConnectionConfigResponse(ConnectionConfigBase):
    """Schema for connection response (excludes password)"""
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ConnectionTestRequest(BaseModel):
    """Schema for testing a connection"""
    host: str
    port: int = 4444
    username: Optional[str] = None
    password: str
    verify_ssl: bool = True
    api_type: Literal["xml", "rest"] = "xml"


class ConnectionTestResponse(BaseModel):
    """Schema for connection test response"""
    success: bool
    message: str
    details: Optional[dict] = None
