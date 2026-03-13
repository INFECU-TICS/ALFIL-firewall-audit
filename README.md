# ALFIL – Automated Layered Firewall Inspection & Logic

Herramienta de auditoría de salud para **Sophos Firewall (SFOS/XG)**. Recolecta la configuración del equipo vía XML API, analiza problemas de seguridad y genera reportes exportables en Excel y PDF.

## Funcionalidades

- **Gestión de conexiones** — registra múltiples firewalls con credenciales cifradas (Fernet + PBKDF2)
- **Auditoría completa** — recolecta en paralelo: reglas de firewall, reglas NAT, zonas, interfaces, hosts, grupos, servicios, administradores, políticas web/app, configuración de sistema
- **Detección de problemas**:
  - Administradores sin MFA/OTP
  - Acceso administrativo desde zona WAN
  - Reglas permisivas Any→Any
  - Reglas duplicadas
  - Reglas y NAT sin logging
  - DNAT expuesto desde WAN
  - Hosts sin uso en reglas
  - NTP no configurado
  - Reglas deshabilitadas (potencialmente obsoletas)
- **Reportes exportables** en Excel (.xlsx) y PDF
- **Puntaje de salud** 0–100

## Stack

| Capa | Tecnología |
|---|---|
| Backend | FastAPI + Uvicorn (Python 3.12) |
| Base de datos | SQLite (persistida en volumen Docker) |
| Frontend | React 18 + Vite + TailwindCSS |
| Servidor web | nginx (producción) |
| Despliegue | Docker Compose + Dokploy |

## Despliegue rápido (Docker Compose)

```bash
cp .env.example .env
# Editar .env: ENCRYPTION_KEY, DOMAIN, CORS_ORIGINS
docker compose up --build
```

Frontend: `http://localhost:80` · API docs: `http://localhost:8000/docs`

## Variables de entorno requeridas

| Variable | Descripción |
|---|---|
| `ENCRYPTION_KEY` | Clave para cifrar contraseñas. Generar con: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DOMAIN` | Hostname público para Traefik (ej. `alfil.empresa.com`) |
| `CORS_ORIGINS` | Lista JSON de orígenes permitidos (ej. `["https://alfil.empresa.com"]`) |
| `DEBUG` | `false` en producción (default) |

Ver `.env.example` para referencia completa.

## Desarrollo local

```bash
# Backend
cd alfil/backend
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend (otra terminal)
cd alfil/frontend
npm install
npm run dev
```

## API

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/v1/connections` | Listar conexiones |
| POST | `/api/v1/connections` | Crear conexión |
| PUT | `/api/v1/connections/{id}` | Actualizar conexión |
| DELETE | `/api/v1/connections/{id}` | Eliminar conexión |
| POST | `/api/v1/connections/test` | Probar conexión ad-hoc |
| POST | `/api/v1/connections/{id}/test` | Probar conexión guardada |
| POST | `/api/v1/audit/{id}` | Ejecutar auditoría (JSON) |
| GET | `/api/v1/audit/{id}/export/excel` | Exportar reporte Excel |
| GET | `/api/v1/audit/{id}/export/pdf` | Exportar reporte PDF |
