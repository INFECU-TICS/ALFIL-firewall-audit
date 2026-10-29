# Guía de desarrollo

Arquitectura, comandos y convenciones del repositorio. Complementa a `README.md` y a la guía de usuario (`alfil/frontend/src/content/guia.md`).

## Project Overview

**ALFIL – Automated Layered Firewall Inspection & Logic**

Firewall audit system for Sophos Firewall (SFOS/XG). Recolecta configuración via XML API, analiza problemas de seguridad y genera reportes de salud exportables en Excel y PDF. Backend FastAPI + Frontend React.

## Commands

### Backend (development)

```bash
cd alfil/backend
pip install -r requirements.txt
cp ../../.env.example ../../.env   # edit values
uvicorn app.main:app --reload
```

API docs: `http://localhost:8000/docs`

### Frontend (development)

```bash
cd alfil/frontend
npm install
npm run dev    # http://localhost:5173
```

El frontend en dev hace proxy de `/api/` al backend via `vite.config.js`.

### Docker (local)

```bash
cp .env.example .env   # edit values
docker compose up --build
```

## Deployment (Dokploy + GitHub)

1. Push a GitHub. Dokploy lee `docker-compose.yml` de la raíz.
2. En el UI de Dokploy, configurar estas variables **antes** del primer deploy:

| Variable | Notas |
|---|---|
| `ENCRYPTION_KEY` | Generar: `python -c "import secrets; print(secrets.token_hex(32))"`. Nunca rotar — rompe todas las contraseñas guardadas. |
| `DOMAIN` | Hostname público, ej. `alfil.example.com` |
| `DEBUG` | Opcional, default `false` |

3. `DATABASE_URL` está hardcoded en `docker-compose.yml` → `sqlite:////data/alfil.db` (volumen persistente `alfil_data`).
4. Traefik: el frontend sirve `Host(DOMAIN)` (priority=1), el backend sirve `Host(DOMAIN) && PathPrefix(/api)` (priority=10). El nginx del frontend también proxea `/api/` al backend.

## Architecture

### Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI + Uvicorn |
| ORM | SQLAlchemy 2.x |
| Validation | Pydantic v2 |
| Database | SQLite (volume-persisted in Docker) |
| Firewall API | XML API over HTTPS port 4444 |
| Encryption | Fernet + PBKDF2-HMAC-SHA256 |
| Export | openpyxl (Excel), reportlab (PDF) |
| Frontend | React 18 + Vite + TailwindCSS |
| Frontend server | nginx (prod), vite dev server (dev) |

### Backend (`alfil/backend/app/`)

- **`config.py`** — Pydantic `Settings`; lee env vars. `CORS_ORIGINS` se pasa como JSON string.
- **`database.py`** — SQLAlchemy engine + `get_db()` dependency. Guard `"sqlite" in url` para `check_same_thread`.
- **`models/connection.py`** — `ConnectionConfig`: host, port, username, `password_encrypted`, verify_ssl, timestamps.
- **`schemas/connection.py`** — `ConnectionConfigCreate/Update/Response`, `ConnectionTestRequest/Response`. La response nunca incluye password.
- **`routers/connections.py`** — CRUD completo + `POST /connections/test` (ad-hoc) + `POST /connections/{id}/test` (guardada).
- **`routers/audit.py`** — `POST /audit/{id}` → JSON report, `GET /audit/{id}/export/excel`, `GET /audit/{id}/export/pdf`.
- **`services/sophos_client.py`** — `SophosFirewallClient`. `collect_audit_data()` llama todos los colectores secuencialmente; continúa si alguno falla. Helper `_extract_list()` normaliza estructuras XML anidadas (pueden ser str/dict/list).
- **`services/audit_service.py`** — `generate_audit_report(connection_info, raw_data)` → report dict con `summary`, `issues[]`, `sections{}`. Score 0–100.
- **`services/crypto.py`** — `EncryptionManager` singleton. Fixed salt `alfil_salt_value`.

### Frontend (`alfil/frontend/src/`)

- **`api.js`** — Todas las llamadas HTTP. Export URLs se abren con `window.open`.
- **`pages/ConnectionsPage.jsx`** — Grid de conexiones: crear, editar, eliminar, probar, navegar a auditoría.
- **`pages/AuditPage.jsx`** — Ejecuta auditoría, muestra score + hallazgos colapsables por sección + tablas de datos, botones exportación.
- **`components/ConnectionForm.jsx`** — Form con botón "Probar conexión" antes de guardar.
- **`components/IssuesBadge.jsx`** — `SeverityBadge` y `ScoreRing`.

### Detecciones de auditoría implementadas

| Hallazgo | Severidad |
|---|---|
| Admin sin MFA/OTP | Critical |
| Acceso admin desde zona WAN | Critical |
| Regla Any→Any Accept | Warning |
| Regla duplicada | Warning |
| Regla sin logging | Warning |
| Regla NAT DNAT desde WAN | Warning |
| Certificado de admin por defecto | Warning |
| Sin notificaciones configuradas | Warning |
| NTP no configurado | Warning |
| Regla deshabilitada (potencialmente obsoleta) | Info |
| Host sin uso en reglas | Info |
| Timezone del equipo | Info |

### Postman Collection

`sophosfirewall.postman_collection.json` — referencia de requests XML para la Sophos API. Útil para entender el formato de responses al agregar nuevos colectores.

## Sophos Firewall v23 – REST API y servidor MCP

Línea de trabajo nueva (challenge): `alfil-mcp/`, servidor MCP sobre la REST API v1 de SFOS v23 (`/api/firewall-config/v1`, Bearer token). Fase 1 solo lectura; fase 2 escritura con confirmación. Plan y decisiones en la sesión de planificación; no asumir rutas de endpoints, validarlas contra la spec OpenAPI del firewall v23 de pruebas.

Links oficiales y notas verificadas: `docs/REFERENCES.md`.
