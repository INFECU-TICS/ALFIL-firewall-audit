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
| Firewall API | XML API (todas las versiones) o REST API v1 (SFOS v23), HTTPS puerto 4444 |
| Encryption | Fernet + PBKDF2-HMAC-SHA256 |
| Export | openpyxl (Excel), reportlab (PDF) |
| Frontend | React 18 + Vite + TailwindCSS |
| Frontend server | nginx (prod), vite dev server (dev) |

### Backend (`alfil/backend/app/`)

- **`config.py`** — Pydantic `Settings`; lee env vars. `CORS_ORIGINS` se pasa como JSON string.
- **`database.py`** — SQLAlchemy engine + `get_db()` dependency. Guard `"sqlite" in url` para `check_same_thread`.
- **`models/connection.py`** — `ConnectionConfig`: host, port, username, `password_encrypted`, verify_ssl, `api_type` (`xml`|`rest`), timestamps. En modo `rest` `password_encrypted` guarda la API key y `username` es el placeholder `api-key`. `database.ensure_schema()` migra BD antiguas (añade `api_type`).
- **`schemas/connection.py`** — `ConnectionConfigCreate/Update/Response`, `ConnectionTestRequest/Response`. La response nunca incluye password.
- **`routers/connections.py`** — CRUD completo + `POST /connections/test` (ad-hoc) + `POST /connections/{id}/test` (guardada).
- **`routers/mcp.py`** — integración con el MCP: estado y token (dashboard), latido, conexiones habilitadas y proxy GET de solo lectura (Bearer). Modelo `models/mcp_access.py`; `services/get_catalog.py` valida rutas contra `app/data/get_catalog.json`.
- **`routers/audit.py`** — `POST /audit/{id}` → JSON report, `GET /audit/{id}/export/excel`, `GET /audit/{id}/export/pdf`.
- **`services/sophos_client.py`** — `SophosFirewallClient`. `collect_audit_data()` llama todos los colectores secuencialmente; continúa si alguno falla. Helper `_extract_list()` normaliza estructuras XML anidadas (pueden ser str/dict/list).
- **`services/firewall_client.py`** — fábrica: `client_for_connection(obj)` devuelve el cliente XML o REST según `api_type`. **`services/sophos_rest_client.py`** (REST API v23, solo lectura) + **`services/rest_normalizers.py`** (JSON REST → mismo formato que los colectores XML). Config: `SOPHOS_REQUEST_TIMEOUT` (90 s) y `SOPHOS_COLLECT_WORKERS` (4).
- **`services/topology.py`** — `build_topology(raw_data, connection_info)`: grafo de topología (nodos/aristas/advertencias) desde los datos recolectados; se guarda en `report["topology"]`. Funciona igual con datos XML y REST (los normalizadores REST emiten el formato XML).
- **`services/audit_service.py`** — `generate_audit_report(connection_info, raw_data)` → report dict con `summary`, `issues[]`, `sections{}`. Score 0–100.
- **`services/crypto.py`** — `EncryptionManager` singleton. Fixed salt `alfil_salt_value`.

### Frontend (`alfil/frontend/src/`)

- **`api.js`** — Todas las llamadas HTTP. Export URLs se abren con `window.open`.
- **`pages/ConnectionsPage.jsx`** — Grid de conexiones: crear, editar, eliminar, probar, navegar a auditoría.
- **`pages/AuditPage.jsx`** — Ejecuta auditoría, muestra score + hallazgos colapsables por sección + tablas de datos, botones exportación.
- **`components/ConnectionForm.jsx`** — Form con selector de tipo de API (XML / REST v23) y botón "Probar conexión" antes de guardar.
- **`components/McpStatusCard.jsx`** — panel de estado y token del MCP en el dashboard.
- **`pages/TopologyPage.jsx`** + **`topology/`** (`layout.js` filtro/ELK/Mermaid, `TopoNodes.jsx`) — visor interactivo de la topología (React Flow + ELK).
- **`pages/DocsPage.jsx`** + **`content/guia.md`** — documentación integrada en la web.
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

Línea de trabajo nueva (challenge): `alfil-mcp/`, servidor MCP sobre la REST API v1 de SFOS v23 (`/api/firewall-config/v1`, Bearer token). Fase 1 solo lectura; fase 2 escritura con confirmación. No asumir rutas de endpoints: validarlas contra la spec OpenAPI del firewall v23 de pruebas.

**Estado y pendientes para retomar: `docs/ESTADO_Y_PENDIENTES.md`** (leer primero). Links oficiales y notas verificadas: `docs/REFERENCES.md`. Spec oficial extraída del firewall: `alfil-mcp/spec/openapi.yaml`; inventario de endpoints: `docs/API_V23_INVENTORY.md` (regenerar con `alfil-mcp/scripts/gen_inventory.py`). La API key de pruebas vive en `.env` (`API_KEY`, ignorado por git); el firewall de pruebas se indica con `SFOS_HOST` (puerto 4444). Nunca imprimir ni commitear la key.

Nota: la web ALFIL (API XML) funciona contra v23 pero el firewall de pruebas es lento; con los defaults actuales (timeout 10 s, 12 hilos) la auditoría falla casi por completo. Contraseña del admin de pruebas en la variable de entorno `FWPASS`. Detalle y plan en `docs/ESTADO_Y_PENDIENTES.md`.

## Documentación: mantenerla al día (obligatorio)

Toda modificación funcional debe actualizar la documentación **en el mismo cambio**:

| Archivo | Qué contiene | Actualizar cuando |
|---|---|---|
| `alfil/frontend/src/content/guia.md` | Guía de usuario (se muestra en la web, sección *Documentación*): funciones, conexión por tipo de API, MCP, límites y próximas implementaciones | Cambia una función, un modo de conexión, una detección o el alcance del MCP |
| `docs/ESTADO_Y_PENDIENTES.md` | Estado, pendientes y decisiones | Se completa o se agrega trabajo |
| `docs/REFERENCES.md` | Fuentes oficiales y hallazgos/rutas verificadas del firewall | Se verifica algo nuevo en un equipo |
| `docs/API_V23_INVENTORY.md` | Inventario generado de la API | Cambia la spec (`alfil-mcp/scripts/gen_inventory.py`) |
| `alfil-mcp/README.md` | Instalación y uso del MCP | Cambia el MCP |
| `docs/DESARROLLO.md` | Esta guía de arquitectura | Cambia la arquitectura o los comandos |

Actualice también la fecha de «Última actualización» de la guía de usuario.

## Seguridad del repositorio

- Nunca commitear claves, contraseñas, tokens, `.env`, bases de datos (`*.db`) ni respuestas reales de clientes (`.example_responses/`).
- Las IPs, hostnames y usuarios de equipos reales no van en el código ni en la documentación: usar variables de entorno o marcadores (`<ip-del-firewall>`).
- Los mensajes de commit describen el cambio; no incluyen credenciales ni datos de clientes.
