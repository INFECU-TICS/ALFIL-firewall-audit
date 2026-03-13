# Guía de desarrollo

Arquitectura, comandos y convenciones del repositorio. Complementa a `README.md` y a la guía de usuario (`alfil/frontend/src/content/guia.md`).

## Project Overview

**ALFIL – Automated Layered Firewall Inspection & Logic**

A firewall audit system for inspecting and managing Sophos Firewall configurations. The backend exposes a FastAPI REST API that communicates with Sophos Firewall via its XML API, stores connection configs with encrypted credentials in SQLite, and will serve a frontend (not yet implemented).

## Commands

### Local Development

```bash
cd alfil/backend
pip install -r requirements.txt
cp ../../.env.example ../../.env   # edit values
uvicorn app.main:app --reload
```

API docs available at `http://localhost:8000/docs`.

### Docker (local)

```bash
cp .env.example .env   # edit values
docker compose up --build
```

## Deployment (Dokploy + GitHub)

1. Push the repo to GitHub. Dokploy reads `docker-compose.yml` from the root.
2. In the Dokploy UI, set these environment variables **before** the first deploy:

| Variable | Notes |
|---|---|
| `ENCRYPTION_KEY` | Generate: `python -c "import secrets; print(secrets.token_hex(32))"`. Never rotate — doing so makes all stored passwords unreadable. |
| `CORS_ORIGINS` | JSON array string, e.g. `["https://alfil.example.com"]` |
| `DOMAIN` | Public hostname, e.g. `alfil.example.com` |
| `DEBUG` | Optional; defaults to `false` |

3. `DATABASE_URL` is hardcoded in `docker-compose.yml` to `sqlite:////data/alfil.db` (absolute path inside container, persisted in the `alfil_data` named volume).
4. Traefik labels in `docker-compose.yml` handle TLS termination via Let's Encrypt and route `Host(DOMAIN) && PathPrefix(/api)` to the backend.

## Architecture

### Stack

| Layer | Technology |
|-------|-----------|
| Backend framework | FastAPI + Uvicorn |
| ORM | SQLAlchemy 2.x |
| Validation | Pydantic v2 |
| Database | SQLite (volume-persisted in Docker) |
| Firewall protocol | XML API over HTTPS (port 4444) |
| Encryption | Fernet (cryptography lib, PBKDF2-HMAC-SHA256 key derivation) |
| XML parsing | xmltodict |
| Migrations | Alembic (installed, not yet configured) |

### Backend Structure (`alfil/backend/app/`)

- **`config.py`** — Pydantic `Settings` class; reads env vars. Defaults: SQLite DB, CORS for `localhost:5173` and `localhost:3000`.
- **`database.py`** — SQLAlchemy engine/session setup; `get_db()` dependency for injection.
- **`models/connection.py`** — `ConnectionConfig` ORM model; stores firewall host, port, username, encrypted password, and timestamps.
- **`schemas/connection.py`** — Pydantic schemas: `ConnectionConfigCreate`, `ConnectionConfigUpdate`, `ConnectionConfigResponse` (no password), `ConnectionTestRequest/Response`.
- **`services/sophos_client.py`** — `SophosClient` class that wraps the Sophos XML API (`https://<host>:<port>/webconsole/APIController`). Key methods: `test_connection()`, `get_system_status()`, `get_firewall_rules()`, `get_network_zones()`, `get_interfaces()`.
- **`services/crypto.py`** — `EncryptionManager` singleton using Fernet for encrypting stored passwords. Key: derived from a secret via PBKDF2.
- **`routers/`** — Empty; API route implementations go here.

### Key Design Decisions

- Passwords are never returned in API responses (`ConnectionConfigResponse` excludes them).
- SSL verification for Sophos API calls is configurable (disabled by default for self-signed certs).
- The Sophos XML API requires credentials embedded in every request payload.

### Postman Collection

`sophosfirewall.postman_collection.json` at the repo root contains reference API calls for the Sophos Firewall XML API — useful for understanding request/response formats when implementing new `SophosClient` methods.
