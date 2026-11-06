# ALFIL-MCP

Servidor MCP **de solo lectura** para Sophos Firewall v23 sobre su REST API v1 (`/api/firewall-config/v1`). Parte de ALFIL (Automated Layered Firewall Inspection & Logic). Enfoque: optimización (Optimizer) y diagnóstico (Troubleshoot); fase 2: automatización con confirmación.

> Estado: fase 1 (validada en vivo contra un firewall v23). Pendientes y roadmap: [`../docs/ESTADO_Y_PENDIENTES.md`](../docs/ESTADO_Y_PENDIENTES.md).
>
> Fase 1: Ninguna herramienta modifica el firewall; el cliente rechaza cualquier verbo distinto de GET antes de salir a la red y solo acepta las 266 rutas GET de la spec oficial (`spec/openapi.yaml`).

## Herramientas

| Tool | Qué hace |
|---|---|
| `list_connections()` | Firewalls disponibles: conexiones habilitadas en ALFIL («Disponible en MCP») y la directa |
| `list_api_endpoints(search, limit)` | Busca entre los 266 endpoints GET de la API v23 |
| `api_get(path, query)` | GET genérico sobre cualquiera de esas rutas (ej. `/network/zones`) |
| `list_firewall_rules(only_enabled)` | Resumen de reglas IPv4 |
| `get_firewall_rule(id_or_name)` | Detalle de una regla |
| `audit_firewall()` | Hallazgos de reglas (Any→Any, sin log, duplicadas, deshabilitadas) y score 0–100 |
| `get_topology(format)` | Topología de configuración (zonas, interfaces/VLAN, rutas, VPN, advertencias). Solo con conexiones de ALFIL |
| `explain_path(source_ip, destination_ip)` | Ruta de un flujo según la configuración: zonas, interfaz, ruta/VPN, problemas y reglas candidatas por zona. Solo con conexiones de ALFIL |

Resource: `firewall://summary`. Próximo: hardening de admin (MFA, acceso WAN), objetos sin uso, `explain_rule_match`.

Todas las herramientas que consultan un firewall aceptan `connection` (nombre o id de ALFIL, o `directa`). Con ALFIL configurado, el MCP envía un latido cada 30 s para que el dashboard muestre su estado. Ver la guía de usuario (sección 5) para la puesta en marcha.

## Servicio remoto (HTTP)

Con `python -m alfil_mcp.server --transport http` (o las variables `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT`) el MCP escucha en `/mcp` (streamable HTTP sin sesión, respuestas JSON) y `/health`. Cada petición debe traer `Authorization: Bearer <token de ALFIL>`; el servicio lo valida contra ALFIL (`ALFIL_URL`, URL interna del backend) y lo reutiliza para leer los firewalls habilitados a través del proxy de solo lectura. No guarda credenciales ni acepta conexión directa. El `Dockerfile` y el servicio `amcp` del `docker-compose.yml` lo publican en `https://DOMINIO/mcp`. La guía de usuario (sección 5.2) explica cómo conectar cada agente.

## Instalación

```bash
cd alfil-mcp
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

## Configuración (variables de entorno)

| Variable | Notas |
|---|---|
| `ALFIL_URL` | URL de ALFIL: usa sus conexiones habilitadas en el dashboard (ALFIL custodia las credenciales y hace de proxy de solo lectura) |
| `ALFIL_MCP_TOKEN` | Token generado en el dashboard de ALFIL (panel «Servidor MCP») |
| `ALFIL_VERIFY_SSL` | Default `true` |
| `SFOS_HOST` | IP/hostname del firewall (modo directo) |
| `SFOS_PORT` | Default `4444` |
| `SFOS_TOKEN` | API key (*Administration › API access*). También se acepta `API_KEY` |
| `SFOS_VERIFY_SSL` | Default `true`; `false` para certificado autofirmado de laboratorio |
| `SFOS_ENV_FILE` | Ruta opcional a un `.env` del que leer `SFOS_*`/`API_KEY` |

El token nunca se imprime ni se registra. No lo commitees.

## Conexión desde un cliente MCP

Funciona con cualquier cliente MCP que soporte transporte **stdio**. Defina el servidor con esta configuración (el nombre del archivo y su ubicación dependen del cliente):

```json
{
  "mcpServers": {
    "alfil": {
      "command": "/ruta/alfil-mcp/.venv/bin/python",
      "args": ["-m", "alfil_mcp.server"],
      "env": {
        "SFOS_HOST": "<ip-del-firewall>",
        "SFOS_VERIFY_SSL": "false",
        "SFOS_ENV_FILE": "/ruta/al/.env"
      }
    }
  }
}
```

Para probarlo sin cliente: `npx @modelcontextprotocol/inspector /ruta/alfil-mcp/.venv/bin/python -m alfil_mcp.server`.

## Mantenimiento

- Spec oficial: `spec/openapi.yaml` (extraída del firewall v23). Inventario: `../docs/API_V23_INVENTORY.md`.
- Regenerar catálogo de GET: `python scripts/gen_catalog.py`; inventario: `python scripts/gen_inventory.py`.
- Es Early Access: si cambia la spec, regenerar ambos y correr los tests.

## Validación en laboratorio

`scripts/lab_validate.py` crea reglas `ALFIL-TEST-*` en un firewall **de pruebas**, ejecuta `audit_firewall` y las borra. Escribe en el equipo, por eso exige `ALFIL_LAB_WRITE=yes`. POST/DELETE tardan ~20 s cada uno.
