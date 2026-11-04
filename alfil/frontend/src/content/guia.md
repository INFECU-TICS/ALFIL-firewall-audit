# Guía de uso de ALFIL

> Última actualización: 2026-11-05. Este documento se mantiene junto con el código: **toda modificación funcional debe actualizarlo** (ver la sección *Mantenimiento de esta documentación*).

## 1. Qué es ALFIL

**ALFIL – Automated Layered Firewall Inspection & Logic** audita firewalls Sophos (SFOS/XG). Recolecta la configuración, detecta problemas de seguridad y calcula un puntaje de salud de 0 a 100. Ofrece además consultas directas al equipo y exportación de resultados.

El proyecto tiene dos componentes:

| Componente | Para qué sirve | Interfaz |
|---|---|---|
| **ALFIL web** | Auditorías con historial, consultas y reportes exportables | Navegador |
| **ALFIL-MCP** | Servidor MCP de **solo lectura** para consultar y auditar el firewall desde un asistente de IA | Cliente MCP (stdio) |

## 2. Funciones de la aplicación web

### 2.1 Conexiones
Cada conexión guarda el firewall a auditar: nombre, host, puerto, tipo de API y credenciales (cifradas). Desde la página principal se puede **crear, editar, eliminar y probar** conexiones, y abrir la auditoría o las consultas de cada una.

### 2.2 Auditoría
Ejecuta la recolección en segundo plano y genera un reporte con:

- **Puntaje de salud** (0–100): `100 − 15 × críticos − 5 × advertencias − 1 × informativos`.
- **Hallazgos** por severidad (crítico, advertencia, informativo), agrupados por sección.
- **Tablas de datos**: administradores, acceso a dispositivo, reglas de firewall (con agrupación), reglas NAT, zonas, interfaces, hosts, servicios, etc.
- **Historial** de auditorías por conexión, numeradas por conexión (#1, #2, #3…; el número no cambia si se borra una auditoría).
- **Exportación** a Excel, PDF y ZIP (incluye los datos crudos).

### 2.3 Consultas directas («Obtener Info»)
Consulta puntual al firewall y muestra de los datos en tabla, con la respuesta cruda copiable y exportación a CSV. Tipos: reglas de firewall, interfaces (con VLAN, alias y LAG en modo XML), objetos de host, servicios y usuarios.

## 3. Cómo conectar un firewall

Al crear una conexión se elige el **tipo de API**. Antes de guardar, use siempre **Probar conexión**.

### 3.1 API XML (todas las versiones)
**Requisitos en el firewall**

1. Crear un usuario con perfil **Auditor** (solo lectura).
2. Autorizar la **IP pública del servidor de ALFIL** en *Sistema › Administración › Acceso API*. El formulario muestra esa IP.
3. El puerto por defecto es **4444**.

**En ALFIL:** tipo *API XML*, host, puerto, usuario y contraseña.

> En firewalls lentos algunas consultas tardan decenas de segundos (por ejemplo, las reglas pueden tardar ~50 s). ALFIL usa un timeout de **90 s** por consulta y **4** consultas simultáneas; son configurables con las variables `SOPHOS_REQUEST_TIMEOUT` y `SOPHOS_COLLECT_WORKERS`. Una auditoría XML completa puede tardar entre 2 y 3 minutos.

### 3.2 API REST v23 (Sophos Firewall v23 o superior)
**Requisitos en el firewall**

1. Generar una **API key** en *Administración › Acceso API (API access)*.
2. Autorizar la IP del servidor de ALFIL.
3. El puerto por defecto es **4444**.

**En ALFIL:** tipo *API REST v23*, host, puerto y **API key** (no se pide usuario). La clave se guarda cifrada.

### 3.3 ¿Qué modo elegir?

| | API XML | API REST v23 |
|---|---|---|
| Versiones | Todas | Solo v23 o superior |
| Credenciales | Usuario y contraseña | API key |
| Duración de una auditoría | Minutos (según el equipo) | Segundos |
| MFA de administradores | **No verificable en v23** | Sí |
| Cobertura de datos | Más amplia (41 colectores) | Reglas, NAT, zonas, interfaces, hosts, servicios, gateways, administradores, acceso por zona y notificaciones |
| Consulta de usuarios | Sí | Aún no |

Recomendación: en firewalls v23 use **REST**; en versiones anteriores use **XML**.

## 4. Qué detecta la auditoría

| Hallazgo | Severidad | XML | REST |
|---|---|---|---|
| Administrador sin MFA/OTP | Crítico | No en v23 | Sí |
| Acceso de administración desde zona WAN | Crítico | Sí | Sí (servicios `https`/`ssh` de la zona) |
| Regla permisiva Any→Any (redes origen y destino y servicios *Any*, acción aceptar) | Advertencia | Sí | Sí |
| Regla duplicada | Advertencia | Sí | Sí |
| Regla sin registro (logging) | Advertencia | Sí | Sí |
| Certificado de administración por defecto | Advertencia | Sí | No |
| Sin notificaciones configuradas | Advertencia | Sí | Sí |
| NTP no configurado | Advertencia | Solo si el equipo lo informa | No |
| Regla deshabilitada (posible obsoleta) | Informativo | Sí | Sí |
| Host sin uso en reglas | Informativo | Sí | Sí |
| Zona horaria / hostname | Informativo | Sí | Parcial |

ALFIL **no afirma nada sobre datos que no pudo obtener**: si un dato no está disponible en el modo elegido, se informa como no verificable.

## 5. ALFIL-MCP

### 5.1 Qué es y su alcance
Es un servidor [MCP](https://modelcontextprotocol.io) que expone el firewall v23 a asistentes de IA a través de su API REST. En esta fase es **estrictamente de solo lectura**:

- El cliente rechaza cualquier verbo distinto de **GET** antes de enviar la petición.
- Solo acepta las **266 rutas GET** de la especificación OpenAPI oficial del firewall v23. Las operaciones de acción (borrado masivo, mover reglas, probar conexiones) no están disponibles.
- No modifica la configuración del equipo bajo ninguna circunstancia.

### 5.2 Instalación
Requiere Python 3.10 o superior.

```bash
cd alfil-mcp
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

### 5.3 Configuración (variables de entorno)

| Variable | Descripción |
|---|---|
| `SFOS_HOST` | IP u hostname del firewall (obligatoria) |
| `SFOS_PORT` | Puerto, por defecto `4444` |
| `SFOS_TOKEN` | API key del firewall (también se acepta `API_KEY`) |
| `SFOS_VERIFY_SSL` | `true` por defecto; `false` para certificados autofirmados de laboratorio |
| `SFOS_ENV_FILE` | Ruta opcional a un archivo `.env` del que leer las variables |

La clave nunca se imprime ni se registra.

### 5.4 Conexión desde un cliente MCP
Cualquier cliente MCP compatible con transporte **stdio** puede usarlo. La definición típica es:

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

### 5.5 Herramientas disponibles

| Herramienta | Qué hace |
|---|---|
| `list_api_endpoints(search, limit)` | Busca entre los 266 endpoints GET de la API v23 |
| `api_get(path, query)` | Lectura genérica de cualquiera de esas rutas (p. ej. `/network/zones`) |
| `list_firewall_rules(only_enabled)` | Resumen de las reglas IPv4 |
| `get_firewall_rule(id_or_name)` | Detalle de una regla por nombre o UUID |
| `audit_firewall()` | Auditoría de reglas (Any→Any, sin log, duplicadas, deshabilitadas) con puntaje |

Recurso: `firewall://summary` (zonas y cantidad de reglas).

### 5.6 Limitaciones del MCP
- Solo firewalls con la **API REST de v23**.
- La auditoría del MCP cubre hoy las **reglas de firewall**; aún no incluye MFA de administradores, acceso de administración desde WAN, objetos sin uso ni diagnóstico de tráfico.
- Las respuestas grandes se paginan (hasta 100 elementos por página).
- La API es *Early Access*: las rutas pueden cambiar antes de la versión general.

## 6. Limitaciones actuales de ALFIL
- En modo REST no están implementados todos los colectores (NTP y zona horaria, certificado de administración, VLAN, alias, LAG, grupos de reglas, VPN, SSL/TLS, filtrado web, rutas, SD-WAN, etc.) ni la consulta de usuarios.
- En modo XML sobre v23 la entidad de administradores no existe, por lo que el MFA de administradores no se puede evaluar.
- La interfaz web no tiene gráficos ni topología: solo tablas y tarjetas.
- No hay autenticación de usuarios en la propia aplicación web: debe desplegarse detrás de un control de acceso (VPN, proxy con autenticación o red restringida).
- Las auditorías las inicia el usuario; no hay programación automática.

## 7. Próximas implementaciones

**Web**
- Completar los colectores del modo REST y la consulta de usuarios.
- Gráficos y vistas de topología (visualización).
- Autenticación de usuarios de la aplicación.

**MCP**
- Auditoría ampliada: MFA de administradores, acceso de administración desde WAN, hosts y servicios sin uso, NAT, interfaces y notificaciones.
- Diagnóstico: `explain_rule_match` (qué regla casa con un tráfico) y `trace_object_usage` (dónde se usa un objeto).
- Prompts MCP guiados ("revisión de salud", "por qué no pasa este tráfico").
- **Fase 2 – escritura con confirmación:** propuestas de cambio con vista previa (*dry-run*), copia de seguridad previa, lista de recursos permitidos y confirmación explícita, deshabilitada por defecto.

## 8. Seguridad y buenas prácticas
- Las contraseñas y API keys se guardan **cifradas**; la clave de cifrado (`ENCRYPTION_KEY`) se define por variable de entorno y **no debe cambiarse** una vez en uso: invalidaría las credenciales guardadas.
- Genere una `ENCRYPTION_KEY` propia y única por despliegue; no use valores de ejemplo.
- Use cuentas de **solo lectura** (perfil Auditor) y autorice únicamente la IP del servidor de ALFIL.
- No registre claves en repositorios, capturas ni tickets.
- Los entregables a clientes deben ser **revisados por una persona** antes de enviarse. El puntaje y los hallazgos son una ayuda a la decisión, no un dictamen.

## 9. Mantenimiento de esta documentación

Este documento vive en `alfil/frontend/src/content/guia.md` y se muestra en la sección **Documentación** de la web. Al modificar funcionalidad, actualice **en el mismo cambio**:

1. Esta guía (funciones, modos de conexión, tabla de detecciones, límites y próximas implementaciones).
2. `docs/ESTADO_Y_PENDIENTES.md` (estado, pendientes y decisiones).
3. `docs/REFERENCES.md` (hallazgos y rutas verificadas del firewall).
4. `alfil-mcp/README.md` si cambia el MCP, y `docs/DESARROLLO.md` si cambia la arquitectura.
5. La fecha de «Última actualización» de esta guía.
