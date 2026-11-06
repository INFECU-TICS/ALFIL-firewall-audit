# Guía de uso de ALFIL

> Última actualización: 2026-11-05 (MCP remoto y conexión de agentes). Este documento se mantiene junto con el código: **toda modificación funcional debe actualizarlo** (ver la sección *Mantenimiento de esta documentación*).

## 1. Qué es ALFIL

**ALFIL – Automated Layered Firewall Inspection & Logic** audita firewalls Sophos (SFOS/XG). Recolecta la configuración, detecta problemas de seguridad y calcula un puntaje de salud de 0 a 100. Ofrece además consultas directas al equipo y exportación de resultados.

El proyecto tiene dos componentes:

| Componente | Para qué sirve | Interfaz |
|---|---|---|
| **ALFIL web** | Auditorías con historial, consultas y reportes exportables | Navegador |
| **ALFIL-MCP** | Servidor MCP de **solo lectura** para consultar y auditar el firewall desde un asistente de IA | Servicio remoto (`/mcp`) o local (stdio) |

## 2. Funciones de la aplicación web

### 2.1 Conexiones
Cada conexión guarda el firewall a auditar: nombre, host, puerto, tipo de API y credenciales (cifradas). Desde la página principal se puede **crear, editar, eliminar y probar** conexiones, y abrir la auditoría o las consultas de cada una.

Las conexiones **REST** tienen además el interruptor **Disponible en MCP** (apagado por defecto), que permite a un asistente de IA leerlas a través del servidor MCP. Las conexiones XML no pueden habilitarse. En la parte superior de la página, el panel **Servidor MCP** muestra su estado (ver la sección 5.8).

### 2.2 Auditoría
Ejecuta la recolección en segundo plano y genera un reporte con:

- **Puntaje de salud** (0–100): `100 − 15 × críticos − 5 × advertencias − 1 × informativos`.
- **Hallazgos** por severidad (crítico, advertencia, informativo), agrupados por sección.
- **Tablas de datos**: administradores, acceso a dispositivo, reglas de firewall (con agrupación), reglas NAT, zonas, interfaces, hosts, servicios, etc.
- **Historial** de auditorías por conexión, numeradas por conexión (#1, #2, #3…; el número no cambia si se borra una auditoría).
- **Exportación** a Excel, PDF y ZIP (incluye los datos crudos).

### 2.3 Topología de red
Desde el historial de auditorías, el botón **Topología de red** (icono de red) de una auditoría completada abre un diagrama interactivo generado con la configuración del firewall:

- **Zonas** (LAN, WAN, DMZ, VPN, WiFi y personalizadas) como contenedores de color.
- **Interfaces** con su IP: físicas, **VLAN** (se dibujan como interfaces más, con su ID), LAG y bridge. Las IP secundarias (alias) aparecen como redes adicionales.
- **Redes conectadas** (por ejemplo `10.0.1.0/24`) calculadas a partir de la IP y la máscara de cada interfaz.
- **Salida a Internet** a través del gateway de la zona WAN.
- **Rutas estáticas**: cada ruta se dibuja como `red conectada → router de salto → red remota`; los routers compartidos no se duplican y la ruta por defecto va a Internet. Una ruta cuyo salto no está en ninguna red conectada se marca como **salto inalcanzable**.
- **VPN IPsec**: `Firewall ⇄ túnel ⇄ sitio remoto → redes remotas`; los túneles inactivos se dibujan punteados.

Controles: zoom y desplazamiento, minimapa, panel de detalle al hacer clic en un elemento, filtros (puertos sin configurar, zonas vacías, etiquetas) y exportación a **PNG** o como texto **Mermaid** (para pegar en documentación). El panel lateral lista las **advertencias de topología**: salto inalcanzable, redes remotas que se solapan con redes conectadas e interfaces con IP sin zona.

> El grafo se calcula al ejecutar la auditoría y se guarda con ella. Las auditorías anteriores a esta función no lo incluyen: ejecute una nueva.

### 2.4 Consultas directas («Obtener Info»)
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

Además, la topología genera sus propias **advertencias** (salto inalcanzable, solapamiento de subredes, interfaz sin zona); por ahora no afectan al puntaje.

ALFIL **no afirma nada sobre datos que no pudo obtener**: si un dato no está disponible en el modo elegido, se informa como no verificable.

## 5. ALFIL-MCP

### 5.1 Qué es y su alcance
Es un servidor [MCP](https://modelcontextprotocol.io) que expone el firewall v23 a asistentes de IA a través de su API REST. En esta fase es **estrictamente de solo lectura**:

- El cliente rechaza cualquier verbo distinto de **GET** antes de enviar la petición.
- Solo acepta las **266 rutas GET** de la especificación OpenAPI oficial del firewall v23. Las operaciones de acción (borrado masivo, mover reglas, probar conexiones) no están disponibles.
- No modifica la configuración del equipo bajo ninguna circunstancia.

### 5.2 Conectar un agente de IA (MCP remoto, recomendado)
ALFIL publica el MCP como un servicio remoto en `https://<su-dominio>/mcp`. **El agente no instala nada**: solo registra la URL y un token.

1. Cree una conexión de tipo **API REST v23** y active **Disponible en MCP** (en la tarjeta o al editarla).
2. En el panel **Servidor MCP** del dashboard pulse **Conectar un agente** y luego **Generar token**. Se muestra una sola vez: en la base solo queda su hash.
3. Elija su agente en el asistente y copie el comando o la configuración, ya con la URL y el token. Si el agente no está en la lista, copie el **prompt de instalación** y péguelo en su chat: *«Instala este servidor MCP remoto…»*; el agente lo traduce a su propio formato.
4. Verifique que el agente lista las herramientas de `alfil` y ejecute `list_connections`.

| Agente | Estado de la configuración |
|---|---|
| Claude Code | Probado contra ALFIL (`claude mcp list` → Connected) |
| opencode | Probado contra ALFIL (`opencode mcp list` → connected) |
| Codex | Según su documentación; sin probar |
| Cursor, VS Code | Según su documentación; sin probar |
| Gemini CLI | Formato pendiente de confirmar; sin probar |

Los formatos de cada herramienta cambian con las versiones: si el fragmento deja de funcionar, use el prompt de instalación o consulte la documentación del agente. En local (`http://localhost:8081/mcp`) basta HTTP; en cualquier otro entorno use **HTTPS**.

### 5.3 Uso local por stdio: instalación
Requiere Python 3.10 o superior.

```bash
cd alfil-mcp
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

### 5.4 Formas de acceder a un firewall
El MCP puede trabajar de dos maneras (se pueden combinar):

| Modo | Cómo se configura | Cuándo usarlo |
|---|---|---|
| **Conexiones de ALFIL** (recomendado) | `ALFIL_URL` + `ALFIL_MCP_TOKEN` en el MCP local, o el servicio remoto de ALFIL (sección 5.2); las conexiones se habilitan en el dashboard | Varios firewalls, credenciales centralizadas y estado visible en el dashboard |
| **Directo** | `SFOS_HOST` + `SFOS_TOKEN` | Un solo firewall, sin ALFIL |

En el modo ALFIL **el MCP nunca recibe la API key**: pide al backend de ALFIL que lea una ruta GET de la conexión elegida y el backend la ejecuta con la clave que custodia. Solo se aceptan las rutas GET de la especificación oficial.

**Puesta en marcha en modo ALFIL**

1. Cree una conexión de tipo **API REST v23** y actívele **Disponible en MCP** (en la tarjeta o al editarla).
2. En el panel **Servidor MCP** del dashboard pulse **Generar token** y cópielo: solo se muestra una vez y en la base solo se guarda su hash. Generar otro invalida el anterior; **Revocar** lo anula.
3. Configure el cliente MCP con `ALFIL_URL` (la dirección de ALFIL, alcanzable desde donde corre el MCP) y `ALFIL_MCP_TOKEN`. El panel muestra un JSON listo para copiar.
4. En el asistente use `list_connections` para ver los firewalls disponibles y el parámetro `connection` para elegir uno. Si solo hay una conexión habilitada, se usa por defecto.

### 5.5 Configuración (variables de entorno)

| Variable | Descripción |
|---|---|
| `ALFIL_URL` | Dirección de ALFIL (por ejemplo `http://servidor:8081`) para usar sus conexiones |
| `ALFIL_MCP_TOKEN` | Token generado en el dashboard de ALFIL |
| `ALFIL_VERIFY_SSL` | `true` por defecto; `false` si ALFIL usa un certificado propio |
| `SFOS_HOST` | IP u hostname del firewall (modo directo) |
| `SFOS_PORT` | Puerto, por defecto `4444` |
| `SFOS_TOKEN` | API key del firewall (también se acepta `API_KEY`) |
| `SFOS_VERIFY_SSL` | `true` por defecto; `false` para certificados autofirmados de laboratorio |
| `SFOS_ENV_FILE` | Ruta opcional a un archivo `.env` del que leer las variables |

La clave nunca se imprime ni se registra.

### 5.6 Conexión desde un cliente MCP local (stdio)
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

### 5.7 Herramientas disponibles

| Herramienta | Qué hace |
|---|---|
| `list_connections()` | Lista los firewalls disponibles (conexiones habilitadas en ALFIL y la directa) |
| `list_api_endpoints(search, limit)` | Busca entre los 266 endpoints GET de la API v23 |
| `api_get(path, query)` | Lectura genérica de cualquiera de esas rutas (p. ej. `/network/zones`) |
| `list_firewall_rules(only_enabled)` | Resumen de las reglas IPv4 |
| `get_firewall_rule(id_or_name)` | Detalle de una regla por nombre o UUID |
| `audit_firewall()` | Auditoría de reglas (Any→Any, sin log, duplicadas, deshabilitadas) con puntaje |

Todas las herramientas que consultan un firewall aceptan el parámetro opcional `connection` (nombre o id de la conexión de ALFIL, o `directa`).

Recurso: `firewall://summary` (zonas y cantidad de reglas de la conexión por defecto).

### 5.8 Estado del MCP en el dashboard
El panel **Servidor MCP** muestra el estado del **servicio remoto** (ALFIL lo sondea cada 15 s) y, si usa el MCP local por stdio, el de ese proceso: mientras está en ejecución envía un latido a ALFIL cada 30 segundos. Estados:

| Estado | Significado |
|---|---|
| **En línea** | Hubo un latido en los últimos 90 segundos |
| **Fuera de línea** | El MCP dejó de enviar latidos |
| **Sin actividad** | Hay token, pero el MCP aún no se ha conectado |
| **No configurado** | No hay token generado |

Además indica la versión, el número de herramientas, el modo (solo lectura), las conexiones habilitadas, el prefijo del token y cuándo fue la **última lectura de un agente**. El servicio remoto está en línea aunque no haya agentes conectados; el MCP local por stdio solo mientras el cliente lo mantiene abierto.

### 5.9 Seguridad del MCP remoto
- **El token da lectura** de las configuraciones de los firewalls habilitados. Trátelo como una credencial: no lo pegue en repositorios, tickets ni capturas, y revóquelo si se expone. Hay un único token compartido; generar otro invalida el anterior.
- **Use HTTPS** fuera de local: el token viaja en cada petición. El despliegue con Traefik ya publica `/mcp` con TLS.
- Habilite en MCP **solo las conexiones necesarias** y, si es posible, limite el acceso a `/mcp` por VPN o por IP.
- El servicio **no guarda credenciales**: valida el token contra ALFIL en cada petición y las consultas pasan por el proxy de solo lectura del backend, que solo ejecuta las rutas GET de la especificación.
- Los agentes pueden enviar lo que leen a su proveedor de modelo: considere qué datos del firewall autoriza a analizar.

### 5.10 Limitaciones del MCP
- Solo firewalls con la **API REST de v23**; las conexiones XML de ALFIL no se pueden usar desde el MCP.
- En modo ALFIL, las consultas pasan por el backend de ALFIL (que debe estar accesible); en equipos lentos una consulta puede tardar decenas de segundos.
- Para el MCP local por stdio, el estado depende de los latidos: si ALFIL no es alcanzable desde el MCP, aparecerá *fuera de línea* aunque el MCP funcione.
- Un único token compartido para todos los agentes (sin tokens por agente ni caducidad).
- Los formatos de configuración de Codex, Cursor, VS Code y Gemini CLI no se han probado contra ALFIL.
- La auditoría del MCP cubre hoy las **reglas de firewall**; aún no incluye MFA de administradores, acceso de administración desde WAN, objetos sin uso ni diagnóstico de tráfico.
- Las respuestas grandes se paginan (hasta 100 elementos por página).
- La API es *Early Access*: las rutas pueden cambiar antes de la versión general.

## 6. Limitaciones actuales de ALFIL
- En modo REST no están implementados todos los colectores (NTP y zona horaria, certificado de administración, VLAN, alias, LAG, grupos de reglas, VPN, SSL/TLS, filtrado web, rutas, SD-WAN, etc.) ni la consulta de usuarios.
- En modo XML sobre v23 la entidad de administradores no existe, por lo que el MFA de administradores no se puede evaluar.
- La topología refleja la **configuración**, no el estado en vivo: no incluye rutas aprendidas por ruteo dinámico (OSPF/BGP/RIP, que la API REST v1 no expone) ni las rutas SD-WAN, y no muestra el estado real de los enlaces.
- En modo XML, las redes protegidas de las conexiones VPN se leen con nombres de etiqueta por confirmar en un equipo con VPN; en modo REST sí están verificadas.
- La interfaz web aún no tiene gráficos de resultados (puntajes, tendencias); solo tablas y tarjetas, además de la topología.
- No hay autenticación de usuarios en la propia aplicación web: debe desplegarse detrás de un control de acceso (VPN, proxy con autenticación o red restringida).
- Las auditorías las inicia el usuario; no hay programación automática.

## 7. Próximas implementaciones

**Web**
- Completar los colectores del modo REST y la consulta de usuarios.
- Topología: colorear el grafo con los hallazgos de la auditoría, servidores publicados (DNAT), rutas SD-WAN, matriz zona→zona con las reglas permitidas, mapa multi-sitio (unir firewalls por sus VPN) y comparación entre auditorías.
- Detecciones basadas en topología (salto inalcanzable, subredes solapadas) integradas en los hallazgos y el puntaje.
- Gráficos de resultados (tendencia del puntaje).
- Autenticación de usuarios de la aplicación.

**MCP**
- Auditoría ampliada: MFA de administradores, acceso de administración desde WAN, hosts y servicios sin uso, NAT, interfaces y notificaciones.
- Diagnóstico: `explain_rule_match` (qué regla casa con un tráfico) y `trace_object_usage` (dónde se usa un objeto).
- Herramienta `get_topology` (JSON o Mermaid) y `explain_path(origen, destino)`: por dónde sale el tráfico y qué regla lo permite.
- Tokens por agente (con nombre, revocables y con último uso) y caducidad.
- Prompts MCP guiados ("revisión de salud", "por qué no pasa este tráfico").
- **Fase 2 – escritura con confirmación:** propuestas de cambio con vista previa (*dry-run*), copia de seguridad previa, lista de recursos permitidos y confirmación explícita, deshabilitada por defecto.

## 8. Seguridad y buenas prácticas
- Las contraseñas y API keys se guardan **cifradas** con una clave derivada de `ENCRYPTION_KEY` y una sal aleatoria propia de cada instalación. Con `DEBUG=false` el servidor **no arranca** si la clave falta, es de ejemplo o tiene menos de 32 caracteres. Para cambiarla, ponga la nueva en `ENCRYPTION_KEY` y la anterior en `ENCRYPTION_KEY_OLD` durante un arranque: ALFIL reescribe las credenciales y deja una copia de la base de datos antes de hacerlo.
- Genere una `ENCRYPTION_KEY` propia y única por despliegue; no use valores de ejemplo. Los respaldos de la base de datos incluyen la sal: guárdelos con el mismo cuidado que la clave.
- Use cuentas de **solo lectura** (perfil Auditor) y autorice únicamente la IP del servidor de ALFIL.
- No registre claves en repositorios, capturas ni tickets.
- Trate el token del MCP como una credencial: permite leer (solo lectura) las conexiones habilitadas. Revóquelo si se expone y habilite en MCP solo las conexiones necesarias.
- Los entregables a clientes deben ser **revisados por una persona** antes de enviarse. El puntaje y los hallazgos son una ayuda a la decisión, no un dictamen.

## 9. Mantenimiento de esta documentación

Este documento vive en `alfil/frontend/src/content/guia.md` y se muestra en la sección **Documentación** de la web. Al modificar funcionalidad, actualice **en el mismo cambio**:

1. Esta guía (funciones, modos de conexión, tabla de detecciones, límites y próximas implementaciones).
2. `docs/ESTADO_Y_PENDIENTES.md` (estado, pendientes y decisiones).
3. `docs/REFERENCES.md` (hallazgos y rutas verificadas del firewall).
4. `alfil-mcp/README.md` si cambia el MCP, y `docs/DESARROLLO.md` si cambia la arquitectura.
5. La fecha de «Última actualización» de esta guía.
