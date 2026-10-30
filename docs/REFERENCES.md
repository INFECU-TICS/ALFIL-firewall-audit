# Referencias – Sophos Firewall v23

Fuentes oficiales para consultar información vigente. Verificar siempre contra la guía de API integrada del firewall v23 de pruebas.

| Recurso | URL |
|---|---|
| Sophos Firewall Configuration API (REST, OpenAPI 3.0) | https://docs.sophos.com/nsg/sophos-firewall/rest-api/api/firewall-config-openapi/sophos-firewall-configuration-api/ |
| Anuncio v23 Early Access | https://www.sophos.com/en-us/blog/sophos-firewall-v23-early-access |

## Notas verificadas (2026-10-29)

- Base URL: `https://<firewall>:<puerto>/api/firewall-config/v1` (la doc pública no indica puerto por defecto).
- Autenticación: `Authorization: Bearer <api-key>`; la clave se genera en *Administration › API access*.
- Métodos: GET, POST, PATCH (JSON Merge Patch, RFC 7396; `null` elimina la propiedad), DELETE. No se documenta PUT.
- Objetos identificados por nombre único o UUID.
- La documentación pública indica versión de spec 1.0.0 y no menciona v23; tampoco documenta rate limits ni content-type.
- El blog v23 EA describe una "API REST moderna con autenticación por token y guía de API integrada". No menciona MCP.
- Es Early Access: los endpoints pueden cambiar antes de GA.

## Pendiente de confirmar en el firewall de pruebas

Puerto, content-type, paginación, formato de errores, rutas reales por recurso y comportamiento con certificado autofirmado.

## Rutas verificadas en firewall v23 de pruebas (2026-10-30)

Puerto **4444**, `Authorization: Bearer <key>`, TLS autofirmado, JSON. Prefijo `/api/firewall-config/v1`. Las rutas **no** siguen los slugs de la doc; se descubrieron por prueba (GET → 200).

Listas: `{"items": [...], "pages": {"current": 1, "maxSize": 100, "size": 50}}`. Objetos con `id` (UUID), `name`, `createdAt`, `updatedAt`. Rutas inexistentes → 404 HTML (no JSON).

| Recurso | Ruta |
|---|---|
| Reglas de firewall IPv4 / IPv6 | `/firewall/rules/ipv4`, `/firewall/rules/ipv6` |
| Zonas | `/network/zones` |
| Servicios / grupos de servicios | `/network/services`, `/network/service-groups` |
| Hosts IPv4 / IPv6 / FQDN / MAC | `/network/addresses/ipv4`, `/ipv6`, `/fqdn`, `/mac` |
| Grupos de hosts IPv4 | `/network/address-groups/ipv4` |
| DNS | `/network/dns/settings` |
| Gateways | `/routing/gateways/ipv4` |
| Usuarios / grupos / en vivo | `/authentication/users`, `/user-groups`, `/live-users` |
| Servidores de autenticación | `/authentication/servers` |
| Sistema / portal / schedules / mensajes | `/administration/system-settings`, `/portal-settings`, `/schedules`, `/messages` |
| API settings | `/administration/api-settings` |
| Actualizaciones de seguridad | `/system/security-updates` |

**Spec OpenAPI:** `alfil-mcp/spec/openapi.yaml` (OpenAPI 3.0.0, v1.0.0, ~9 MB), extraída oficialmente del firewall v23 activo (guía de API integrada; el equipo no la sirve por HTTP). Fuente de verdad para rutas. Inventario completo generado: [`API_V23_INVENTORY.md`](API_V23_INVENTORY.md) (390 paths, 708 operaciones: GET 266, POST 212, PATCH 137, DELETE 93; 134 tags). Regenerar: `python3 alfil-mcp/scripts/gen_inventory.py`.

Rutas adicionales según la spec (aún sin probar en el equipo):

| Recurso | Ruta |
|---|---|
| NAT IPv4 / IPv6 | `/nat/rules/ipv4`, `/nat/rules/ipv6` |
| Interfaces | `/network/interfaces/network-interfaces` |
| ACL servicios locales (device access) | `/acl-exception-rules/ipv4`, `/ipv6` |
| Administradores | `/authentication/users/administrators` |
| Perfiles de acceso admin | `/administration/access/profiles` |
| Notificaciones | `/notification/notifications` |
| IPsec | `/ipsec-vpn/site-to-site/connections/ipv4`, `/ipsec-vpn/profiles` |
| Rutas estáticas | `/routing/static-unicast-routes/ipv4` |
| Backup / hotfix | `/system/backup/settings`, `/system/hotfix/settings` |
| Políticas web / apps / TLS | `/web/policies`, `/application/policies`, `/tls-inspection/decryption-profiles` |
| Syslog | `/logging/log-destinations/syslog-servers` |

No se encontró ruta de hora/NTP en la búsqueda parcial; revisar la spec por `time`/`ntp` antes de portar el check de NTP.

## Hallazgos de la spec relevantes para el MCP

- **POST no implica "crear".** 121 paths son solo-POST: acciones como `.../delete` (borrado masivo), `.../move` (reordenar reglas), `.../test-connection`, `fetch-groups`, `fetch-base-dn`, `oidc-discovery`, cambio de contraseña de admin. El guard de fase 1 debe bloquear **todo** verbo distinto de GET (incluidos los `test-connection`, que abren conexiones salientes desde el firewall).
- **Errores:** JSON `{"error": "<codigo>", "message": "...", "code": "..."}` (ej. `badRequest`, `notAuthorized`) con 400/401/403/500. Un 404 de ruta inexistente devuelve HTML.
- **Reglas:** discriminador `ruleType` (`firewall` | `waf`) en reglas IPv4/IPv6.
- **Paginación:** `page`, `pageSize` (máx 100), `pageTotal`; el MCP debe paginar y limitar salida.
- **Servidor por defecto en la spec:** `https://{firewallHost}/api/firewall-config/v1` con `<ip-del-firewall-lab>:4444` (el valor está embebido por el fabricante en el ejemplo; el puerto va dentro de `firewallHost`).
- La spec trae ejemplos con credenciales ficticias (`securepassword`, `NewS3cur3P@ss!`); no son datos reales.

## Validación en vivo (2026-10-30, firewall v23 de laboratorio)

- Se crearon 5 reglas `ALFIL-TEST-*` vía `POST /firewall/rules/ipv4` (201) y se borraron con `DELETE /firewall/rules/ipv4/{name}` (200). El firewall quedó con sus reglas originales.
- `audit_firewall` detectó lo esperado: `RULE_ANY_ANY_ACCEPT`, `RULE_DUPLICATE` (con `duplicateOf`), `RULE_NO_LOGGING`, `RULE_DISABLED`. Score 79 = 100 − 4×5 − 1×1.
- `servicesOrGroups` "cualquiera" se representa como `{"any": true}` (igual que zonas y redes).
- Las referencias a objetos en reglas son `{"name": "..."}`; las reglas aceptan `position: "bottom"` al crear.
- **Las escrituras son lentas:** POST y DELETE de reglas tardan ~20 s cada una. Un cliente de fase 2 necesita timeouts ≥ 120 s, y tras un timeout debe **consultar el estado antes de reintentar** (la regla puede haberse creado igualmente).

## API XML legacy en v23 (2026-10-30)

- Login y consultas funcionan (`APIVersion 2300.1`), endpoint `https://<fw>:4444/webconsole/APIController` (multipart `reqxml`).
- En el laboratorio las consultas XML son lentas (`SystemStatus` 1.6 s, `IPHost` 2.4 s, `Zone` 22 s, `FirewallRule` 50 s). Con timeout 10 s y 12 hilos, 38 de 41 colectores de ALFIL fallan por timeout. Plan en `ESTADO_Y_PENDIENTES.md`.
