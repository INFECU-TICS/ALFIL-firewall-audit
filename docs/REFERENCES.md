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
