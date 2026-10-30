"""Regenera docs/API_V23_INVENTORY.md desde alfil-mcp/spec/openapi.yaml (requiere PyYAML)."""
import collections
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
d = yaml.load((ROOT / "alfil-mcp/spec/openapi.yaml").open(encoding="utf8"), Loader=yaml.CSafeLoader)
tagdesc = {t["name"]: t.get("description", "") for t in d["tags"]}
rows = collections.defaultdict(list); meth = collections.Counter(); nogetpost = []
for path, item in d["paths"].items():
    for m in ("get", "post", "put", "patch", "delete"):
        if m in item:
            op = item[m]; meth[m.upper()] += 1
            tag = (op.get("tags") or ["(sin tag)"])[0]
            rows[tag].append((path, m.upper(), op.get("operationId", ""), (op.get("summary") or "").replace("|", "\\|")))
L = []
L += ["# Inventario API – Sophos Firewall Configuration API v1 (v23)", "",
 "> Generado desde `alfil-mcp/spec/openapi.yaml`, spec OpenAPI 3.0.0 v1.0.0 extraída del firewall v23 activo (guía de API integrada). **No editar a mano**: regenerar con `alfil-mcp/scripts/gen_inventory.py`.", "",
 "## Convenciones", "",
 "- Base URL: `https://<host>:<puerto>/api/firewall-config/v1` (puerto 4444 en el equipo de pruebas).",
 "- Auth: `Authorization: Bearer <api-key>` (esquema `apiKey`, http bearer). Claves en *Administration › API access*.",
 "- Objetos: GET/PATCH/DELETE por `{idOrName}` (nombre único o UUID); en POST el nombre es obligatorio. Formatos `sfos-object-name` (sin comas, `;`, espacios en extremos, nunca un UUID) y `sfos-object-name-or-id`.",
 "- PATCH = JSON Merge Patch (RFC 7396): lo omitido se conserva, `null` elimina; la doc de cada operación puede variar (arrays reemplazados, listas `add`/`remove`). En `oneOf` basta enviar la rama nueva.",
 "- Listados: query `page` (default 1), `pageSize` (default 50, máx 100), `pageTotal` (bool), filtros `nameContains` / `nameNotEquals` (mutuamente excluyentes). Respuesta `{items, pages}`.",
 "- Códigos documentados en listados: 200, 400, 401, 403, 500. Rutas inexistentes en el equipo devuelven 404 HTML.",
 "", "## Resumen", "",
 f"- Paths: {len(d['paths'])} · Operaciones: {sum(meth.values())} · Tags: {len(rows)}",
 "- Por método: " + ", ".join(f"{k} {v}" for k, v in sorted(meth.items())),
 "- Fase 1 del MCP (solo lectura) usa únicamente las operaciones GET.", "", "## Operaciones por tag", ""]
for tag in sorted(rows):
    L += [f"### {tag}", ""]
    if tagdesc.get(tag): L += [tagdesc[tag], ""]
    L += ["| Método | Ruta | operationId | Resumen |", "|---|---|---|---|"]
    for p, m, o, s in sorted(rows[tag]): L.append(f"| {m} | `{p}` | `{o}` | {s} |")
    L.append("")
(ROOT / "docs/API_V23_INVENTORY.md").write_text("\n".join(L), encoding="utf8")
