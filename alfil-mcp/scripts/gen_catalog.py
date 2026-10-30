"""Genera src/alfil_mcp/data/get_catalog.json (solo operaciones GET) desde spec/openapi.yaml."""
import json
import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = yaml.load((ROOT / "spec/openapi.yaml").open(encoding="utf8"), Loader=yaml.CSafeLoader)

catalog = []
for path, item in spec["paths"].items():
    op = item.get("get")
    if not op:
        continue
    params = [*item.get("parameters", []), *op.get("parameters", [])]
    catalog.append({
        "path": path,
        "operationId": op.get("operationId", ""),
        "tag": (op.get("tags") or [""])[0],
        "summary": op.get("summary", ""),
        "query": sorted({p["name"] for p in params if p.get("in") == "query"}),
    })
catalog.sort(key=lambda e: e["path"])
out = ROOT / "src/alfil_mcp/data/get_catalog.json"
out.write_text(json.dumps(catalog, indent=1, ensure_ascii=False), encoding="utf8")
print(f"{len(catalog)} GET endpoints -> {out}")
