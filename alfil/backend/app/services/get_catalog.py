"""Rutas GET permitidas de la REST API v23 (catálogo generado desde la spec por alfil-mcp/scripts/gen_catalog.py)."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _patterns() -> list[re.Pattern[str]]:
    catalog = json.loads((Path(__file__).resolve().parent.parent / "data" / "get_catalog.json").read_text(encoding="utf8"))
    # {idOrName} / {name} -> un segmento; el resto es literal
    return [re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(e["path"])) + "$") for e in catalog]


def is_known_get_path(path: str) -> bool:
    if ".." in path or "?" in path or "#" in path or not path.startswith("/"):
        return False
    return any(p.match(path) for p in _patterns())
