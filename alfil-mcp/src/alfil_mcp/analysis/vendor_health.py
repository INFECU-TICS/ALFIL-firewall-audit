"""Verificación de políticas del propio firewall (`/firewall-health-check/policies`), resumida por severidad y módulo."""
from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "veryLow": 3}


def effective_status(item: dict[str, Any]) -> str:
    """El estado manual (`overriddenStatus`) tiene prioridad sobre el calculado."""
    return str(item.get("overriddenStatus") or item.get("status") or "unknown")


def summarize(items: list[dict[str, Any]], only_noncompliant: bool = True, severity: str | None = None, limit: int = 100) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_severity: dict[str, dict[str, int]] = {}
    for i in items:
        st = effective_status(i)
        by_status[st] = by_status.get(st, 0) + 1
        sev = by_severity.setdefault(str(i.get("severity", "unknown")), {})
        sev[st] = sev.get(st, 0) + 1
    picked = [i for i in items if (not only_noncompliant or effective_status(i) == "nonCompliant") and (not severity or i.get("severity") == severity)]
    picked.sort(key=lambda i: (SEVERITY_ORDER.get(str(i.get("severity")), 9), str(i.get("module", "")), str(i.get("policy", ""))))
    rows = [{"policy": i.get("policy", ""), "key": i.get("policyKey", ""), "module": i.get("module", ""), "severity": i.get("severity", ""),
             "status": effective_status(i), "overridden": bool(i.get("overriddenStatus")), "standards": i.get("standards") or []} for i in picked]
    modules: dict[str, int] = {}
    for r in rows:
        modules[r["module"]] = modules.get(r["module"], 0) + 1
    return {"total": len(items), "by_status": by_status, "by_severity": by_severity, "listed": min(len(rows), limit), "matching": len(rows),
            "by_module": modules, "policies": rows[:limit],
            "notes": ["Es la evaluación del propio firewall (no de ALFIL): cubre las verificaciones de Sophos Firewall Health Check, p. ej. CIS.",
                      "Un estado manual (`overridden`) sustituye al calculado por el equipo."]}
