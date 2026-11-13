"""Comparación entre dos reportes de auditoría de la misma conexión. Función pura sobre los dicts de reporte."""
from __future__ import annotations

from typing import Any

RULE_FIELDS = ("status", "action", "log_traffic", "source_zones", "destination_zones", "source_networks", "destination_networks", "services")
SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _issue_key(i: dict) -> tuple:
    # El título lleva el nombre del objeto afectado; «host(s) sin uso» cambia de número, así que se normaliza el prefijo numérico
    title = i.get("title", "")
    if "host(s) sin uso" in title or title.startswith("Host sin uso en reglas"):  # también el formato anterior (un hallazgo por host)
        title = "host(s) sin uso en reglas ni NAT"
    return (i.get("category", ""), title)


def _brief(i: dict) -> dict:
    return {"severity": i.get("severity", "info"), "category": i.get("category", ""), "title": i.get("title", ""), "recommendation": i.get("recommendation", "")}


def _sorted(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda i: (SEV_ORDER.get(i["severity"], 9), i["title"]))


def _rules(report: dict) -> dict[str, dict]:
    return {r.get("name"): r for r in report.get("sections", {}).get("firewall_rules", {}).get("data", []) if isinstance(r, dict) and r.get("name")}


def diff_reports(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """`old` = línea base, `new` = auditoría actual. Devuelve hallazgos nuevos/resueltos/persistentes, cambios de reglas y de topología."""
    old_issues = {_issue_key(i): i for i in old.get("issues", [])}
    new_issues = {_issue_key(i): i for i in new.get("issues", [])}
    appeared = _sorted([_brief(v) for k, v in new_issues.items() if k not in old_issues])
    resolved = _sorted([_brief(v) for k, v in old_issues.items() if k not in new_issues])
    persisting = _sorted([_brief(v) for k, v in new_issues.items() if k in old_issues])
    changed_sev = [{**_brief(new_issues[k]), "was": old_issues[k].get("severity")} for k in new_issues
                   if k in old_issues and new_issues[k].get("severity") != old_issues[k].get("severity")]

    o_rules, n_rules = _rules(old), _rules(new)
    rules_changed = []
    for name in sorted(set(o_rules) & set(n_rules)):
        diffs = {f: {"antes": o_rules[name].get(f), "ahora": n_rules[name].get(f)} for f in RULE_FIELDS if o_rules[name].get(f) != n_rules[name].get(f)}
        if diffs:
            rules_changed.append({"name": name, "changes": diffs})
    o_order = [n for n in o_rules if n in n_rules]
    n_order = [n for n in n_rules if n in o_rules]
    reordered = o_order != n_order

    o_topo = {n["id"]: n for n in (old.get("topology") or {}).get("nodes", [])}
    n_topo = {n["id"]: n for n in (new.get("topology") or {}).get("nodes", [])}
    o_score, n_score = old.get("summary", {}).get("score"), new.get("summary", {}).get("score")
    return {
        "score": {"before": o_score, "after": n_score, "delta": (n_score - o_score) if isinstance(o_score, int) and isinstance(n_score, int) else None},
        "counts": {"new": len(appeared), "resolved": len(resolved), "persisting": len(persisting)},
        "issues": {"new": appeared, "resolved": resolved, "persisting": persisting, "severity_changed": changed_sev},
        "rules": {"added": sorted(set(n_rules) - set(o_rules)), "removed": sorted(set(o_rules) - set(n_rules)), "changed": rules_changed, "reordered": reordered},
        "topology": {"added": sorted(n_topo[i]["label"] for i in set(n_topo) - set(o_topo)), "removed": sorted(o_topo[i]["label"] for i in set(o_topo) - set(n_topo))},
        "notes": ["Los hallazgos se comparan por categoría y título; si cambia el nombre de un objeto aparece como resuelto + nuevo.",
                  "Compara la configuración recolectada en cada auditoría, no el estado en vivo entre ambas."],
    }
