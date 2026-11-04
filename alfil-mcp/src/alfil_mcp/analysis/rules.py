"""Análisis de reglas de firewall IPv4 (JSON de /firewall/rules/ipv4, v23).

Funciones puras sobre listas de dicts; lógica portada del auditor XML de ALFIL
(alfil/backend/app/services/audit_service.py) y adaptada al esquema REST.
"""
from __future__ import annotations

from typing import Any

CRITICAL, WARNING, INFO = "critical", "warning", "info"
_PENALTY = {CRITICAL: 15, WARNING: 5, INFO: 1}  # misma fórmula que ALFIL: 100 - 15c - 5w - 1i


def is_any(selector: Any) -> bool:
    """`{"any": true}` => cualquiera (verificado en v23 para zonas, redes y servicios).

    Un selector sin elementos también se trata como 'cualquiera' (criterio defensivo, no verificado en vivo).
    """
    if not isinstance(selector, dict):
        return selector is None
    if selector.get("any") is True:
        return True
    return not any(selector.values())


def _names(selector: Any) -> list[str]:
    """Aplana un selector a una lista ordenada de nombres (acepta str o {"name": ...})."""
    out: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if "name" in value and isinstance(value["name"], str):
                out.append(value["name"])
            else:
                for v in value.values():
                    walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
        elif isinstance(value, str):
            out.append(value)

    walk(selector)
    return sorted(out)


def _finding(severity: str, code: str, rule: dict[str, Any], title: str, **extra: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "rule": rule.get("name"), "ruleId": rule.get("id"), "title": title, **extra}


def is_any_to_any(rule: dict[str, Any]) -> bool:
    """Redes origen/destino y servicios "any" (zonas no cuentan; mismo criterio que la web ALFIL)."""
    return all(is_any(rule.get(k)) for k in ("sourceNetworks", "destinationNetworks", "servicesOrGroups"))


def find_permissive(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _finding(WARNING, "RULE_ANY_ANY_ACCEPT", r, "Regla Any→Any con acción accept")
        for r in rules if r.get("enabled") and r.get("action") == "accept" and is_any_to_any(r)
    ]


def find_without_logging(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _finding(WARNING, "RULE_NO_LOGGING", r, "Regla habilitada sin registro de tráfico")
        for r in rules if r.get("enabled") and not r.get("logTraffic")
    ]


def find_disabled(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _finding(INFO, "RULE_DISABLED", r, "Regla deshabilitada (potencialmente obsoleta)")
        for r in rules if not r.get("enabled")
    ]


def _signature(rule: dict[str, Any]) -> tuple[Any, ...]:
    return (
        rule.get("action"),
        tuple(_names(rule.get("sourceZones"))), tuple(_names(rule.get("destinationZones"))),
        tuple(_names(rule.get("sourceNetworks"))), tuple(_names(rule.get("destinationNetworks"))),
        tuple(_names(rule.get("servicesOrGroups"))),
        is_any(rule.get("sourceZones")), is_any(rule.get("destinationZones")),
        is_any(rule.get("sourceNetworks")), is_any(rule.get("destinationNetworks")),
        is_any(rule.get("servicesOrGroups")),
    )


def find_duplicates(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reglas habilitadas con igual acción, zonas, redes y servicios."""
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    findings = []
    for r in rules:
        if not r.get("enabled"):
            continue
        sig = _signature(r)
        if sig in seen:
            findings.append(_finding(WARNING, "RULE_DUPLICATE", r, "Regla duplicada",
                                     duplicateOf=seen[sig].get("name")))
        else:
            seen[sig] = r
    return findings


def audit_rules(rules: list[dict[str, Any]]) -> dict[str, Any]:
    findings = [*find_permissive(rules), *find_without_logging(rules),
                *find_duplicates(rules), *find_disabled(rules)]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in (CRITICAL, WARNING, INFO)}
    score = max(0, min(100, 100 - sum(_PENALTY[s] * n for s, n in counts.items())))
    return {"score": score, "totalRules": len(rules), "counts": counts, "findings": findings}
