"""Lecturas derivadas de un reporte guardado: hallazgos por nodo de la topología y matriz zona→zona. Funciones puras."""
from __future__ import annotations

from typing import Any

SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}
FIREWALL_NODE = "fw"
ANY = "Any"


def _zone_node(name: str) -> str:
    return f"zone:{name}"


def findings_by_node(issues: list[dict], rules: list[dict], topology_nodes: list[dict], topology_warnings: list[dict] | None = None) -> dict[str, list[dict]]:
    """Asigna cada hallazgo al nodo que mejor lo representa: la zona (acceso desde WAN, reglas con zonas concretas) o el firewall."""
    nodes = {n["id"] for n in topology_nodes}
    zones_of_rule = {r.get("name"): [z for z in (r.get("source_zones") or []) + (r.get("destination_zones") or []) if z and z != ANY] for r in rules}
    out: dict[str, list[dict]] = {}

    def put(node: str, issue: dict) -> None:
        target = node if node in nodes else FIREWALL_NODE
        item = {"severity": issue.get("severity", "info"), "title": issue.get("title", ""), "category": issue.get("category", ""),
                "recommendation": issue.get("recommendation", "")}
        if item not in out.setdefault(target, []):
            out[target].append(item)

    for issue in issues or []:
        cat, ref = issue.get("category", ""), issue.get("reference", "")
        if cat == "device_access" and ref:
            put(_zone_node(ref), issue)
        elif cat in ("firewall_rules", "nat_rules") and zones_of_rule.get(ref):
            for z in dict.fromkeys(zones_of_rule[ref]):
                put(_zone_node(z), issue)
        else:
            put(FIREWALL_NODE, issue)
    for w in topology_warnings or []:  # advertencias del propio grafo (interfaz sin zona, salto inalcanzable…)
        if w.get("node"):
            put(w["node"], {"severity": w.get("severity", "warning"), "title": w.get("message", ""), "category": "topology"})
    for items in out.values():
        items.sort(key=lambda i: SEV_ORDER.get(i["severity"], 9))
    return out


def zone_matrix(rules: list[dict], zone_names: list[str]) -> dict[str, Any]:
    """Qué reglas habilitadas permiten o bloquean tráfico entre cada par de zonas (origen en filas, destino en columnas).

    «Any» se expande a todas las zonas conocidas. `permissive` marca celdas con una regla accept sin restricción de redes ni servicios.
    No evalúa orden ni sombreado entre reglas: es un mapa de cobertura, no un veredicto.
    """
    named = [z for r in rules for z in (r.get("source_zones") or []) + (r.get("destination_zones") or []) if z and z != ANY]
    zones = list(dict.fromkeys([z for z in zone_names if z] + named))  # también las zonas que solo aparecen en reglas
    cells: dict[str, dict[str, Any]] = {}
    for r in rules:
        if str(r.get("status", "")).lower() not in ("enable", "enabled", "true"):
            continue
        action = str(r.get("action", "")).lower()
        kind = "accept" if action == "accept" else "deny" if action in ("drop", "reject") else None
        if not kind:
            continue
        src = zones if (not r.get("source_zones") or ANY in r["source_zones"]) else r["source_zones"]
        dst = zones if (not r.get("destination_zones") or ANY in r["destination_zones"]) else r["destination_zones"]
        wide = kind == "accept" and all(ANY in (r.get(k) or [ANY]) or not r.get(k) for k in ("source_networks", "destination_networks", "services"))
        no_log = str(r.get("log_traffic", "")).lower() in ("disable", "disabled", "")
        for s in src:
            for d in dst:
                c = cells.setdefault(f"{s}|{d}", {"accept": 0, "deny": 0, "permissive": False, "no_log": 0, "rules": []})
                c[kind] += 1
                c["permissive"] = c["permissive"] or wide
                c["no_log"] += 1 if (kind == "accept" and no_log) else 0
                if r.get("name") and len(c["rules"]) < 8:
                    c["rules"].append({"name": r["name"], "action": kind})
    for s in zones:
        for d in zones:
            cells.setdefault(f"{s}|{d}", {"accept": 0, "deny": 0, "permissive": False, "no_log": 0, "rules": []})
    return {"zones": zones, "cells": cells,
            "notes": ["Solo reglas habilitadas con acción accept/drop/reject. «Any» se expande a todas las zonas.",
                      "No evalúa el orden ni el sombreado entre reglas; una celda sin reglas cae en el descarte implícito del equipo."]}
