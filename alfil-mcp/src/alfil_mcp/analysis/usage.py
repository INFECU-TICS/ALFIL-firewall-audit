"""Dónde se usa cada objeto (hosts, grupos, servicios, zonas, interfaces) y cuáles no se usan en ninguna parte.

Recorre el JSON de reglas de firewall, reglas NAT, grupos de hosts, grupos de servicios y conexiones VPN; toda referencia
`{"name": X}` bajo una clave conocida (`ipv4Addresses`, `services`, `zones`…) cuenta como uso. No evalúa si la regla que lo
usa está habilitada o es efectiva: solo marca las deshabilitadas. Funciones puras, sin red.
"""
from __future__ import annotations

import difflib
from collections import defaultdict
from typing import Any

# Clave del JSON -> tipo de objeto al que apunta
LEAF_KIND = {
    "ipv4Addresses": "host", "ipv4Address": "host", "ipv4Groups": "host_group",
    "fqdnAddresses": "fqdn_host", "fqdnAddress": "fqdn_host", "fqdnGroups": "fqdn_group",
    "macAddresses": "mac_host", "countries": "country", "countryGroups": "country_group",
    "services": "service", "serviceGroups": "service_group", "translatedService": "service",
    "zones": "zone", "interfaces": "interface", "outboundInterface": "interface", "linkedFirewallRule": "firewall_rule",
}
DEFINED_KINDS = ("host", "host_group", "service", "service_group")
GROUP_KINDS = {"host_group": "host_group", "service_group": "service_group"}
MAX_DEPTH = 8


def _walk(value: Any, key: str | None, path: list[str], found: list[tuple[str, str, str]]) -> None:
    if isinstance(value, dict):
        kind = LEAF_KIND.get(key or "")
        if kind and isinstance(value.get("name"), str):
            found.append((kind, value["name"], ".".join(path)))
        for k, v in value.items():
            if k == "name" and kind:
                continue
            _walk(v, k, path + [k], found)
    elif isinstance(value, list):
        for item in value:
            _walk(item, key, path, found)


def references_in(resource: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(tipo, nombre, campo) de cada objeto que referencia un recurso (sin contar su propio `name`)."""
    found: list[tuple[str, str, str]] = []
    for k, v in resource.items():
        if k != "name":
            _walk(v, k, [k], found)
    return found


class UsageIndex:
    def __init__(self, rules=(), nat_rules=(), host_groups=(), service_groups=(), vpn_connections=(), hosts=(), services=()):
        self.defs: dict[tuple[str, str], dict[str, Any]] = {}
        for kind, items in (("host", hosts), ("host_group", host_groups), ("service", services), ("service_group", service_groups)):
            for o in items:
                if isinstance(o.get("name"), str):
                    self.defs[(kind, o["name"])] = o
        self.refs: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for pos, r in enumerate(rules, start=1):
            self._add("firewall_rule", r, {"position": pos, "enabled": r.get("enabled")})
        for pos, r in enumerate(nat_rules, start=1):
            self._add("nat_rule", r, {"position": pos, "enabled": r.get("enabled")})
        for g in host_groups:
            self._add("host_group", g, {})
        for g in service_groups:
            self._add("service_group", g, {})
        for v in vpn_connections:
            self._add("vpn_connection", v, {"enabled": v.get("status") if isinstance(v.get("status"), bool) else None})

    def _add(self, resource_kind: str, resource: dict[str, Any], extra: dict[str, Any]) -> None:
        for kind, name, field in references_in(resource):
            self.refs[(kind, name)].append({"resource": resource_kind, "name": resource.get("name"), "field": field,
                                            **{k: v for k, v in extra.items() if v is not None}})

    # -- uso de un objeto ------------------------------------------------------------------------
    def indirect(self, kind: str, name: str, seen: frozenset = frozenset(), depth: int = 0) -> list[dict[str, Any]]:
        """Usos a través de grupos que contienen el objeto (con la cadena de grupos)."""
        out: list[dict[str, Any]] = []
        if depth >= MAX_DEPTH:
            return out
        for ref in self.refs.get((kind, name), []):
            gkind = ref["resource"]
            if gkind not in GROUP_KINDS or (gkind, ref["name"]) in seen:
                continue
            group = (gkind, ref["name"])
            for use in self.refs.get(group, []):
                if use["resource"] not in GROUP_KINDS:
                    out.append({**use, "via": [ref["name"]]})
            for use in self.indirect(gkind, ref["name"], seen | {(kind, name), group}, depth + 1):
                out.append({**use, "via": [ref["name"], *use["via"]]})
        return out

    def trace(self, name: str, kind: str | None = None) -> dict[str, Any]:
        kinds = {k for (k, n) in [*self.refs, *self.defs] if n == name}
        if kind:
            kinds &= {kind}
        if not kinds:
            known = sorted({n for (_, n) in [*self.refs, *self.defs]})
            raise LookupError(f"No existe ningún objeto «{name}»" + (f" de tipo {kind}" if kind else "") +
                              (f". Nombres parecidos: {', '.join(difflib.get_close_matches(name, known, n=5, cutoff=0.6))}"
                               if difflib.get_close_matches(name, known, n=5, cutoff=0.6) else "."))
        results = []
        for k in sorted(kinds):
            direct = list(self.refs.get((k, name), []))
            members_of = [r for r in direct if r["resource"] in GROUP_KINDS]
            direct_uses = [r for r in direct if r["resource"] not in GROUP_KINDS]
            indirect_uses = self.indirect(k, name)
            effective = [*direct_uses, *indirect_uses]
            notes = []
            if effective and all(u.get("enabled") is False for u in effective):
                notes.append("Todos los usos están en reglas deshabilitadas.")
            if (k, name) in self.defs and not effective:
                notes.append("Definido y sin uso en reglas, NAT ni VPN" + (" (solo pertenece a grupos que tampoco se usan)." if members_of else "."))
            if k not in DEFINED_KINDS:
                notes.append("Tipo sin definición consultada (zona, interfaz…): se muestran solo las referencias.")
            results.append({"kind": k, "defined": (k, name) in self.defs, "in_groups": [r["name"] for r in members_of],
                            "direct_uses": direct_uses, "indirect_uses": indirect_uses,
                            "total_uses": len(effective), "unused": (k, name) in self.defs and not effective, "notes": notes})
        return {"name": name, "matches": results}

    # -- objetos sin uso -------------------------------------------------------------------------
    def effectively_used(self, kind: str, name: str) -> bool:
        return any(u["resource"] not in GROUP_KINDS for u in self.refs.get((kind, name), [])) or bool(self.indirect(kind, name))

    def unused(self, kind: str | None = None, limit: int = 100) -> dict[str, Any]:
        items = []
        for (k, name), obj in sorted(self.defs.items()):
            if kind and k != kind:
                continue
            if obj.get("isInternal") or obj.get("isSystem"):
                continue  # objetos del sistema
            if self.effectively_used(k, name):
                continue
            groups = [r["name"] for r in self.refs.get((k, name), []) if r["resource"] in GROUP_KINDS]
            items.append({"kind": k, "name": name, "reason": "solo_via_grupo_sin_uso" if groups else "sin_referencias", "in_groups": groups})
        counts: dict[str, int] = defaultdict(int)
        for i in items:
            counts[i["kind"]] += 1
        return {"total": len(items), "by_kind": dict(counts), "items": items[:limit], "truncated": len(items) > limit,
                "notes": ["Incluye objetos predefinidos que el equipo no marca como internos (p. ej. servicios estándar): revise antes de borrar.",
                          "Uso = referencia en reglas de firewall, NAT, VPN o grupos usados. No considera objetos usados por otras funciones "
                          "(SD-WAN, políticas web, usuarios, etc.) que esta herramienta no consulta."]}
