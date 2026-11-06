"""¿Qué regla de firewall decide un flujo? Evaluación de reglas IPv4 (JSON v23) contra un flujo concreto.

Cada criterio devuelve verdadero, falso o ``None`` (no se puede decidir con los datos de la API: FQDN, país, MAC,
identidad de usuario, horario, objetos desconocidos). Una regla solo «coincide» si **todos** sus criterios son
verdaderos; si alguno es ``None`` y ninguno es falso, queda «posible». No evalúa NAT ni inspección (web, IPS, apps).
Funciones puras, sin red.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from .rules import is_any

MATCH, NO_MATCH, POSSIBLE = "coincide", "no_coincide", "posible"
CRITERIA = ("zonas_origen", "zonas_destino", "red_origen", "red_destino", "servicio")
_NET_KEYS_EVALUABLE = ("ipv4Addresses", "ipv4Groups")
_NET_KEYS_UNKNOWN = ("fqdnAddresses", "fqdnGroups", "countries", "countryGroups", "macAddresses")
ALL_TIME = {"all the time", "all time", "alltime"}


def _names(items: Any) -> list[str]:
    return [i["name"] for i in items or [] if isinstance(i, dict) and isinstance(i.get("name"), str)]


class Objects:
    """Índices de hosts, grupos de hosts, servicios y grupos de servicios por nombre."""

    def __init__(self, hosts=(), host_groups=(), services=(), service_groups=()):
        self.hosts = {h.get("name"): h for h in hosts}
        self.host_groups = {g.get("name"): g for g in host_groups}
        self.services = {s.get("name"): s for s in services}
        self.service_groups = {g.get("name"): g for g in service_groups}


def _host_contains(host: dict[str, Any], ip: ipaddress.IPv4Address) -> bool | None:
    try:
        t = host.get("type")
        if t == "ipv4Address":
            return ip == ipaddress.ip_address(host["ipv4Address"])
        if t == "ipv4Network":
            return ip in ipaddress.ip_network(f"{host['ipv4NetworkAddress']}/{int(host['cidr'])}", strict=False)
        if t == "ipv4Range":
            return ipaddress.ip_address(host["ipv4AddressStart"]) <= ip <= ipaddress.ip_address(host["ipv4AddressEnd"])
        if t == "ipv4List":
            return any(ip == ipaddress.ip_address(a if isinstance(a, str) else a.get("ipv4Address")) for a in host.get("ipv4Addresses") or [])
    except (KeyError, TypeError, ValueError):
        return None
    return None


def _or(values: list[bool | None]) -> bool | None:
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


def network_match(selector: Any, ip: ipaddress.IPv4Address, objs: Objects) -> bool | None:
    """¿La IP cae en la selección de redes de la regla?"""
    if is_any(selector):
        return True
    results: list[bool | None] = []
    for name in _names(selector.get("ipv4Addresses")):
        host = objs.hosts.get(name)
        results.append(_host_contains(host, ip) if host else None)
    for name in _names(selector.get("ipv4Groups")):
        group = objs.host_groups.get(name)
        if not group:
            results.append(None)
            continue
        members = [objs.hosts.get(m) for m in _names(group.get("ipv4Addresses"))]
        results.append(_or([_host_contains(m, ip) if m else None for m in members]))
    for key in _NET_KEYS_UNKNOWN:
        if selector.get(key):
            results.append(None)
    return _or(results) if results else False


def _port_ok(port_range: Any, port: int | None) -> bool | None:
    if not port_range:
        return True  # sin restricción de puerto
    if port is None:
        return None
    try:
        low, high = int(port_range.get("from")), int(port_range.get("to", port_range.get("from")))
    except (AttributeError, TypeError, ValueError):
        return None
    return low <= port <= high


def _service_entry_match(entry: dict[str, Any], protocol: str, port: int | None) -> bool | None:
    if "protocol" in entry:  # tcp/udp con puertos
        if str(entry["protocol"]).lower() != protocol:
            return False
        return _port_ok(entry.get("destinationPort"), port)
    if "ipProtocol" in entry:
        return str(entry["ipProtocol"]).lower() == protocol
    return None


def _service_match(name: str, protocol: str, port: int | None, objs: Objects) -> bool | None:
    svc = objs.services.get(name)
    if not svc:
        return None
    entries = svc.get("services") or []
    if not entries:
        return None
    if svc.get("type") in ("icmp", "icmpv6"):
        return protocol in ("icmp", "icmpv6") and (protocol == svc.get("type"))
    return _or([_service_entry_match(e, protocol, port) for e in entries if isinstance(e, dict)])


def services_match(selector: Any, protocol: str, port: int | None, objs: Objects) -> bool | None:
    if is_any(selector):
        return True
    results = [_service_match(n, protocol, port, objs) for n in _names(selector.get("services"))]
    for gname in _names(selector.get("serviceGroups")):
        group = objs.service_groups.get(gname)
        results.append(_or([_service_match(n, protocol, port, objs) for n in _names(group.get("services"))]) if group else None)
    return _or(results) if results else False


def _zone_match(selector: Any, zone: str | None) -> bool | None:
    if is_any(selector):
        return True
    if not zone:
        return None  # zona desconocida: no se puede decidir
    return zone in _names(selector.get("zones"))


def _excluded(exclusions: Any, flow: dict[str, Any], objs: Objects) -> bool | None:
    """True si el flujo cae en una exclusión de la regla (la regla entonces no aplica)."""
    if not isinstance(exclusions, dict) or not exclusions:
        return False
    checks: list[bool | None] = []
    for key, ip in (("sourceNetworks", flow["src"]), ("destinationNetworks", flow["dst"])):
        sel = exclusions.get(key)
        if isinstance(sel, dict) and any(sel.values()):
            checks.append(network_match({k: v for k, v in sel.items()}, ip, objs))
    sel = exclusions.get("servicesOrGroups")
    if isinstance(sel, dict) and any(sel.values()):
        checks.append(services_match(sel, flow["protocol"], flow["port"], objs))
    for key, zone in (("sourceZones", flow.get("src_zone")), ("destinationZones", flow.get("dst_zone"))):
        sel = exclusions.get(key)
        if isinstance(sel, dict) and any(sel.values()):
            checks.append(_zone_match(sel, zone))
    return _or(checks) if checks else False


def evaluate_rule(rule: dict[str, Any], flow: dict[str, Any], objs: Objects) -> dict[str, Any]:
    """Resultado de una regla: `result` (coincide / no_coincide / posible), `criteria` y `notes`."""
    criteria = {
        "zonas_origen": _zone_match(rule.get("sourceZones"), flow.get("src_zone")),
        "zonas_destino": _zone_match(rule.get("destinationZones"), flow.get("dst_zone")),
        "red_origen": network_match(rule.get("sourceNetworks"), flow["src"], objs),
        "red_destino": network_match(rule.get("destinationNetworks"), flow["dst"], objs),
        "servicio": services_match(rule.get("servicesOrGroups"), flow["protocol"], flow["port"], objs),
    }
    notes: list[str] = []
    excluded = _excluded(rule.get("exclusions"), flow, objs)
    if excluded is True:
        criteria["exclusiones"] = False
    elif excluded is None:
        criteria["exclusiones"] = None
    sched = (rule.get("schedule") or {}).get("name") if isinstance(rule.get("schedule"), dict) else None
    if sched and sched.lower() not in ALL_TIME:
        criteria["horario"] = None
        notes.append(f"La regla usa el horario «{sched}»: no se evalúa la hora.")
    auth = rule.get("userAuthentication")
    if isinstance(auth, dict) and any(v for v in auth.values()):
        criteria["identidad"] = None
        notes.append("La regla depende de usuarios o grupos: no se evalúa la identidad.")
    values = list(criteria.values())
    if any(v is False for v in values):
        result = NO_MATCH
    elif any(v is None for v in values):
        result = POSSIBLE
    else:
        result = MATCH
    return {"result": result, "criteria": criteria, "notes": notes}


def _label(criterion: str, value: bool | None) -> str | None:
    return None if value is True else ("no se puede evaluar con los datos de la API" if value is None else "no coincide")


def explain_rule_match(rules: list[dict[str, Any]], objs: Objects, source_ip: str, destination_ip: str,
                       protocol: str = "tcp", port: int | None = None,
                       src_zone: str | None = None, dst_zone: str | None = None) -> dict[str, Any]:
    """Recorre las reglas habilitadas en orden y devuelve la que decide, las «posibles» anteriores y el porqué."""
    protocol = (protocol or "tcp").strip().lower()
    if port is not None and not 0 < int(port) < 65536:
        raise ValueError(f"Puerto fuera de rango: {port}")
    if port is not None and protocol not in ("tcp", "udp"):
        raise ValueError("El puerto solo aplica a tcp y udp.")
    flow = {"src": ipaddress.IPv4Address(source_ip.strip()), "dst": ipaddress.IPv4Address(destination_ip.strip()),
            "protocol": protocol, "port": int(port) if port is not None else None, "src_zone": src_zone, "dst_zone": dst_zone}

    decided: dict[str, Any] | None = None
    possible_before: list[dict[str, Any]] = []
    why_not: list[dict[str, Any]] = []
    for pos, rule in enumerate(rules, start=1):
        if rule.get("enabled") is False:
            continue
        ev = evaluate_rule(rule, flow, objs)
        summary = {"position": pos, "name": rule.get("name"), "action": rule.get("action"), "logTraffic": rule.get("logTraffic")}
        if decided is None:
            if ev["result"] == MATCH:
                decided = {**summary, "criteria": {k: v for k, v in ev["criteria"].items()}, "notes": ev["notes"]}
                continue
            if ev["result"] == POSSIBLE:
                possible_before.append({**summary, "unknown": [k for k, v in ev["criteria"].items() if v is None], "notes": ev["notes"]})
        zones_ok = ev["criteria"]["zonas_origen"] is not False and ev["criteria"]["zonas_destino"] is not False
        if ev["result"] == NO_MATCH and zones_ok and (src_zone or dst_zone) and (decided is None or summary["position"] < decided["position"]):
            why_not.append({**summary, "failed": {k: _label(k, v) for k, v in ev["criteria"].items() if v is False}})

    findings: list[dict[str, str]] = []
    if not (src_zone and dst_zone):
        findings.append({"severity": "info", "message": "Zonas no indicadas o no deducibles: las reglas con zonas concretas quedan «posibles»."})
    if decided is None:
        verdict = ("Ninguna regla coincide de forma definitiva: el tráfico se descarta por la regla implícita"
                   if not possible_before else "Ninguna regla coincide de forma definitiva; hay reglas que podrían aplicar (ver possible_earlier)")
        findings.append({"severity": "warning" if not possible_before else "info", "message": verdict + "."})
    else:
        verdict = f"Decide la regla #{decided['position']} «{decided['name']}» ({decided['action']})."
        if possible_before:
            findings.append({"severity": "warning", "message": f"{len(possible_before)} regla(s) anterior(es) podrían aplicar y no se pueden descartar "
                             "con los datos de la API; si alguna aplica, decide ella."})
    return {"flow": {"source_ip": source_ip, "destination_ip": destination_ip, "protocol": protocol, "destination_port": port,
                     "source_zone": src_zone, "destination_zone": dst_zone},
            "decision": decided, "possible_earlier": possible_before, "why_not": why_not[:20],
            "verdict": verdict, "findings": findings,
            "limits": "Evalúa zonas, redes, servicios y exclusiones. No evalúa NAT, horarios, usuarios/identidad, FQDN, país, MAC ni inspección (web, IPS, aplicaciones)."}
