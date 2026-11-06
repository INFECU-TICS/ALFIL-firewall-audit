"""Lectura del grafo de topología de ALFIL: resumen compacto y explicación de la ruta de un flujo.

Trabaja sobre el grafo (`nodes`/`edges`) que construye el backend de ALFIL con la configuración del firewall. Es
**topología de configuración**: no hay ruteo dinámico (OSPF/BGP/RIP) ni rutas aprendidas. Funciones puras, sin red.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from .rules import _names, is_any

DYNAMIC_NOTE = ("Basado en la configuración: no incluye ruteo dinámico (OSPF/BGP/RIP) ni rutas aprendidas, "
                "ni NAT/DNAT ni SD-WAN.")
MAX_RULES = 20


def _zone_name(node_id: str | None) -> str | None:
    return node_id[len("zone:"):] if node_id and node_id.startswith("zone:") else None


class _Index:
    def __init__(self, graph: dict[str, Any]):
        self.nodes = {n["id"]: n for n in graph.get("nodes", [])}
        self.edges = graph.get("edges", [])
        self.meta = graph.get("meta", {})

    def incoming(self, node_id: str, kind: str) -> list[dict[str, Any]]:
        return [e for e in self.edges if e["target"] == node_id and e["kind"] == kind]

    def of_type(self, type_: str) -> list[dict[str, Any]]:
        return [n for n in self.nodes.values() if n["type"] == type_]

    def interface_of_network(self, net_id: str) -> str | None:
        for e in self.incoming(net_id, "connected"):
            node = self.nodes.get(e["source"])
            if node and node["type"] == "interface":
                return node["label"]
        return None


def _cidr(node_id: str) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.ip_network(node_id.split(":", 1)[1], strict=False)
    except (ValueError, IndexError):
        return None


def _router_exit(ix: _Index, router_id: str) -> dict[str, Any]:
    """Zona e interfaz de salida de un router de salto (la red conectada donde vive)."""
    router = ix.nodes.get(router_id, {})
    interface = None
    for e in ix.incoming(router_id, "gateway"):
        src = ix.nodes.get(e["source"])
        if src and src["type"] == "network":
            interface = ix.interface_of_network(src["id"])
    return {"via": router.get("label"), "zone": _zone_name(router.get("parent")), "interface": interface,
            "unreachable": bool(router.get("data", {}).get("unreachable"))}


def resolve_ip(graph: dict[str, Any], ip: str) -> dict[str, Any]:
    """Dónde cae una IP según la configuración: red conectada, ruta estática, VPN, descarte o ruta por defecto.

    Gana el prefijo más largo; a igual prefijo, la red conectada.
    """
    ix = graph if isinstance(graph, _Index) else _Index(graph)
    addr = ipaddress.ip_address(ip.strip())
    if addr.version != 4:
        raise ValueError("Solo se admiten direcciones IPv4.")

    candidates: list[tuple[int, int, dict[str, Any]]] = []  # (prefijo, prioridad, resultado)
    for n in ix.of_type("network"):
        net = _cidr(n["id"])
        if net and addr in net:
            candidates.append((net.prefixlen, 2, {
                "kind": "connected", "network": str(net), "zone": _zone_name(n.get("parent")),
                "interface": ix.interface_of_network(n["id"])}))
    for n in ix.of_type("remote_network"):
        net = _cidr(n["id"])
        if not net or addr not in net or net.prefixlen == 0:
            continue
        for e in ix.incoming(n["id"], "route"):
            src = ix.nodes.get(e["source"], {})
            if src.get("type") == "router":
                candidates.append((net.prefixlen, 1, {"kind": "route", "network": str(net), "route": e.get("label"),
                                                      "distance": e.get("data", {}).get("distance"), **_router_exit(ix, src["id"])}))
            elif src.get("type") == "remote_site":
                tunnels = [ix.nodes[t["source"]]["label"] for t in ix.incoming(src["id"], "vpn") if t["source"] in ix.nodes]
                candidates.append((net.prefixlen, 1, {"kind": "vpn", "network": str(net), "zone": "VPN", "site": src["label"],
                                                      "tunnel": tunnels[0] if tunnels else None}))
            elif src.get("type") == "interface":
                candidates.append((net.prefixlen, 1, {"kind": "route", "network": str(net), "route": e.get("label"),
                                                      "zone": _zone_name(src.get("parent")), "interface": src["label"], "via": None}))
    for n in ix.of_type("blackhole"):
        net = _cidr(n["id"])
        if net and addr in net:
            candidates.append((net.prefixlen, 1, {"kind": "blackhole", "network": str(net)}))
    if candidates:
        return max(candidates, key=lambda c: (c[0], c[1]))[2]

    for e in ix.edges:  # ruta por defecto
        if e["kind"] == "route" and e["target"] == "internet" and ix.nodes.get(e["source"], {}).get("type") == "router":
            return {"kind": "default", "network": "0.0.0.0/0", "route": e.get("label"), **_router_exit(ix, e["source"])}
    for n in ix.of_type("router"):  # sin ruta por defecto explícita: gateway de una interfaz WAN
        if n.get("data", {}).get("gateway") and "internet" in ix.nodes:
            return {"kind": "default", "network": "0.0.0.0/0", "route": "gateway de la interfaz WAN", **_router_exit(ix, n["id"])}
    return {"kind": "unknown"}


def _describe(role: str, ip: str, loc: dict[str, Any]) -> str:
    k = loc["kind"]
    if k == "connected":
        return f"{role} {ip}: red conectada {loc['network']} (zona {loc['zone']}, interfaz {loc['interface'] or '?'})."
    if k == "route":
        via = f" por el salto {loc['via']}" if loc.get("via") else ""
        return f"{role} {ip}: ruta estática {loc['network']}{via} (zona {loc.get('zone') or '?'}, interfaz {loc.get('interface') or '?'})."
    if k == "vpn":
        return f"{role} {ip}: red remota {loc['network']} del túnel VPN {loc.get('tunnel') or '?'} (sitio {loc['site']})."
    if k == "default":
        if role == "Origen":
            return f"{role} {ip}: no coincide con ninguna red conocida; se asume externo, con entrada por la zona {loc.get('zone') or '?'} (ruta por defecto)."
        return f"{role} {ip}: no coincide con ninguna red conocida; sale por la ruta por defecto vía {loc.get('via') or '?'} (zona {loc.get('zone') or '?'})."
    if k == "blackhole":
        return f"{role} {ip}: ruta blackhole {loc['network']}: el tráfico se descarta."
    return f"{role} {ip}: no coincide con ninguna red ni ruta y no hay ruta por defecto."


def explain_path(graph: dict[str, Any], source_ip: str, destination_ip: str, rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Explica por dónde pasaría un flujo origen→destino según la topología de configuración."""
    ix = _Index(graph)
    src, dst = resolve_ip(ix, source_ip), resolve_ip(ix, destination_ip)
    steps = [_describe("Origen", source_ip, src), _describe("Destino", destination_ip, dst)]
    findings: list[dict[str, str]] = []

    src_zone, dst_zone = src.get("zone"), dst.get("zone")
    if src["kind"] == "default":
        findings.append({"severity": "info", "message": f"Supuesto: el origen no está en ninguna red conocida, así que se trata como externo "
                         f"que entra por la zona {src_zone or '?'}. Si llega por una ruta o VPN que no está configurada aquí, la zona sería otra."})
    elif src["kind"] == "unknown":
        findings.append({"severity": "info", "message": "El origen no pertenece a ninguna red conocida y no hay ruta por defecto: la zona de entrada no se puede determinar."})
    if dst["kind"] == "blackhole":
        findings.append({"severity": "critical", "message": f"El destino cae en una ruta blackhole ({dst['network']}): el firewall descarta el tráfico."})
    if dst["kind"] == "unknown":
        findings.append({"severity": "critical", "message": "No hay ruta hacia el destino (sin red conectada, ruta estática ni ruta por defecto)."})
    for loc, role in ((src, "origen"), (dst, "destino")):
        if loc.get("unreachable"):
            findings.append({"severity": "critical", "message": f"La ruta del {role} usa el salto {loc['via']}, que no está en ninguna red conectada del firewall."})

    if dst["kind"] == "connected" and src["kind"] == "connected" and src.get("interface") == dst.get("interface"):
        verdict = "Mismo segmento: el tráfico no pasa por el firewall (no se evalúan reglas)."
    elif src_zone and dst_zone:
        verdict = f"Flujo {src_zone} → {dst_zone}" + (" (intrazona)" if src_zone == dst_zone else "") + ": se evalúan las reglas de firewall de ese par de zonas."
    elif dst_zone:
        verdict = f"Zona de destino: {dst_zone}; la zona de entrada no se puede determinar."
    else:
        verdict = "No se puede determinar el par de zonas con la configuración disponible."

    out: dict[str, Any] = {"source": {"ip": source_ip, **src}, "destination": {"ip": destination_ip, **dst},
                           "source_zone": src_zone, "destination_zone": dst_zone, "steps": steps, "verdict": verdict,
                           "findings": findings, "notes": [DYNAMIC_NOTE]}
    if rules is not None and src_zone and dst_zone:
        out["candidate_rules"], out["candidate_rules_note"] = candidate_rules(rules, src_zone, dst_zone)
    return out


def candidate_rules(rules: list[dict[str, Any]], src_zone: str, dst_zone: str) -> tuple[list[dict[str, Any]], str]:
    """Reglas habilitadas que podrían aplicar por zonas, en el orden del firewall (la primera que coincida gana)."""
    def zone_match(selector: Any, zone: str) -> bool:
        return is_any(selector) or zone in _names(selector)

    found = []
    for pos, r in enumerate(rules, start=1):
        if r.get("enabled") is False:
            continue
        if zone_match(r.get("sourceZones"), src_zone) and zone_match(r.get("destinationZones"), dst_zone):
            found.append({"position": pos, "name": r.get("name"), "action": r.get("action"), "logTraffic": r.get("logTraffic"),
                          "sourceNetworks": r.get("sourceNetworks"), "destinationNetworks": r.get("destinationNetworks"),
                          "servicesOrGroups": r.get("servicesOrGroups")})
    note = ("Candidatas por zona y orden del firewall; NO se evaluaron redes, servicios, usuarios ni NAT: "
            "revise cada una (puede haber más de un acierto, gana la primera que coincide por completo).")
    if len(found) > MAX_RULES:
        note += f" Se muestran las primeras {MAX_RULES} de {len(found)}."
    return found[:MAX_RULES], note


def summarize(graph: dict[str, Any]) -> dict[str, Any]:
    """Resumen legible: zonas con sus interfaces, rutas, VPN, advertencias y notas."""
    ix = _Index(graph)
    zones = []
    for z in ix.of_type("zone"):
        ifaces = []
        for n in ix.of_type("interface"):
            if n.get("parent") != z["id"]:
                continue
            d = n.get("data", {})
            nets = [ix.nodes[e["target"]]["label"] for e in ix.edges if e["source"] == n["id"] and e["kind"] == "connected" and e["target"] in ix.nodes]
            item = {"name": n["label"], "kind": d.get("kind"), "ip": d.get("ip") or None, "networks": nets, "up": d.get("up")}
            if d.get("vlan_id") not in (None, ""):
                item["vlan_id"] = d["vlan_id"]
            if d.get("kind") == "vlan" and d.get("parent_interface"):
                item["parent_interface"] = d["parent_interface"]
            ifaces.append(item)
        zones.append({"zone": z["label"], "role": z.get("data", {}).get("role"), "interfaces": ifaces})
    routes = []
    for e in ix.edges:
        if e["kind"] != "route":
            continue
        src, dst = ix.nodes.get(e["source"], {}), ix.nodes.get(e["target"], {})
        if src.get("type") == "router":
            routes.append({"destination": "0.0.0.0/0" if dst.get("type") == "internet" else dst.get("label"), "via": src.get("label"),
                           "name": e.get("label"), "distance": e.get("data", {}).get("distance"), "unreachable": bool(src.get("data", {}).get("unreachable"))})
        elif src.get("type") == "interface":
            routes.append({"destination": dst.get("label"), "interface": src.get("label"), "name": e.get("label")})
    for n in ix.of_type("blackhole"):
        routes.append({"destination": n["id"].split(":", 1)[1], "action": "descartar"})
    vpns = []
    for t in ix.of_type("vpn_tunnel"):
        d = t.get("data", {})
        site = next((ix.nodes[e["target"]] for e in ix.edges if e["source"] == t["id"] and e["kind"] == "vpn" and ix.nodes.get(e["target"], {}).get("type") == "remote_site"), None)
        remote = [ix.nodes[e["target"]]["label"] for e in ix.edges if site and e["source"] == site["id"] and e["kind"] == "route" and e["target"] in ix.nodes]
        vpns.append({"name": t["label"], "enabled": d.get("enabled"), "type": d.get("connection_type"), "remote_gateway": site["label"] if site else None,
                     "local_networks": d.get("local_networks"), "remote_networks": remote})
    return {"firewall": ix.nodes.get("fw", {}).get("label"), "zones": zones, "routes": routes, "vpn_tunnels": vpns,
            "warnings": ix.meta.get("warnings", []), "notes": ix.meta.get("notes") or [DYNAMIC_NOTE]}
