"""Grafo de topología de red a partir de los datos recolectados (mismo formato para el modo XML y el REST).

Es topología **de configuración**: interfaces (físicas, VLAN, LAG, alias), zonas, redes conectadas, rutas estáticas
(con su router de salto), salida a internet y túneles VPN IPsec. El ruteo dinámico (OSPF/BGP/RIP) no se obtiene por la
API de configuración, por lo que no aparece (se avisa en `meta.notes`).

Salida: {"nodes": [...], "edges": [...], "meta": {...}}. Funciones puras, sin red, para poder testearlas.
"""
from __future__ import annotations

import ipaddress
from typing import Any

NO_ZONE = "(sin zona)"
ROLE_KEYWORDS = ("wan", "lan", "dmz", "vpn", "wifi")
DYNAMIC_ROUTING_NOTE = (
    "Topología basada en la configuración. El ruteo dinámico (OSPF/BGP/RIP) y las rutas aprendidas no están "
    "disponibles por la API, por lo que no se dibujan."
)


def _network(ip: str, mask: Any) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.ip_interface(f"{ip}/{mask}").network
    except ValueError:
        return None


def _address(ip: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(ip)
    except ValueError:
        return None


def zone_role(zone_name: str, zone_type: str = "") -> str:
    """lan | wan | dmz | vpn | wifi | other."""
    for candidate in (str(zone_type).lower(), str(zone_name).lower()):
        for role in ROLE_KEYWORDS:
            if role == candidate or (candidate and role in candidate):
                return role
    return "other"


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.warnings: list[dict[str, str]] = []

    def node(self, node_id: str, type_: str, label: str, parent: str | None = None, **data: Any) -> dict[str, Any]:
        if node_id not in self.nodes:
            self.nodes[node_id] = {"id": node_id, "type": type_, "label": label, "parent": parent, "data": data}
        return self.nodes[node_id]

    def edge(self, source: str, target: str, kind: str, label: str = "", dashed: bool = False, **data: Any) -> None:
        edge_id = f"{source}->{target}:{kind}"
        if edge_id not in self.edges:
            self.edges[edge_id] = {"id": edge_id, "source": source, "target": target, "kind": kind,
                                   "label": label, "dashed": dashed, "data": data}

    def warn(self, code: str, message: str, node: str = "", severity: str = "warning") -> None:
        self.warnings.append({"code": code, "severity": severity, "message": message, "node": node})


def _data(raw: dict[str, Any], key: str) -> list[dict[str, Any]]:
    entry = raw.get(key) or {}
    data = entry.get("data") if isinstance(entry, dict) else None
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def _failed(raw: dict[str, Any], key: str) -> str | None:
    entry = raw.get(key) or {}
    if isinstance(entry, dict) and entry.get("success") is False:
        return str(entry.get("error", "no disponible"))
    return None


def _host_cidrs(hosts: list[dict[str, Any]]) -> dict[str, str]:
    """Nombre de objeto de host -> CIDR (para resolver redes de VPN que vienen como nombres)."""
    out: dict[str, str] = {}
    for h in hosts:
        name, kind = h.get("name", ""), str(h.get("type", "")).lower()
        ip, mask = h.get("ip_address", ""), h.get("subnet", "")
        if not name or not ip:
            continue
        net = _network(ip, mask) if kind == "network" and mask else (_network(ip, 32) if kind == "ip" else None)
        if net:
            out[name] = str(net)
    return out


def build_topology(raw: dict[str, Any], connection_info: dict[str, Any] | None = None) -> dict[str, Any]:
    g = _Graph()
    info = connection_info or {}

    admin = (raw.get("admin_settings") or {}).get("data") or {}
    hostname = (admin.get("HostnameSettings") or {}).get("HostName") or info.get("name") or "Firewall"
    g.node("fw", "firewall", hostname, role="firewall")

    # -- Zonas (contenedores) --------------------------------------------------------------------
    zones = {z.get("name", ""): z.get("type", "") for z in _data(raw, "zones") if z.get("name")}

    def zone_group(name: str) -> str:
        zname = name or NO_ZONE
        g.node(f"zone:{zname}", "zone", zname, role=zone_role(zname, zones.get(zname, "")), zone_type=zones.get(zname, ""))
        return f"zone:{zname}"

    for name in zones:
        zone_group(name)

    # -- Interfaces: físicas/bridge, VLAN y LAG (las VLAN se dibujan como interfaces más) --------
    interfaces: list[tuple[str, dict[str, Any]]] = []
    interfaces += [("physical" if str(i.get("type", "physical")) == "physical" else str(i.get("type")), i) for i in _data(raw, "interfaces")]
    interfaces += [("vlan", v) for v in _data(raw, "vlans")]
    interfaces += [("lag", lag) for lag in _data(raw, "lags")]

    connected: list[tuple[ipaddress.IPv4Network, str, str]] = []  # (red, id del nodo de red, nombre de interfaz)
    if_zone: dict[str, str] = {}
    wan_networks: list[tuple[str, str]] = []  # (id de red, IP del gateway)

    def attach_network(if_id: str, if_name: str, zone_id: str, ip: str, mask: Any, via: str = "") -> ipaddress.IPv4Network | None:
        net = _network(ip, mask) if ip else None
        if not net:
            return None
        net_id = f"net:{net}"
        g.node(net_id, "network", str(net), parent=zone_id, role=g.nodes[zone_id]["data"]["role"])
        g.edge(if_id, net_id, "connected", via)  # la IP ya se muestra en la interfaz; solo se etiqueta "alias"
        connected.append((net, net_id, if_name))
        return net

    for kind, i in interfaces:
        name = i.get("name", "")
        if not name:
            continue
        zone_name = i.get("zone", "") or ""
        zid = zone_group(zone_name)
        if_zone[name] = zid
        ip, mask = i.get("ip_address", "") or "", i.get("netmask", "")
        status = str(i.get("interface_status", "")).upper()
        node = g.node(f"if:{name}", "interface", name, parent=zid, kind=kind, ip=ip, netmask=mask, zone=zone_name,
                      vlan_id=i.get("vlan_id", ""), parent_interface=i.get("interface", "") if kind == "vlan" else "",
                      members=i.get("members", []), hardware=i.get("hardware", ""), up=status in ("ON", "UP", "CONNECTED"),
                      unconfigured=not zone_name and not ip)
        g.edge("fw", node["id"], "interface", f"VLAN {i.get('vlan_id')}" if kind == "vlan" else "")
        net = attach_network(node["id"], name, zid, ip, mask)
        if ip and not zone_name:
            g.warn("interface_without_zone", f"La interfaz {name} tiene IP ({ip}) pero no pertenece a ninguna zona.", node["id"])
        if net and g.nodes[zid]["data"]["role"] == "wan":
            wan_networks.append((f"net:{net}", str(i.get("gateway_ip", "") or "")))

    for a in _data(raw, "aliases"):  # IP secundarias: red adicional colgada de la interfaz padre
        parent = f"if:{a.get('interface', '')}"
        if parent in g.nodes:
            attach_network(parent, a.get("interface", ""), g.nodes[parent]["parent"], a.get("ip_address", ""), a.get("netmask", ""), "alias")

    # -- Internet / gateways WAN ----------------------------------------------------------------
    if wan_networks:
        g.node("internet", "internet", "Internet", role="wan")
        for net_id, gateway_ip in wan_networks:
            if gateway_ip:
                zid = g.nodes[net_id]["parent"]
                g.node(f"rt:{gateway_ip}", "router", gateway_ip, parent=zid, gateway=True, role="wan")  # mismo id que una ruta con ese salto
                g.edge(net_id, f"rt:{gateway_ip}", "gateway", "gateway")
                g.edge(f"rt:{gateway_ip}", "internet", "uplink")
            else:
                g.edge(net_id, "internet", "uplink")

    # -- Rutas estáticas: red remota alcanzable a través de un router -----------------------------
    routes_err = _failed(raw, "static_routes")
    remote_cidrs: dict[str, str] = {}  # cidr -> id de nodo (para solapamientos)
    for r in _data(raw, "static_routes"):
        dest = _network(r.get("DestinationIP", ""), r.get("Netmask", "")) if r.get("DestinationIP") else None
        if not dest:
            continue
        gateway, out_if = str(r.get("Gateway", "") or ""), str(r.get("Interface", "") or "")
        label = r.get("Name", "") or str(dest)
        extra = {"distance": r.get("Distance", ""), "route": label}
        gw_addr = _address(gateway) if gateway else None

        if gw_addr:
            candidates = [(n, nid, ifn) for n, nid, ifn in connected if gw_addr in n and (not out_if or ifn == out_if)] or \
                         [(n, nid, ifn) for n, nid, ifn in connected if gw_addr in n]
            if candidates:
                _, net_id, ifn = max(candidates, key=lambda c: c[0].prefixlen)  # la red más específica
                zid = g.nodes[net_id]["parent"]
                router_id = f"rt:{gateway}"
                g.node(router_id, "router", gateway, parent=zid, role=g.nodes[zid]["data"]["role"])
                g.edge(net_id, router_id, "gateway", "gateway")
            else:
                router_id, zid = f"rt:{gateway}", None
                g.node(router_id, "router", gateway, unreachable=True, role="other")
                g.edge("fw", router_id, "gateway", "sin red conectada", dashed=True)
                g.warn("route_nexthop_unreachable",
                       f"La ruta {label} ({dest}) usa el salto {gateway}, que no está en ninguna red conectada del firewall.", router_id, "critical")
            if str(dest) == "0.0.0.0/0":
                if "internet" not in g.nodes:
                    g.node("internet", "internet", "Internet", role="wan")
                g.edge(router_id, "internet", "route", "ruta por defecto", **extra)
                continue
            rn_id = f"rn:{dest}"
            g.node(rn_id, "remote_network", str(dest), parent=zid, role=g.nodes[zid]["data"]["role"] if zid else "other")
            g.edge(router_id, rn_id, "route", label, **extra)
            remote_cidrs[str(dest)] = rn_id
        elif out_if.lower() == "blackhole":
            bh = g.node(f"bh:{dest}", "blackhole", f"{dest} (descartada)", role="other")
            g.edge("fw", bh["id"], "route", label, dashed=True, **extra)
        elif f"if:{out_if}" in g.nodes:  # ruta directa por interfaz, sin salto
            rn_id = f"rn:{dest}"
            g.node(rn_id, "remote_network", str(dest), parent=g.nodes[f"if:{out_if}"]["parent"], role="other")
            g.edge(f"if:{out_if}", rn_id, "route", label, **extra)
            remote_cidrs[str(dest)] = rn_id

    # -- VPN IPsec: FW <-> túnel <-> sitio remoto --------------------------------------------------
    vpn_err = _failed(raw, "vpn_ipsec_connections")
    cidr_by_name = _host_cidrs(_data(raw, "hosts"))
    for v in _data(raw, "vpn_ipsec_connections"):
        name = v.get("name", "")
        if not name:
            continue
        enabled = str(v.get("status", "")).lower() in ("enable", "enabled", "active", "connected", "established", "1")
        tunnel_id = f"vpn:{name}"
        g.node(tunnel_id, "vpn_tunnel", name, role="vpn", status=v.get("status", ""), enabled=enabled,
               connection_type=v.get("connection_type", ""), policy=v.get("policy", ""),
               local_networks=v.get("local_networks", []))
        local_if = f"if:{v.get('local_gateway', '')}"
        g.edge(local_if if local_if in g.nodes else "fw", tunnel_id, "vpn", v.get("connection_type", ""), dashed=not enabled)
        remote_gw = v.get("remote_gateway", "") or name
        site_id = f"site:{remote_gw}"
        g.node(site_id, "remote_site", remote_gw, role="vpn", remote_gateway=v.get("remote_gateway", ""))
        g.edge(tunnel_id, site_id, "vpn", "", dashed=not enabled)
        for rn in v.get("remote_networks", []):
            cidr = cidr_by_name.get(rn, rn)
            rn_id = f"rn:{cidr}"
            label = "Cualquiera" if cidr == "Any" else (cidr if cidr == rn else f"{cidr} ({rn})")
            g.node(rn_id, "remote_network", label, role="vpn")
            g.edge(site_id, rn_id, "route", "")
            if cidr != "Any":
                remote_cidrs.setdefault(cidr, rn_id)

    # -- Solapamientos entre redes remotas y redes conectadas ------------------------------------
    connected_nets = {net for net, _, _ in connected}
    for cidr, node_id in remote_cidrs.items():
        try:
            remote = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        for net in connected_nets:
            if remote.prefixlen > 0 and remote.overlaps(net) and remote != net:
                g.warn("overlapping_subnets", f"La red remota {cidr} se solapa con la red conectada {net}.", node_id)
            elif remote == net and remote.prefixlen > 0:
                g.warn("overlapping_subnets", f"La red remota {cidr} es idéntica a la red conectada {net} (conflicto de ruteo).", node_id)

    notes = [DYNAMIC_ROUTING_NOTE]
    if routes_err:
        notes.append(f"Rutas estáticas no disponibles: {routes_err}")
    if vpn_err:
        notes.append(f"Conexiones VPN no disponibles: {vpn_err}")
    counts: dict[str, int] = {}
    for n in g.nodes.values():
        counts[n["type"]] = counts.get(n["type"], 0) + 1
    return {
        "nodes": list(g.nodes.values()),
        "edges": list(g.edges.values()),
        "meta": {"source": info.get("api_type", "xml"), "counts": counts, "warnings": g.warnings, "notes": notes},
    }
