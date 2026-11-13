"""Normaliza respuestas de la REST API v1 de SFOS v23 al formato que producen los colectores XML.

Así `audit_service` y las tablas del frontend funcionan igual con ambos modos (api_type "xml" | "rest").
Funciones puras: sin red, fáciles de testear.
"""
from __future__ import annotations

import ipaddress
from typing import Any

# Servicios de zona que exponen administración (se usan para detectar acceso admin desde WAN)
ADMIN_ZONE_SERVICES = ("https", "ssh")


def selector_names(selector: Any) -> list[str]:
    """`{"any": true}` -> ["Any"]; `{"zones": [{"name": "LAN"}]}` -> ["LAN"]; vacío -> []."""
    if not isinstance(selector, dict) or not selector:
        return []
    if selector.get("any") is True:
        return ["Any"]
    out: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            if isinstance(v.get("name"), str):
                out.append(v["name"])
            else:
                for x in v.values():
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(selector)
    return out


def ref_name(value: Any) -> str:
    """Referencia a objeto: {"name": "x"} -> "x"; str -> str; otro -> ""."""
    if isinstance(value, dict):
        return str(value.get("name", ""))
    return value if isinstance(value, str) else ""


def _enable(flag: Any) -> str:
    return "Enable" if flag else "Disable"


def normalize_firewall_rule(rule: dict[str, Any], position: int) -> dict[str, Any]:
    sec = rule.get("securityFeatures") or {}
    waf = rule.get("ruleType") == "waf"
    return {
        "name": rule.get("name", ""),
        "description": rule.get("description", ""),
        "ip_family": "IPv4",
        "status": _enable(rule.get("enabled")),
        "position": str(position),
        "policy_type": "HTTPBased" if waf else "Network",
        "action": str(rule.get("action", "")).capitalize(),
        "log_traffic": _enable(rule.get("logTraffic")),
        "schedule": ref_name(rule.get("schedule")),
        "source_zones": selector_names(rule.get("sourceZones")),
        "destination_zones": selector_names(rule.get("destinationZones")),
        "source_networks": selector_names(rule.get("sourceNetworks")),
        "destination_networks": selector_names(rule.get("destinationNetworks")),
        "services": selector_names(rule.get("servicesOrGroups")),
        "web_filter": ref_name(sec.get("webPolicy")),
        "application_control": ref_name(sec.get("applicationPolicy")),
        "intrusion_prevention": ref_name(sec.get("ipsPolicy")),
        "scan_virus": _enable(sec.get("scanHttpAndDecryptedHttps")),
        "decrypt_https": _enable(sec.get("decryptHTTPSWebProxyMode")),
        "hosted_address": "",
        "listen_port": "",
        "domains": [],
        "raw": rule,
    }


def _translated(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return ""
    if value.get("masq"):
        return "MASQ"
    if value.get("original"):
        return "Original"
    names = selector_names(value)
    return names[0] if names else ""


def normalize_nat_rule(rule: dict[str, Any], position: int) -> dict[str, Any]:
    t_src = _translated(rule.get("translatedSource"))
    t_dst = _translated(rule.get("translatedDestination"))
    if t_dst not in ("", "Original"):
        nat_type = "DNAT"
    elif t_src == "MASQ":
        nat_type = "MASQ"
    elif t_src not in ("", "Original"):
        nat_type = "SNAT"
    else:
        nat_type = "NAT"
    return {
        "name": rule.get("name", ""),
        "description": rule.get("description", ""),
        "ip_family": "IPv4",
        "status": _enable(rule.get("enabled")),
        "position": str(position),
        "nat_type": nat_type,
        "linked_firewall_rule": ref_name(rule.get("linkedFirewallRule")),
        "original_source_networks": selector_names(rule.get("originalSourceNetworks")),
        "original_destination_networks": selector_names(rule.get("originalDestinationNetworks")),
        "original_services": selector_names(rule.get("originalServicesOrGroups")),
        "translated_source": t_src,
        "translated_destination": t_dst,
        "translated_service": _translated(rule.get("translatedService")),
        "inbound_interfaces": selector_names(rule.get("inboundInterfaces")),
        "outbound_interfaces": selector_names(rule.get("outboundInterfaces")),
        "override_interface_nat": _enable(rule.get("overrideSnatForOutboundInterfaces")),
        "nat_method": "",
        "health_check": "",
        "raw": rule,
    }


def normalize_zone(zone: dict[str, Any]) -> dict[str, Any]:
    services = [s["name"] for s in zone.get("services", []) if isinstance(s, dict) and "name" in s]
    return {
        "name": zone.get("name", ""),
        "type": zone.get("type", ""),
        "description": zone.get("description", ""),
        "appliance_access": {"services": services},
        "raw": zone,
    }


_HOST_TYPES = {"ipv4Address": "IP", "ipv4Network": "Network", "ipv4Range": "IPRange", "ipv4List": "IPList",
               "ipv6Address": "IP", "ipv6Network": "Network", "ipv6Range": "IPRange", "ipv6List": "IPList"}


def normalize_host(host: dict[str, Any]) -> dict[str, Any]:
    """Objetos de host v23 -> campos del colector XML (HostType IP/Network/IPRange/IPList)."""
    htype = host.get("type", "")
    ip = subnet = start = end = ""
    if htype == "ipv4Address":
        ip = host.get("ipv4Address", "")
    elif htype == "ipv4Network":
        ip, subnet = host.get("ipv4NetworkAddress", ""), _netmask(host.get("cidr"))
    elif htype == "ipv4Range":
        start, end = host.get("ipv4AddressStart", ""), host.get("ipv4AddressEnd", "")
    elif htype == "ipv4List":
        ip = ", ".join(a if isinstance(a, str) else str(a.get("ipv4Address", a)) if isinstance(a, dict) else str(a)
                       for a in host.get("ipv4Addresses") or [])
    return {
        "name": host.get("name", ""),
        "description": host.get("description", ""),
        "ip_family": "IPv6" if htype.startswith("ipv6") else "IPv4",
        "type": _HOST_TYPES.get(htype, htype),
        "ip_address": ip,
        "subnet": subnet,
        "start_ip": start,
        "end_ip": end,
        "raw": host,
    }


def normalize_named_object(obj: dict[str, Any]) -> dict[str, Any]:
    """Servicios, grupos y similares: conserva el objeto completo bajo `raw`."""
    return {"name": obj.get("name", ""), "description": obj.get("description", ""), "type": obj.get("type", ""), "raw": obj}


def _netmask(cidr: Any) -> str:
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{int(cidr)}").netmask)
    except (TypeError, ValueError):
        return ""


def normalize_interface(iface: dict[str, Any]) -> dict[str, Any]:
    v4 = iface.get("ipv4") or {}
    return {
        "name": iface.get("name", ""),
        "hardware": iface.get("hardwareName", ""),
        "zone": ref_name(iface.get("zone")),
        "interface_status": "ON" if iface.get("enabled") else "OFF",  # estado administrativo (la API de configuración no da el enlace)
        "type": iface.get("type", "physical"),
        "gateway_ip": v4.get("gatewayIpAddress", "") or "",
        "ip_address": v4.get("ipv4Address", "") or "",
        "netmask": _netmask(v4.get("cidr")),
        "ipv4_assignment": v4.get("assignmentType", ""),
        "status": _enable(iface.get("enabled")),
        "mtu": iface.get("mtu", ""),
        "mac_address": iface.get("macAddress", "") or "",
        "raw": iface,
    }


def normalize_gateway(gw: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": gw.get("name", ""),
        "ip_address": gw.get("ipv4Address", "") or gw.get("ipv6Address", "") or "",
        "interface": ref_name(gw.get("interface")),
        "type": gw.get("type", ""),
        "raw": gw,
    }


def otp_applies_to_admin(totp: dict[str, Any], admin: dict[str, Any]) -> bool:
    """MFA efectivo para el acceso web de un administrador: OTP habilitado, aplicado a la consola y al usuario/grupo."""
    if not totp.get("enabled") or "webAdminPortal" not in (totp.get("enabledFor") or []):
        return False
    scope = totp.get("usersOrGroups") or {}
    if scope.get("any") is True:
        return True
    users = {u.get("name") for u in scope.get("users", []) if isinstance(u, dict)}
    groups = {g.get("name") for g in scope.get("userGroups", []) if isinstance(g, dict)}
    return admin.get("name") in users or ref_name(admin.get("group")) in groups


def normalize_admins(admins: list[dict[str, Any]], totp: dict[str, Any]) -> list[dict[str, Any]]:
    """Solo cuentas administrativas reales (con perfil de acceso); excluye grupos/pseudo-usuarios sin perfil."""
    out = []
    for a in admins:
        policies = a.get("administrativePolicies") or {}
        profile = ref_name(policies.get("accessProfile"))
        if not profile:
            continue
        out.append({
            "name": a.get("name", ""),
            "profile": profile,
            "email": ", ".join(a.get("emailAddresses") or []) if isinstance(a.get("emailAddresses"), list) else "",
            "otp_enabled": otp_applies_to_admin(totp, a),
            "login_restriction": "",
            "allowed_networks": ", ".join(selector_names(policies.get("allowedNetworksIpv4"))),
            "raw": a,
        })
    return out


def normalize_notifications(settings: dict[str, Any]) -> list[dict[str, Any]]:
    return [{
        "SendEmail": _enable(settings.get("enableEmailNotifications")),
        "SendSnmp": _enable(settings.get("enableSnmpTraps")),
        "notifications": settings.get("notifications", []),
    }]


def normalize_admin_settings(system_settings: dict[str, Any]) -> dict[str, Any]:
    """REST solo expone hostname aquí; sin datos de certificado de administración (no se evalúa)."""
    return {"HostnameSettings": {"HostName": system_settings.get("hostname", "")}}


def build_device_access(zones: list[dict[str, Any]], acl_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Acceso de administración por zona (servicios https/ssh habilitados) + reglas ACL de excepción."""
    out = []
    for z in zones:
        services = [s["name"] for s in z.get("services", []) if isinstance(s, dict) and s.get("name") in ADMIN_ZONE_SERVICES]
        if services:
            out.append({"rule_name": f"Acceso por zona: {z.get('name', '')}", "description": "", "position": "",
                        "ip_family": "IPv4", "source_zone": z.get("name", ""), "hosts": [], "services": services,
                        "action": "Accept", "raw": z})
    for r in acl_rules:
        out.append({"rule_name": r.get("name", ""), "description": r.get("description", ""), "position": "",
                    "ip_family": "IPv4", "source_zone": ref_name(r.get("sourceZone")),
                    "hosts": selector_names(r.get("sourceNetworks")),
                    "services": selector_names({"services": r.get("services")}),
                    "action": str(r.get("action", "")).capitalize(), "raw": r})
    return out


# ---------------------------------------------------------------------------
# Interfaces virtuales, rutas y VPN (insumos del grafo de topología)
# ---------------------------------------------------------------------------

def normalize_vlan(iface: dict[str, Any]) -> dict[str, Any]:
    v4 = iface.get("ipv4") or {}
    details = iface.get("vlanDetails") or {}
    return {
        "name": iface.get("name", ""),
        "vlan_id": details.get("vlanId", ""),
        "zone": ref_name(iface.get("zone")),
        "interface": ref_name(details.get("parentInterface")),
        "hardware": iface.get("hardwareName", "") or iface.get("name", ""),
        "interface_status": "ON" if iface.get("enabled") else "OFF",
        "ip_address": v4.get("ipv4Address", "") or "",
        "netmask": _netmask(v4.get("cidr")),
        "ipv4_assignment": v4.get("assignmentType", ""),
        "status": _enable(iface.get("enabled")),
        "raw": iface,
    }


def normalize_lag(iface: dict[str, Any]) -> dict[str, Any]:
    v4 = iface.get("ipv4") or {}
    members = [ref_name(m.get("interface")) for m in (iface.get("lagDetails") or {}).get("members", []) if isinstance(m, dict)]
    return {
        "name": iface.get("name", ""),
        "description": iface.get("description", ""),
        "zone": ref_name(iface.get("zone")),
        "members": members,
        "ip_address": v4.get("ipv4Address", "") or "",
        "netmask": _netmask(v4.get("cidr")),
        "status": _enable(iface.get("enabled")),
        "raw": iface,
    }


def normalize_alias(parent: dict[str, Any], secondary: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "name": f"{parent.get('name', '')}:{index}",
        "interface": parent.get("name", ""),
        "ip_family": "IPv4",
        "ip_address": secondary.get("ipv4Address", ""),
        "netmask": _netmask(secondary.get("cidr")),
        "raw": secondary,
    }


def split_interfaces(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Separa /network/interfaces/network-interfaces en las claves que usa el auditor (como en XML)."""
    out: dict[str, list[dict[str, Any]]] = {"interfaces": [], "vlans": [], "lags": [], "aliases": []}
    for i in items:
        kind = i.get("type", "physical")
        if kind == "vlan":
            out["vlans"].append(normalize_vlan(i))
        elif kind == "lag":
            out["lags"].append(normalize_lag(i))
        else:  # physical, bridge, etc.
            out["interfaces"].append(normalize_interface(i))
        for n, sec in enumerate((i.get("ipv4") or {}).get("secondaryAddresses") or []):
            if isinstance(sec, dict):
                out["aliases"].append(normalize_alias(i, sec, n))
    return out


def normalize_static_route(route: dict[str, Any]) -> dict[str, Any]:
    """Mismos nombres de campo que devuelve la API XML (UnicastRoute)."""
    return {
        "Name": route.get("name", ""),
        "DestinationIP": route.get("destinationAddressIpv4", ""),
        "Netmask": _netmask(route.get("cidr")),
        "Gateway": route.get("gatewayIpv4", "") or "",
        "Interface": ref_name(route.get("interface")),
        "Distance": route.get("metric", ""),
        "AdministrativeDistance": route.get("administrativeDistance", ""),
        "raw": route,
    }


def _vpn_networks(selector: Any) -> list[str]:
    if not isinstance(selector, dict) or not selector:
        return []
    if selector.get("any") is True:
        return ["Any"]
    out: list[str] = []
    for key in ("ipv4Addresses", "ipv4Groups", "fqdnAddresses", "fqdnGroups"):
        for item in selector.get(key) or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or ref_name(item.get("ipv4Address"))
            if name:
                out.append(name)
    return out


def normalize_vpn_ipsec(conn: dict[str, Any]) -> dict[str, Any]:
    gw = conn.get("gatewaySettings") or {}
    remote = gw.get("remoteGateway") or {}
    protected = conn.get("protectedNetworks") or {}
    return {
        "name": conn.get("name", ""),
        "description": conn.get("description", ""),
        "status": "Enable" if conn.get("activateConnection") else "Disable",
        "connection_type": conn.get("type", ""),
        "local_gateway": ref_name(gw.get("localGateway")).lstrip("#"),
        "remote_gateway": remote.get("ipv4Address") or remote.get("fqdn") or "",
        "policy": ref_name(conn.get("profile")),
        "local_networks": _vpn_networks(protected.get("localNetworksIpv4")),
        "remote_networks": _vpn_networks(protected.get("remoteNetworksIpv4")),
        "raw": conn,
    }


# ---------------------------------------------------------------------------
# Objetos, políticas y ajustes adicionales (mismo formato que los colectores XML)
# ---------------------------------------------------------------------------

def _names(items: Any) -> list[str]:
    """[{"name": "a"}, "b"] -> ["a", "b"]; vacío o tipo inesperado -> []."""
    if not isinstance(items, list):
        return []
    return [n for n in (ref_name(i) for i in items) if n]


def normalize_host_group(group: dict[str, Any]) -> dict[str, Any]:
    members = _names(group.get("ipv4Addresses")) + _names(group.get("ipv4Groups"))
    return {"name": group.get("name", ""), "description": group.get("description", ""), "hosts": members, "raw": group}


def normalize_mac_host(host: dict[str, Any]) -> dict[str, Any]:
    macs = host.get("macAddresses") if isinstance(host.get("macAddresses"), list) else []
    return {"name": host.get("name", ""), "description": host.get("description", ""), "type": host.get("type", ""),
            "mac_address": host.get("macAddress", "") or "", "mac_list": [m if isinstance(m, str) else ref_name(m) for m in macs], "raw": host}


def normalize_fqdn_hosts(hosts: list[dict[str, Any]], groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    member_of: dict[str, list[str]] = {}
    for g in groups:
        for n in _names(g.get("fqdns")):
            member_of.setdefault(n, []).append(g.get("name", ""))
    return [{"name": h.get("name", ""), "fqdn": h.get("fqdn", ""), "description": h.get("description", ""),
             "groups": member_of.get(h.get("name", ""), []), "raw": h} for h in hosts]


def normalize_fqdn_group(group: dict[str, Any]) -> dict[str, Any]:
    return {"name": group.get("name", ""), "description": group.get("description", ""), "hosts": _names(group.get("fqdns")), "raw": group}


def normalize_schedule(s: dict[str, Any]) -> dict[str, Any]:
    slots = [t for t in (s.get("timeSlots") or []) if isinstance(t, dict)]
    return {"name": s.get("name", ""), "description": s.get("description", ""), "type": s.get("type", ""),
            "days": "; ".join(str(t.get("dayOfWeek", "")) for t in slots),
            "start_time": slots[0].get("startTime", "") if slots else "", "stop_time": slots[0].get("endTime", "") if slots else "", "raw": s}


def normalize_user(u: dict[str, Any]) -> dict[str, Any]:
    """Usuarios de /authentication/users (incluye administradores; `user_type` lo distingue)."""
    return {"username": u.get("name", ""), "name": u.get("displayName", "") or u.get("name", ""),
            "user_type": "Administrator" if u.get("administrativeAccess") else "User", "group": ref_name(u.get("group")),
            "status": "Active" if u.get("active") else "Inactive", "ssl_vpn_policy": "", "access_time_policy": "",
            "surfing_quota": "", "login_restriction": "", "simultaneous_logins": "", "raw": u}


def normalize_tls_rule(r: dict[str, Any]) -> dict[str, Any]:
    return {"name": r.get("name", ""), "description": r.get("description", ""), "enabled": _enable(r.get("enabled")), "is_default": "",
            "log_connections": _enable(r.get("logTraffic")), "source_zones": selector_names(r.get("sourceZones")),
            "source_networks": selector_names(r.get("sourceNetworks")), "destination_zones": selector_names(r.get("destinationZones")),
            "destination_networks": selector_names(r.get("destinationNetworks")), "services": selector_names(r.get("servicesOrGroups")),
            "decrypt_action": r.get("action", ""), "decryption_profile": ref_name(r.get("decryptionProfile")), "raw": r}


def normalize_decryption_profile(p: dict[str, Any]) -> dict[str, Any]:
    return {"name": p.get("name", ""), "description": p.get("description", ""), "is_default": "",
            "min_tls_version": p.get("minTlsVersion", ""), "max_tls_version": p.get("maxTlsVersion", ""),
            "block_untrusted_issuer": _enable(p.get("blockUntrustedIssuer")), "block_invalid_date": _enable(p.get("blockExpiredCertificates")),
            "block_self_signed": _enable(p.get("blockSelfSigned")), "block_revoked": _enable(p.get("blockRevoked")),
            "ssl_v2_v3": p.get("sslV2V3Action", ""), "raw": p}


def normalize_policy(p: dict[str, Any]) -> dict[str, Any]:
    """Políticas web y de aplicaciones: nombre, descripción y acción por defecto (si existe); el detalle queda en `raw`."""
    out = {"name": p.get("name", ""), "description": p.get("description", ""), "raw": p}
    if "defaultAction" in p:
        out["default_action"] = p.get("defaultAction", "")
    return out


def normalize_backup(settings: dict[str, Any]) -> dict[str, Any]:
    sched = settings.get("schedule") or {}
    return {"mode": settings.get("backupStorage", ""), "prefix": settings.get("backupPrefix", ""), "frequency": sched.get("frequency", ""),
            "day": sched.get("day", sched.get("dayOfWeek", "")), "time": sched.get("time", ""), "email": settings.get("emailAddress", ""),
            "ftp_server": "", "ftp_path": "", "ftp_user": "", "raw": settings}
