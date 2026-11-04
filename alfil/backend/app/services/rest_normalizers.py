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


def normalize_host(host: dict[str, Any]) -> dict[str, Any]:
    addrs = host.get("ipv4Addresses") or host.get("ipv6Addresses") or []
    flat = [a if isinstance(a, str) else str(a.get("name", a)) if isinstance(a, dict) else str(a) for a in addrs]
    return {
        "name": host.get("name", ""),
        "description": host.get("description", ""),
        "ip_family": "IPv4",
        "type": host.get("type", ""),
        "ip_address": ", ".join(flat),
        "subnet": "",
        "start_ip": "",
        "end_ip": "",
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
        "interface_status": "",
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
