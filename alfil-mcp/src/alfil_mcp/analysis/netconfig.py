"""Higiene de NAT, interfaces y notificaciones (funciones puras sobre la configuración REST v23)."""
from __future__ import annotations

from typing import Any

ORDER = {"critical": 0, "warning": 1, "info": 2}
ADMIN_EVENT_GROUP = "admin"  # inicios de sesión fallidos, demasiados intentos


def _name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name", ""))
    return value if isinstance(value, str) else ""


def _any(selector: Any) -> bool:
    return isinstance(selector, dict) and selector.get("any") is True


def _f(severity: str, code: str, target: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "target": target, "message": message}


def check_nat(nat_rules: list[dict[str, Any]], fw_rules: list[dict[str, Any]], wan_interfaces: set[str]) -> list[dict[str, str]]:
    out = []
    fw = {r.get("name"): r for r in fw_rules}
    for n in nat_rules:
        name = n.get("name", "")
        if not n.get("enabled", True):
            out.append(_f("info", "NAT_DISABLED", name, f"La regla NAT «{name}» está deshabilitada (posible regla obsoleta)."))
            continue
        linked = _name(n.get("linkedFirewallRule"))
        if linked and linked not in fw:
            out.append(_f("warning", "NAT_LINKED_RULE_MISSING", name, f"La regla NAT «{name}» enlaza con la regla de firewall «{linked}», que no existe."))
        elif linked and not fw[linked].get("enabled", True):
            out.append(_f("info", "NAT_LINKED_RULE_DISABLED", name, f"La regla NAT «{name}» enlaza con la regla de firewall «{linked}», que está deshabilitada."))
        if n.get("translatedDestination"):  # DNAT: publica un servicio interno
            inbound = n.get("inboundInterfaces") or {}
            from_wan = _any(inbound) or any(_name(i) in wan_interfaces for i in inbound.get("interfaces", []))
            if from_wan and _any(n.get("originalSourceNetworks")):
                out.append(_f("warning", "NAT_DNAT_ANY_SOURCE", name,
                              f"DNAT «{name}»: publica un servicio interno desde cualquier origen por una interfaz WAN o «any». Restrinja el origen o confirme que debe ser público."))
    return out


def check_interfaces(interfaces: list[dict[str, Any]]) -> list[dict[str, str]]:
    out = []
    for i in interfaces:
        name = i.get("name", "")
        if i.get("enabled", True) and not _name(i.get("zone")) and i.get("type", "physical") == "physical":
            out.append(_f("info", "IFACE_NO_ZONE", name, f"La interfaz «{name}» está habilitada pero no pertenece a ninguna zona: no se le aplican reglas."))
    return out


def check_notifications(settings: dict[str, Any]) -> list[dict[str, str]]:
    email, snmp = bool(settings.get("enableEmailNotifications")), bool(settings.get("enableSnmpTraps"))
    if not email and not snmp:
        return [_f("warning", "NOTIF_NONE", "notificaciones", "Ni el correo ni SNMP traps están habilitados: nadie recibe alertas del equipo.")]
    admin = [n for n in settings.get("notifications", []) if isinstance(n, dict) and n.get("group") == ADMIN_EVENT_GROUP]
    if admin and not any((email and n.get("email")) or (snmp and n.get("snmpTrap")) for n in admin):
        return [_f("warning", "NOTIF_ADMIN_EVENTS", "notificaciones",
                   "Los eventos de inicio de sesión de administración (fallos, demasiados intentos) no notifican por ningún canal activo.")]
    return []


def audit_network_config(nat_rules: list[dict[str, Any]], fw_rules: list[dict[str, Any]], interfaces: list[dict[str, Any]],
                         zones: list[dict[str, Any]], notifications: dict[str, Any]) -> dict[str, Any]:
    wan_zones = {z.get("name") for z in zones if str(z.get("type", "")).lower() == "wan"}
    wan_ifaces = {i.get("name", "") for i in interfaces if _name(i.get("zone")) in wan_zones}
    findings = check_nat(nat_rules, fw_rules, wan_ifaces) + check_interfaces(interfaces) + check_notifications(notifications)
    findings.sort(key=lambda f: ORDER[f["severity"]])
    return {"counts": {s: sum(1 for f in findings if f["severity"] == s) for s in ORDER}, "findings": findings,
            "totals": {"nat_rules": len(nat_rules), "interfaces": len(interfaces)},
            "limits": ["La API v1 no expone NTP ni la hora del equipo: no se evalúa.",
                       "NAT: solo se evalúan reglas IPv4; la regla enlazada y el DNAT se revisan por configuración, sin probar el tráfico.",
                       "Interfaces: la API de configuración no informa el estado del enlace (solo habilitada/deshabilitada)."]}
