"""
Motor de auditoría de salud para Sophos Firewall.
Analiza los datos recolectados y genera un reporte estructurado con hallazgos.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Severidades
CRITICAL = "critical"
WARNING = "warning"
INFO = "info"
OK = "ok"

# Zonas consideradas externas (WAN) — se comparan en minúsculas
WAN_ZONE_KEYWORDS = {"wan", "external", "internet", "untrust", "untrusted", "dmz-ext"}


def _issue(severity: str, category: str, title: str, detail: str, reference: str = "") -> dict:
    return {"severity": severity, "category": category, "title": title, "detail": detail, "reference": reference}


# ---------------------------------------------------------------------------
# Análisis por sección
# ---------------------------------------------------------------------------

def _analyze_admin_users(data: dict) -> list[dict]:
    issues = []
    users = data.get("admin_users", {}).get("data", [])
    for u in users:
        name = u.get("name", "?")
        if not u.get("otp_enabled"):
            issues.append(_issue(
                CRITICAL, "admin_users",
                f"Admin '{name}' sin MFA/OTP habilitado",
                "Las cuentas administrativas sin segundo factor son el vector de ataque más común.",
                name,
            ))
    if not users:
        issues.append(_issue(INFO, "admin_users", "No se pudieron recuperar los usuarios administradores", "Verificar permisos de la cuenta API."))
    return issues


def _analyze_device_access(data: dict, zones: list[dict]) -> list[dict]:
    issues = []
    acls = data.get("device_access", {}).get("data", [])
    wan_zone_names = {z["name"] for z in zones if z.get("type", "").lower() in ("wan", "external") or z["name"].lower() in WAN_ZONE_KEYWORDS}

    for acl in acls:
        if not isinstance(acl, dict):
            continue
        zone = acl.get("Zone", acl.get("@zone", ""))
        if zone.lower() in WAN_ZONE_KEYWORDS or zone in wan_zone_names:
            services_node = acl.get("Services", {})
            enabled_services = []
            if isinstance(services_node, dict):
                for svc, val in services_node.items():
                    if str(val).lower() in ("enable", "enabled", "true"):
                        enabled_services.append(svc)
            elif isinstance(services_node, list):
                enabled_services = [s.get("@name", str(s)) for s in services_node]

            risky = [s for s in enabled_services if any(k in s.lower() for k in ("webadmin", "ssh", "console", "admin", "https", "api"))]
            if risky:
                issues.append(_issue(
                    CRITICAL, "device_access",
                    f"Acceso administrativo desde zona WAN/externa '{zone}'",
                    f"Servicios expuestos: {', '.join(risky)}. El panel de administración no debe ser accesible desde internet.",
                    zone,
                ))
    return issues


def _analyze_admin_settings(data: dict) -> list[dict]:
    issues = []
    settings = data.get("admin_settings", {}).get("data", {})
    if not settings:
        return issues

    # Hostname vacío
    hostname = settings.get("Hostname", "")
    if not hostname:
        issues.append(_issue(INFO, "system", "Hostname no configurado", "Se recomienda configurar un hostname descriptivo."))

    # HTTPS certificate (auto-signed?)
    cert = settings.get("Certificate", "")
    if cert.lower() in ("", "default", "appliance"):
        issues.append(_issue(WARNING, "system", "Certificado de administración auto-firmado o por defecto",
                             "Usar un certificado firmado por una CA de confianza reduce riesgos de MITM en la consola."))
    return issues


def _analyze_time_settings(data: dict) -> list[dict]:
    issues = []
    t = data.get("time_settings", {}).get("data", {})
    if not t:
        issues.append(_issue(INFO, "system", "No se pudo obtener configuración de tiempo", "Verificar permisos de la cuenta API."))
        return issues

    timezone_val = t.get("Timezone", "")
    issues.append(_issue(INFO, "system", f"Zona horaria configurada: {timezone_val or 'desconocida'}",
                         "Verificar que coincida con la zona horaria de la organización."))

    ntp_servers = t.get("NTPServer", [])
    if not ntp_servers:
        issues.append(_issue(WARNING, "system", "NTP no configurado",
                             "Sin NTP, los logs pueden tener timestamps incorrectos, dificultando la correlación de eventos."))
    return issues


def _analyze_firewall_rules(data: dict) -> tuple[list[dict], dict]:
    rules = data.get("firewall_rules", {}).get("data", [])
    issues = []
    stats = {"total": len(rules), "enabled": 0, "disabled": 0, "no_log": 0, "any_any": 0, "duplicates": 0}

    enabled_rules = []
    for r in rules:
        if r.get("status", "").lower() in ("enable", "enabled"):
            stats["enabled"] += 1
            enabled_rules.append(r)
        else:
            stats["disabled"] += 1
            issues.append(_issue(INFO, "firewall_rules", f"Regla deshabilitada: '{r['name']}'",
                                 "Las reglas deshabilitadas pueden ser obsoletas. Revisar y eliminar si ya no son necesarias.", r["name"]))

        if r.get("log_traffic", "Disable").lower() in ("disable", "disabled", ""):
            stats["no_log"] += 1
            issues.append(_issue(WARNING, "firewall_rules", f"Regla sin logging: '{r['name']}'",
                                 "Sin logging no hay trazabilidad de este tráfico.", r["name"]))

    # Any-Any: fuente y destino son "Any" o listas vacías, y acción es Accept
    for r in enabled_rules:
        src = r.get("source_networks", [])
        dst = r.get("destination_networks", [])
        action = r.get("action", "").lower()
        src_is_any = not src or src == ["Any"]
        dst_is_any = not dst or dst == ["Any"]
        if src_is_any and dst_is_any and action == "accept":
            stats["any_any"] += 1
            issues.append(_issue(WARNING, "firewall_rules", f"Regla permisiva Any→Any: '{r['name']}'",
                                 "Permite todo el tráfico sin restricción. Revisar si es intencional.", r["name"]))

    # Duplicados: mismas zonas + redes + servicios + acción
    seen: dict[tuple, str] = {}
    for r in enabled_rules:
        key = (
            tuple(sorted(r.get("source_zones", []))),
            tuple(sorted(r.get("destination_zones", []))),
            tuple(sorted(r.get("source_networks", []))),
            tuple(sorted(r.get("destination_networks", []))),
            tuple(sorted(r.get("services", []))),
            r.get("action", "").lower(),
        )
        if key in seen:
            stats["duplicates"] += 1
            issues.append(_issue(WARNING, "firewall_rules",
                                 f"Regla duplicada: '{r['name']}' y '{seen[key]}'",
                                 "Tienen los mismos criterios de matching. Una de las dos puede ser eliminada.", r["name"]))
        else:
            seen[key] = r["name"]

    return issues, stats


def _analyze_nat_rules(data: dict) -> tuple[list[dict], dict]:
    rules = data.get("nat_rules", {}).get("data", [])
    issues = []
    stats = {"total": len(rules), "enabled": 0, "disabled": 0, "no_log": 0}

    for r in rules:
        if r.get("status", "").lower() in ("enable", "enabled"):
            stats["enabled"] += 1
        else:
            stats["disabled"] += 1
            issues.append(_issue(INFO, "nat_rules", f"Regla NAT deshabilitada: '{r['name']}'",
                                 "Revisar si es obsoleta.", r["name"]))

        if r.get("log_traffic", "Disable").lower() in ("disable", "disabled", ""):
            stats["no_log"] += 1
            issues.append(_issue(INFO, "nat_rules", f"Regla NAT sin logging: '{r['name']}'",
                                 "Habilitar logging en reglas NAT facilita la trazabilidad.", r["name"]))

        # DNAT expuesto a WAN
        src_zones = [z.lower() for z in r.get("source_zones", [])]
        is_from_wan = any(k in z for z in src_zones for k in WAN_ZONE_KEYWORDS)
        if is_from_wan and r.get("nat_type", "").upper() in ("DNAT", ""):
            issues.append(_issue(WARNING, "nat_rules",
                                 f"Regla DNAT desde zona WAN: '{r['name']}'",
                                 f"Publica internamente hacia {r.get('translated_destination', '?')}. Verificar que sea intencional y seguro.",
                                 r["name"]))

    return issues, stats


def _analyze_zones(data: dict) -> list[dict]:
    zones = data.get("zones", {}).get("data", [])
    issues = []
    wan_zones = [z for z in zones if z.get("type", "").lower() == "wan" or z["name"].lower() in WAN_ZONE_KEYWORDS]
    if not wan_zones:
        issues.append(_issue(INFO, "zones", "No se identificaron zonas WAN", "Verificar la tipología de zonas del equipo."))
    return issues


def _analyze_hosts(data: dict, firewall_rules: list[dict], nat_rules: list[dict]) -> list[dict]:
    """Detecta hosts definidos que no se usan en ninguna regla."""
    issues = []
    hosts = data.get("hosts", {}).get("data", [])
    host_names = {h["name"] for h in hosts}

    used: set[str] = set()
    for r in firewall_rules:
        used.update(r.get("source_networks", []))
        used.update(r.get("destination_networks", []))
    for r in nat_rules:
        for field in ("original_source", "translated_source", "original_destination", "translated_destination"):
            val = r.get(field, "")
            if val:
                used.add(val)

    unused = host_names - used - {"Any", ""}
    for h in sorted(unused):
        issues.append(_issue(INFO, "hosts", f"Host sin uso en reglas: '{h}'",
                             "El objeto existe pero no está referenciado en ninguna regla de firewall o NAT.", h))
    return issues


def _analyze_notifications(data: dict) -> list[dict]:
    issues = []
    notif = data.get("notification_settings", {}).get("data", [])
    if not notif:
        issues.append(_issue(WARNING, "notifications", "Sin notificaciones configuradas",
                             "Configurar alertas de eventos críticos (ataques, caídas de interfaz, login fallido)."))
    return issues


# ---------------------------------------------------------------------------
# Generador principal del reporte
# ---------------------------------------------------------------------------

def generate_audit_report(connection_info: dict, raw_data: dict) -> dict:
    """
    Genera el reporte completo de salud del firewall.

    Args:
        connection_info: Dict con name, host, port, etc. de la conexión guardada.
        raw_data: Resultado de SophosFirewallClient.collect_audit_data()

    Returns:
        Reporte estructurado con hallazgos y estadísticas.
    """
    generated_at = datetime.now(timezone.utc).isoformat()
    all_issues: list[dict] = []

    # Sistema
    admin_issues = _analyze_admin_users(raw_data)
    zones_data = raw_data.get("zones", {}).get("data", [])
    access_issues = _analyze_device_access(raw_data, zones_data)
    settings_issues = _analyze_admin_settings(raw_data)
    time_issues = _analyze_time_settings(raw_data)
    zone_issues = _analyze_zones(raw_data)
    notif_issues = _analyze_notifications(raw_data)

    # Reglas
    fw_issues, fw_stats = _analyze_firewall_rules(raw_data)
    nat_issues, nat_stats = _analyze_nat_rules(raw_data)

    # Objetos
    host_issues = _analyze_hosts(
        raw_data,
        raw_data.get("firewall_rules", {}).get("data", []),
        raw_data.get("nat_rules", {}).get("data", []),
    )

    all_issues = admin_issues + access_issues + settings_issues + time_issues + zone_issues + notif_issues + fw_issues + nat_issues + host_issues

    # Resumen
    summary = {
        "total_issues": len(all_issues),
        "critical": sum(1 for i in all_issues if i["severity"] == CRITICAL),
        "warning": sum(1 for i in all_issues if i["severity"] == WARNING),
        "info": sum(1 for i in all_issues if i["severity"] == INFO),
    }
    summary["score"] = _health_score(summary)

    system_raw = raw_data.get("system_status", {}).get("data", {})
    admin_raw = raw_data.get("admin_settings", {}).get("data", {})
    time_raw = raw_data.get("time_settings", {}).get("data", {})

    return {
        "connection": connection_info,
        "generated_at": generated_at,
        "summary": summary,
        "system": {
            "hostname": system_raw.get("Hostname", admin_raw.get("Hostname", "")),
            "model": system_raw.get("Model", ""),
            "firmware": system_raw.get("FirmwareVersion", raw_data.get("system_status", {}).get("data", {}).get("FirmwareVersion", "")),
            "uptime": system_raw.get("UpTime", ""),
            "timezone": time_raw.get("Timezone", ""),
            "ntp_servers": raw_data.get("time_settings", {}).get("data", {}).get("NTPServer", []),
        },
        "issues": all_issues,
        "sections": {
            "admin_users": {
                "data": raw_data.get("admin_users", {}).get("data", []),
                "issues": admin_issues + access_issues,
            },
            "firewall_rules": {
                "stats": fw_stats,
                "data": raw_data.get("firewall_rules", {}).get("data", []),
                "issues": fw_issues,
            },
            "nat_rules": {
                "stats": nat_stats,
                "data": raw_data.get("nat_rules", {}).get("data", []),
                "issues": nat_issues,
            },
            "zones": {
                "data": zones_data,
                "issues": zone_issues,
            },
            "interfaces": {
                "data": raw_data.get("interfaces", {}).get("data", []),
            },
            "hosts": {
                "data": raw_data.get("hosts", {}).get("data", []),
                "issues": host_issues,
            },
            "host_groups": {
                "data": raw_data.get("host_groups", {}).get("data", []),
            },
            "services": {
                "data": raw_data.get("services", {}).get("data", []),
            },
            "web_filter": {
                "data": raw_data.get("web_filter_policies", {}).get("data", []),
            },
            "app_filter": {
                "data": raw_data.get("app_filter_policies", {}).get("data", []),
            },
            "notifications": {
                "data": raw_data.get("notification_settings", {}).get("data", []),
                "issues": notif_issues,
            },
        },
    }


def _health_score(summary: dict) -> int:
    """Puntaje 0–100. Penaliza más los críticos que los warnings."""
    base = 100
    base -= summary["critical"] * 15
    base -= summary["warning"] * 5
    base -= summary["info"] * 1
    return max(0, min(100, base))
