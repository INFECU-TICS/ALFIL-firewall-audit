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
        reason = data.get("admin_users", {}).get("error") or "Verificar permisos de la cuenta."
        issues.append(_issue(INFO, "admin_users", "No se pudieron verificar los administradores (MFA/OTP no evaluado)", reason))
    return issues


def _analyze_device_access(data: dict, zones: list[dict]) -> list[dict]:
    issues = []
    acls = data.get("device_access", {}).get("data", [])
    wan_zone_names = {z["name"] for z in zones if z.get("type", "").lower() in ("wan", "external") or z["name"].lower() in WAN_ZONE_KEYWORDS}

    for acl in acls:
        if not isinstance(acl, dict):
            continue
        # Con la nueva estructura parseada, el campo es 'source_zone'
        zone = acl.get("source_zone", acl.get("SourceZone", ""))
        if zone.lower() in WAN_ZONE_KEYWORDS or zone in wan_zone_names:
            # Los servicios ya vienen como lista de strings
            services = acl.get("services", [])
            if not isinstance(services, list):
                services = []
            risky = [s for s in services if any(k in s.lower() for k in ("webadmin", "ssh", "console", "admin", "https", "api"))]
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
    hostname = (settings.get("HostnameSettings") or {}).get("HostName") or settings.get("Hostname", "")
    if not hostname:
        issues.append(_issue(INFO, "system", "Hostname no configurado", "Se recomienda configurar un hostname descriptivo."))

    # HTTPS certificate (auto-signed?)
    cert = (settings.get("WebAdminSettings") or {}).get("Certificate") or settings.get("Certificate", "")
    cert_reported = "WebAdminSettings" in settings or "Certificate" in settings  # REST no informa el certificado
    if cert_reported and str(cert).lower() in ("", "default", "appliance", "appliancecertificate"):
        issues.append(_issue(WARNING, "system", "Certificado de administración auto-firmado o por defecto",
                             "Usar un certificado firmado por una CA de confianza reduce riesgos de MITM en la consola."))
    return issues


def _analyze_time_settings(data: dict) -> list[dict]:
    issues = []
    t = data.get("time_settings", {}).get("data", {})
    if not t:
        issues.append(_issue(INFO, "system", "No se pudo obtener configuración de tiempo", "Verificar permisos de la cuenta API."))
        return issues

    timezone_val = t.get("TimeZone") or t.get("Timezone", "")
    issues.append(_issue(INFO, "system", f"Zona horaria configurada: {timezone_val or 'desconocida'}",
                         "Verificar que coincida con la zona horaria de la organización."))

    # NTP solo se evalúa si el firewall lo informa (v23 no devuelve datos de NTP en la entidad Time)
    ntp_reported = "NTPServer" in t or "PredefinedNTPServer" in t
    ntp_servers = t.get("NTPServer") or (t.get("PredefinedNTPServer", "").lower() == "enable")
    if ntp_reported and not ntp_servers:
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

    # Any-Any (criterio unificado con alfil-mcp): redes origen y destino "Any" Y servicios "Any", con acción Accept.
    # Las zonas no cuentan: LAN→WAN con todos los servicios sigue siendo permisiva; una regla acotada a SMTP no lo es.
    for r in enabled_rules:
        src = r.get("source_networks", [])
        dst = r.get("destination_networks", [])
        svc = r.get("services", [])
        action = r.get("action", "").lower()
        src_is_any = not src or src == ["Any"]
        dst_is_any = not dst or dst == ["Any"]
        svc_is_any = not svc or svc == ["Any"]
        if src_is_any and dst_is_any and svc_is_any and action == "accept":
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
    stats = {"total": len(rules), "enabled": 0, "disabled": 0, "dnat": 0, "snat": 0, "masq": 0}

    for r in rules:
        name = r.get("name", "?")
        if r.get("status", "").lower() in ("enable", "enabled"):
            stats["enabled"] += 1
        else:
            stats["disabled"] += 1
            issues.append(_issue(INFO, "nat_rules", f"Regla NAT deshabilitada: '{name}'",
                                 "Revisar si es obsoleta.", name))

        nat_type = r.get("nat_type", "")
        if nat_type == "DNAT":
            stats["dnat"] += 1
            issues.append(_issue(INFO, "nat_rules",
                                 f"Publicación DNAT: '{name}'",
                                 f"Publica hacia {r.get('translated_destination', '?')} desde interfaz(es): {', '.join(r.get('inbound_interfaces', [])) or 'cualquiera'}. Verificar que sea intencional.",
                                 name))
        elif nat_type == "MASQ":
            stats["masq"] += 1
        elif nat_type == "SNAT":
            stats["snat"] += 1

    return issues, stats


def _analyze_zones(data: dict) -> list[dict]:
    zones = data.get("zones", {}).get("data", [])
    issues = []
    wan_zones = [z for z in zones if z.get("type", "").lower() == "wan" or z.get("name", "").lower() in WAN_ZONE_KEYWORDS]
    if not wan_zones:
        issues.append(_issue(INFO, "zones", "No se identificaron zonas WAN", "Verificar la tipología de zonas del equipo."))
    return issues


def _analyze_hosts(data: dict, firewall_rules: list[dict], nat_rules: list[dict]) -> list[dict]:
    """Detecta hosts definidos que no se usan en ninguna regla."""
    issues = []
    hosts = data.get("hosts", {}).get("data", [])
    host_names = {h.get("name", "") for h in hosts if h.get("name", "")}

    used: set[str] = set()
    for r in firewall_rules:
        used.update(r.get("source_networks", []))
        used.update(r.get("destination_networks", []))
    for r in nat_rules:
        for field in ("translated_source", "translated_destination"):
            val = r.get(field, "")
            if val and val not in ("Original", "MASQ"):
                used.add(val)
        for net in r.get("original_source_networks", []):
            used.add(net)
        for net in r.get("original_destination_networks", []):
            used.add(net)

    unused = host_names - used - {"Any", ""}
    for h in sorted(unused):
        issues.append(_issue(INFO, "hosts", f"Host sin uso en reglas: '{h}'",
                             "El objeto existe pero no está referenciado en ninguna regla de firewall o NAT.", h))
    return issues


def _analyze_notifications(data: dict) -> list[dict]:
    issues = []
    notif = data.get("notification_settings", {}).get("data", [])
    # Hay una entrada con banderas SendEmail/SendSnmp: configurado si algún canal está habilitado
    configured = any(str(n.get(k, "")).lower() == "enable" for n in notif if isinstance(n, dict) for k in ("SendEmail", "SendSnmp"))
    if not configured:
        issues.append(_issue(WARNING, "notifications", "Sin notificaciones configuradas",
                             "Configurar alertas de eventos críticos (ataques, caídas de interfaz, login fallido)."))
    return issues


# ---------------------------------------------------------------------------
# Consolidación de interfaces con VLANs y Aliases
# ---------------------------------------------------------------------------

def _build_consolidated_interfaces(interfaces: list, vlans: list, aliases: list, zones: list) -> list:
    """
    Une interfaces físicas con sus VLANs y Aliases asociados.
    Agrega la zona como tag lookup desde la lista de zonas.
    """
    zone_types = {z.get("name", ""): z.get("type", "") for z in zones}

    # Mapa de VLANs y Aliases por interfaz padre
    vlan_map: dict[str, list] = {}
    for v in vlans:
        parent = v.get("interface", v.get("Interface", ""))
        vlan_map.setdefault(parent, []).append(v)

    alias_map: dict[str, list] = {}
    for a in aliases:
        parent = a.get("interface", a.get("Interface", ""))
        alias_map.setdefault(parent, []).append(a)

    result = []
    for iface in interfaces:
        name = iface.get("name", "")
        zone = iface.get("zone", "")
        result.append({
            **iface,
            "zone_type": zone_types.get(zone, ""),
            "vlans": vlan_map.get(name, []),
            "aliases": alias_map.get(name, []),
        })
    return result


# ---------------------------------------------------------------------------
# Agrupador de reglas por grupo
# ---------------------------------------------------------------------------

def _build_grouped_rules(rules: list[dict], groups: list[dict]) -> dict:
    """
    Devuelve un dict ordenado: {group_name: [rule_summary, ...]}
    Las reglas sin grupo van en "Sin grupo".
    """
    # Mapa: policy_name → group_name
    rule_to_group: dict[str, str] = {}
    group_order: list[str] = []
    for g in groups:
        gname = g.get("name", "")
        if gname and gname not in group_order:
            group_order.append(gname)
        for policy in g.get("policies", []):
            rule_to_group[policy] = gname

    grouped: dict[str, list] = {g: [] for g in group_order}
    grouped["Sin grupo"] = []

    for r in rules:
        rname = r.get("name", "")
        gname = rule_to_group.get(rname, "Sin grupo")
        if gname not in grouped:
            grouped[gname] = []
        grouped[gname].append({
            "name": rname,
            "description": r.get("description", ""),
            "status": r.get("status", ""),
            "policy_type": r.get("policy_type", ""),
            "action": r.get("action", ""),
            "log_traffic": r.get("log_traffic", ""),
            "source_zones": r.get("source_zones", []),
            "destination_zones": r.get("destination_zones", []),
            "source_networks": r.get("source_networks", []),
            "destination_networks": r.get("destination_networks", []),
            "services": r.get("services", []),
            "web_filter": r.get("web_filter", ""),
            "application_control": r.get("application_control", ""),
            "intrusion_prevention": r.get("intrusion_prevention", ""),
        })

    # Eliminar grupos vacíos (excepto "Sin grupo" si tiene entradas)
    return {k: v for k, v in grouped.items() if v}


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
            "hostname": system_raw.get("Hostname") or (admin_raw.get("HostnameSettings") or {}).get("HostName") or admin_raw.get("Hostname", ""),
            "model": system_raw.get("Model", ""),
            "firmware": system_raw.get("FirmwareVersion", raw_data.get("system_status", {}).get("data", {}).get("FirmwareVersion", "")),
            "uptime": system_raw.get("UpTime", ""),
            "timezone": time_raw.get("TimeZone") or time_raw.get("Timezone", ""),
            "ntp_servers": raw_data.get("time_settings", {}).get("data", {}).get("NTPServer", []),
        },
        "issues": all_issues,
        "sections": {
            # Usuarios y acceso
            "admin_users": {
                "data": raw_data.get("admin_users", {}).get("data", []),
                "issues": admin_issues + access_issues,
            },
            "auth_users": {
                "data": raw_data.get("auth_users", {}).get("data", []),
            },
            "device_access": {
                "data": raw_data.get("device_access", {}).get("data", []),
            },
            # Reglas
            "firewall_rules": {
                "stats": fw_stats,
                "data": raw_data.get("firewall_rules", {}).get("data", []),
                "issues": fw_issues,
            },
            "firewall_rule_groups": {
                "data": raw_data.get("firewall_rule_groups", {}).get("data", []),
            },
            "grouped_firewall_rules": {
                "data": _build_grouped_rules(
                    raw_data.get("firewall_rules", {}).get("data", []),
                    raw_data.get("firewall_rule_groups", {}).get("data", []),
                ),
            },
            "nat_rules": {
                "stats": nat_stats,
                "data": raw_data.get("nat_rules", {}).get("data", []),
                "issues": nat_issues,
            },
            "ssl_tls_rules": {
                "data": raw_data.get("ssl_tls_rules", {}).get("data", []),
            },
            "ssl_tls_settings": {
                "data": raw_data.get("ssl_tls_settings", {}).get("data"),
            },
            # Red
            "zones": {
                "data": zones_data,
                "issues": zone_issues,
            },
            "interfaces": {
                "data": _build_consolidated_interfaces(
                    raw_data.get("interfaces", {}).get("data", []),
                    raw_data.get("vlans", {}).get("data", []),
                    raw_data.get("aliases", {}).get("data", []),
                    zones_data,
                ),
            },
            "vlans": {
                "data": raw_data.get("vlans", {}).get("data", []),
            },
            "aliases": {
                "data": raw_data.get("aliases", {}).get("data", []),
            },
            "lags": {
                "data": raw_data.get("lags", {}).get("data", []),
            },
            "dns": {
                "data": raw_data.get("dns", {}).get("data"),
            },
            "dns_request_routes": {
                "data": raw_data.get("dns_request_routes", {}).get("data", []),
            },
            "gateways": {
                "data": raw_data.get("gateways", {}).get("data"),
            },
            # Enrutamiento
            "static_routes": {
                "data": raw_data.get("static_routes", {}).get("data", []),
            },
            "sdwan_policy_routes": {
                "data": raw_data.get("sdwan_policy_routes", {}).get("data", []),
            },
            "sdwan_profiles": {
                "data": raw_data.get("sdwan_profiles", {}).get("data", []),
            },
            "health_check_profiles": {
                "data": raw_data.get("health_check_profiles", {}).get("data", []),
            },
            # VPN
            "vpn_ipsec_connections": {
                "data": raw_data.get("vpn_ipsec_connections", {}).get("data", []),
            },
            # Objetos de red
            "hosts": {
                "data": raw_data.get("hosts", {}).get("data", []),
                "issues": host_issues,
            },
            "host_groups": {
                "data": raw_data.get("host_groups", {}).get("data", []),
            },
            "mac_hosts": {
                "data": raw_data.get("mac_hosts", {}).get("data", []),
            },
            "fqdn_hosts": {
                "data": raw_data.get("fqdn_hosts", {}).get("data", []),
            },
            "fqdn_host_groups": {
                "data": raw_data.get("fqdn_host_groups", {}).get("data", []),
            },
            # Servicios
            "services": {
                "data": raw_data.get("services", {}).get("data", []),
            },
            "service_groups": {
                "data": raw_data.get("service_groups", {}).get("data", []),
            },
            # Políticas de contenido
            "web_filter": {
                "data": raw_data.get("web_filter_policies", {}).get("data", []),
            },
            "web_filter_exceptions": {
                "data": raw_data.get("web_filter_exceptions", {}).get("data", []),
            },
            "app_filter": {
                "data": raw_data.get("app_filter_policies", {}).get("data", []),
            },
            # Políticas de administración
            "auth_users": {
                "data": raw_data.get("auth_users", {}).get("data", []),
            },
            "schedules": {
                "data": raw_data.get("schedules", {}).get("data", []),
            },
            "decryption_profiles": {
                "data": raw_data.get("decryption_profiles", {}).get("data", []),
            },
            "access_time_policies": {
                "data": raw_data.get("access_time_policies", {}).get("data", []),
            },
            "surfing_quota_policies": {
                "data": raw_data.get("surfing_quota_policies", {}).get("data", []),
            },
            "data_transfer_policies": {
                "data": raw_data.get("data_transfer_policies", {}).get("data", []),
            },
            "backup_restore": {
                "data": raw_data.get("backup_restore", {}).get("data"),
            },
            # Notificaciones
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
