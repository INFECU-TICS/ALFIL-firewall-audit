"""Acceso administrativo: MFA de administradores y exposición de los servicios de gestión (funciones puras).

Misma lógica que la web ALFIL en modo REST (`rest_normalizers.otp_applies_to_admin` y `build_device_access`).
"""
from __future__ import annotations

from typing import Any

ADMIN_SERVICES = ("https", "ssh")  # consola web y SSH
USER_FACING_SERVICES = ("userPortal", "sslVpn", "clientAuthentication")  # exposición menor, informativa
PSEUDO_USERS = ("known users", "unknown users")


def _name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name", ""))
    return value if isinstance(value, str) else ""


def _is_any(selector: Any) -> bool:
    return isinstance(selector, dict) and selector.get("any") is True


def _selector_names(selector: Any) -> list[str]:
    if not isinstance(selector, dict):
        return []
    out: list[str] = []
    for value in selector.values():
        if isinstance(value, list):
            out += [_name(v) for v in value if _name(v)]
    return out


def mfa_status(totp: dict[str, Any], admin: dict[str, Any]) -> tuple[bool, str]:
    """(MFA efectivo para la consola web, motivo si no lo es)."""
    if not totp.get("enabled"):
        return False, "OTP deshabilitado en el equipo"
    if "webAdminPortal" not in (totp.get("enabledFor") or []):
        return False, "OTP no aplicado a la consola de administración (webAdminPortal)"
    scope = totp.get("usersOrGroups") or {}
    if _is_any(scope):
        return True, ""
    users = {_name(u) for u in scope.get("users", [])}
    groups = {_name(g) for g in scope.get("userGroups", [])}
    if admin.get("name") in users or _name(admin.get("group")) in groups:
        return True, ""
    return False, "El alcance de OTP no incluye a este usuario ni a su grupo"


def audit_admin_access(admins: list[dict[str, Any]], totp: dict[str, Any], zones: list[dict[str, Any]],
                       acl_rules: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    accounts = []
    for a in admins:
        profile = _name((a.get("administrativePolicies") or {}).get("accessProfile"))
        if not profile or str(a.get("name", "")).lower() in PSEUDO_USERS:
            continue  # grupos y pseudo-usuarios sin perfil de administración
        ok, why = mfa_status(totp, a)
        allowed = (a.get("administrativePolicies") or {}).get("allowedNetworksIpv4")
        accounts.append({"name": a.get("name", ""), "profile": profile, "mfa": ok, "mfa_reason": why,
                         "allowed_networks": ["Any"] if _is_any(allowed) else _selector_names(allowed)})
        if not ok:
            findings.append({"severity": "critical", "code": "ADMIN_NO_MFA", "target": a.get("name", ""),
                             "message": f"El administrador «{a.get('name', '')}» no tiene MFA efectivo en la consola: {why}."})
        if _is_any(allowed):
            findings.append({"severity": "info", "code": "ADMIN_ANY_NETWORK", "target": a.get("name", ""),
                             "message": f"«{a.get('name', '')}» puede iniciar sesión desde cualquier red (sin restricción de origen)."})

    wan = {z.get("name", "") for z in zones if str(z.get("type", "")).lower() == "wan"}
    exposure = []
    for z in zones:
        names = [_name(s) for s in z.get("services", [])]
        admin = [s for s in names if s in ADMIN_SERVICES]
        if admin:
            exposure.append({"source": "zona", "zone": z.get("name", ""), "wan": z.get("name") in wan, "services": admin,
                             "networks": ["Any"]})
        if z.get("name") in wan:
            exposed = [s for s in names if s in USER_FACING_SERVICES]
            if exposed:
                findings.append({"severity": "info", "code": "WAN_USER_SERVICES", "target": z.get("name", ""),
                                 "message": f"La zona WAN «{z.get('name', '')}» expone servicios para usuarios: {', '.join(exposed)}."})
    for r in acl_rules:
        if str(r.get("action", "")).lower() != "accept":
            continue
        zone = _name(r.get("sourceZone"))
        services = [_name(s) for s in (r.get("services") or []) if _name(s) in ADMIN_SERVICES]
        if services:
            src = r.get("sourceNetworks")
            networks = ["Any"] if _is_any(src) or not src else _selector_names(src)
            exposure.append({"source": "regla de excepción", "rule": r.get("name", ""), "zone": zone, "wan": zone in wan,
                             "services": services, "networks": networks})

    for e in exposure:
        if not e["wan"]:
            continue
        where = e.get("rule") and f"la regla de excepción «{e['rule']}»" or f"la zona «{e['zone']}»"
        if "Any" in e["networks"]:
            findings.append({"severity": "critical", "code": "ADMIN_FROM_WAN", "target": e["zone"],
                             "message": f"{where[0].upper() + where[1:]} permite {', '.join(e['services'])} desde WAN sin restringir el origen: la administración queda expuesta a Internet."})
        else:
            findings.append({"severity": "warning", "code": "ADMIN_FROM_WAN_RESTRICTED", "target": e["zone"],
                             "message": f"{where[0].upper() + where[1:]} permite {', '.join(e['services'])} desde WAN solo para: {', '.join(e['networks'])}. Verifique que sean redes de confianza."})

    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f["severity"]])
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in order}
    return {"counts": counts, "findings": findings, "administrators": accounts, "admin_exposure": exposure,
            "totp": {"enabled": bool(totp.get("enabled")), "enabled_for": totp.get("enabledFor") or []},
            "limits": ["No evalúa la contraseña, el acceso por API ni el portal de usuarios; la exposición por zona y por reglas "
                       "de excepción se deduce de la configuración (no se prueba desde Internet).",
                       "Una zona WAN se reconoce por su tipo (`wan`)."]}
