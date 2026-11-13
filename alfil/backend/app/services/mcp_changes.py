"""Fase 2 del MCP: planificación de cambios de escritura (lista blanca, validación y diff). Lógica pura, sin E/S propia.

Solo cinco acciones, ninguna destructiva: crear regla, habilitar/deshabilitar regla, mover regla, crear host y crear servicio.
No hay borrados ni ediciones libres. Una regla nueva nace **deshabilitada** salvo que se pida lo contrario, y las reglas
Any→Any con acción accept se rechazan.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any, Callable

ACTIONS = ("create_rule", "set_rule_enabled", "move_rule", "create_host", "create_service")
RULES_PATH = "/firewall/rules/ipv4"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,49}$")
POSITIONS = ("top", "bottom", "before", "after")


class PlanError(ValueError):
    """Entrada inválida o cambio no permitido; el mensaje se muestra al agente."""


Reader = Callable[[str], list]  # path -> items


def snapshot_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf8")).hexdigest()[:16]


def _name(value: Any, field: str = "name") -> str:
    v = str(value or "").strip()
    if not NAME_RE.match(v):
        raise PlanError(f"`{field}` inválido ({v!r}): use 1–50 caracteres (letras, números, espacio, _ . -) y empiece por letra o número.")
    return v


def _items(read: Reader, path: str) -> dict[str, dict]:
    return {i.get("name"): i for i in read(path) if isinstance(i, dict)}


def _list(value: Any, field: str) -> list[str] | None:
    """None = «any» (omitido o 'any'); lista de nombres en otro caso."""
    if value is None or value == "" or value == "any" or value == ["any"]:
        return None
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise PlanError(f"`{field}` debe ser «any» o una lista de nombres.")
    return [v.strip() for v in value]


def _require_exist(names: list[str], known: dict[str, dict], what: str) -> None:
    missing = [n for n in names if n not in known]
    if missing:
        close = [k for k in known if any(m.lower() in k.lower() or k.lower() in m.lower() for m in missing)][:5]
        hint = f" ¿Quiso decir: {', '.join(close)}?" if close else ""
        raise PlanError(f"{what} inexistente(s): {', '.join(missing)}.{hint}")


def _plan(action: str, summary: str, method: str, path: str, payload: dict | None, before: Any, check: dict, warnings: list[str]) -> dict:
    return {"action": action, "summary": summary, "method": method, "path": path, "payload": payload, "before": before,
            "before_hash": snapshot_hash(before), "check": check, "warnings": warnings}


# ---------------------------------------------------------------------------
# Acciones
# ---------------------------------------------------------------------------

def plan_create_rule(p: dict, read: Reader) -> dict:
    name = _name(p.get("name"))
    action = str(p.get("action", "")).lower()
    if action not in ("accept", "drop", "reject"):
        raise PlanError("`action` debe ser accept, drop o reject.")
    rules = _items(read, RULES_PATH)
    if name in rules:
        raise PlanError(f"Ya existe una regla llamada «{name}».")
    zones = _items(read, "/network/zones")
    src_z, dst_z = _list(p.get("source_zones"), "source_zones"), _list(p.get("destination_zones"), "destination_zones")
    src_n, dst_n = _list(p.get("source_networks"), "source_networks"), _list(p.get("destination_networks"), "destination_networks")
    svcs = _list(p.get("services"), "services")
    if action == "accept" and not any((src_z, dst_z, src_n, dst_n, svcs)):
        raise PlanError("Política de ALFIL: no se crean reglas accept con zonas, redes y servicios «any» a la vez (Any→Any). Acote al menos un criterio.")
    for names, label in ((src_z, "Zona(s) de origen"), (dst_z, "Zona(s) de destino")):
        if names:
            _require_exist(names, zones, label)
    hosts = {**_items(read, "/network/addresses/ipv4"), **_items(read, "/network/address-groups/ipv4")}
    groups = _items(read, "/network/address-groups/ipv4")

    def nets(names):
        if not names:
            return {"any": True}
        return {"ipv4Addresses": [{"name": n} for n in names if n not in groups], "ipv4Groups": [{"name": n} for n in names if n in groups]}

    for names, label in ((src_n, "Red(es) de origen"), (dst_n, "Red(es) de destino")):
        if names:
            _require_exist(names, hosts, label)
    if svcs:
        service_items, service_groups = _items(read, "/network/services"), _items(read, "/network/service-groups")
        _require_exist(svcs, {**service_items, **service_groups}, "Servicio(s)")
        services = {"services": [{"name": n} for n in svcs if n not in service_groups], "serviceGroups": [{"name": n} for n in svcs if n in service_groups]}
    else:
        services = {"any": True}
    position = _position(p, rules)
    enabled = bool(p.get("enabled", False))
    log = bool(p.get("log_traffic", True))
    payload = {"name": name, "description": str(p.get("description", ""))[:200] or "Creada por ALFIL MCP", "ruleType": "firewall", "position": position["position"],
               "enabled": enabled, "action": action, "logTraffic": log,
               "sourceZones": {"zones": [{"name": n} for n in src_z]} if src_z else {"any": True},
               "destinationZones": {"zones": [{"name": n} for n in dst_z]} if dst_z else {"any": True},
               "sourceNetworks": nets(src_n), "destinationNetworks": nets(dst_n), "servicesOrGroups": services}
    if "referenceItem" in position:
        payload["referenceItem"] = position["referenceItem"]
    warnings = []
    if enabled:
        warnings.append("La regla se crea HABILITADA y empieza a aplicarse de inmediato.")
    if not log:
        warnings.append("La regla se crea sin registro de tráfico.")
    if action == "accept" and (not src_z or not dst_z):
        warnings.append("Regla accept con zona «any» en origen o destino: revise que no sea más amplia de lo previsto.")
    summary = (f"Crear regla «{name}» ({action}, {'habilitada' if enabled else 'DESHABILITADA'}): "
               f"{'/'.join(src_z or ['any'])} → {'/'.join(dst_z or ['any'])}, servicios {', '.join(svcs or ['any'])}; posición {_pos_text(position)}.")
    return _plan("create_rule", summary, "POST", RULES_PATH, payload, None, {"kind": "absent", "path": f"{RULES_PATH}/{name}"}, warnings)


def _position(p: dict, rules: dict[str, dict]) -> dict:
    pos = str(p.get("position", "bottom")).lower()
    if pos not in POSITIONS:
        raise PlanError("`position` debe ser top, bottom, before o after.")
    if pos in ("before", "after"):
        ref = str(p.get("reference") or "").strip()
        if ref not in rules:
            raise PlanError(f"Con position={pos} indique `reference` con el nombre de una regla existente (no existe: {ref or 'vacío'}).")
        return {"position": pos, "referenceItem": {"name": ref}}
    return {"position": pos}


def _pos_text(position: dict) -> str:
    return position["position"] + (f" «{position['referenceItem']['name']}»" if "referenceItem" in position else "")


def plan_set_rule_enabled(p: dict, read: Reader) -> dict:
    name = str(p.get("name") or "").strip()
    rules = _items(read, RULES_PATH)
    if name not in rules:
        raise PlanError(f"No existe la regla «{name}».")
    if not isinstance(p.get("enabled"), bool):
        raise PlanError("`enabled` debe ser true o false.")
    rule = rules[name]
    if bool(rule.get("enabled")) == p["enabled"]:
        raise PlanError(f"La regla «{name}» ya está {'habilitada' if p['enabled'] else 'deshabilitada'}: no hay nada que cambiar.")
    warnings = []
    if p["enabled"]:
        warnings.append("Al habilitar la regla empieza a aplicarse de inmediato; revise su posición y su alcance.")
    else:
        warnings.append("Al deshabilitar la regla el tráfico que decidía pasará a evaluarse por las reglas siguientes o por el descarte implícito.")
    state = "HABILITAR" if p["enabled"] else "DESHABILITAR"
    return _plan("set_rule_enabled", f"{state} la regla «{name}».", "PATCH", f"{RULES_PATH}/{name}", {"enabled": p["enabled"]},
                 {"name": name, "enabled": bool(rule.get("enabled"))}, {"kind": "field", "path": f"{RULES_PATH}/{name}", "field": "enabled", "value": p["enabled"]}, warnings)


def plan_move_rule(p: dict, read: Reader) -> dict:
    """La API solo mueve «before»/«after» otra regla: top y bottom se traducen a la primera y la última regla."""
    name = str(p.get("name") or "").strip()
    rules = _items(read, RULES_PATH)
    if name not in rules:
        raise PlanError(f"No existe la regla «{name}».")
    order = [r.get("name") for r in read(RULES_PATH)]
    position = _position(p, rules)
    wanted = position["position"]
    if wanted in ("top", "bottom"):
        if (wanted == "top" and order[0] == name) or (wanted == "bottom" and order[-1] == name):
            raise PlanError(f"La regla «{name}» ya está {'primera' if wanted == 'top' else 'última'}: no hay nada que mover.")
        position = {"position": "before" if wanted == "top" else "after", "referenceItem": {"name": order[0] if wanted == "top" else order[-1]}}
        label = f"{wanted} (justo {'antes de la primera' if wanted == 'top' else 'después de la última'} regla, «{position['referenceItem']['name']}»)"
    else:
        if position["referenceItem"]["name"] == name:
            raise PlanError("La regla de referencia no puede ser la misma regla.")
        label = _pos_text(position)
    payload = {"name": name, **position}
    warnings = ["Mover una regla cambia qué regla decide cada flujo. Compruebe el efecto con explain_rule_match antes y después."]
    return _plan("move_rule", f"Mover la regla «{name}» a {label}.", "POST", f"{RULES_PATH}/move", payload,
                 {"order": order}, {"kind": "order", "path": RULES_PATH, "name": name}, warnings)


def plan_create_host(p: dict, read: Reader) -> dict:
    name = _name(p.get("name"))
    if name in _items(read, "/network/addresses/ipv4"):
        raise PlanError(f"Ya existe un host llamado «{name}».")
    ip, net = p.get("ip"), p.get("network")
    if bool(ip) == bool(net):
        raise PlanError("Indique exactamente uno: `ip` (host) o `network` (CIDR, p. ej. 10.0.0.0/24).")
    try:
        if ip:
            payload = {"name": name, "type": "ipv4Address", "ipv4Address": str(ipaddress.IPv4Address(str(ip).strip()))}
            what = payload["ipv4Address"]
        else:
            n = ipaddress.IPv4Network(str(net).strip(), strict=True)
            payload = {"name": name, "type": "ipv4Network", "ipv4NetworkAddress": str(n.network_address), "cidr": n.prefixlen}
            what = str(n)
    except ValueError as exc:
        raise PlanError(f"Dirección inválida: {exc}") from exc
    if p.get("description"):
        payload["description"] = str(p["description"])[:200]
    return _plan("create_host", f"Crear host «{name}» = {what}.", "POST", "/network/addresses/ipv4", payload, None,
                 {"kind": "absent", "path": f"/network/addresses/ipv4/{name}"}, [])


def plan_create_service(p: dict, read: Reader) -> dict:
    name = _name(p.get("name"))
    if name in _items(read, "/network/services"):
        raise PlanError(f"Ya existe un servicio llamado «{name}».")
    proto = str(p.get("protocol", "")).lower()
    if proto not in ("tcp", "udp"):
        raise PlanError("`protocol` debe ser tcp o udp.")
    m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", str(p.get("port", "")).strip())
    if not m:
        raise PlanError("`port` debe ser un puerto (443) o un rango (8000-8100).")
    lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
    if not (1 <= lo <= hi <= 65535):
        raise PlanError("Puertos fuera de rango (1–65535) o rango invertido.")
    payload = {"name": name, "type": "tcpOrUdp", "services": [{"protocol": proto, "destinationPort": {"from": lo, "to": hi}, "sourcePort": {"from": 1, "to": 65535}}]}
    if p.get("description"):
        payload["description"] = str(p["description"])[:200]
    return _plan("create_service", f"Crear servicio «{name}» = {proto.upper()}/{lo if lo == hi else f'{lo}-{hi}'}.", "POST", "/network/services", payload, None,
                 {"kind": "absent", "path": f"/network/services/{name}"}, [])


PLANNERS = {"create_rule": plan_create_rule, "set_rule_enabled": plan_set_rule_enabled, "move_rule": plan_move_rule,
            "create_host": plan_create_host, "create_service": plan_create_service}


def build_plan(action: str, params: dict, read: Reader) -> dict:
    if action not in PLANNERS:
        raise PlanError(f"Acción no permitida: {action}. Permitidas: {', '.join(ACTIONS)}.")
    return PLANNERS[action](params or {}, read)


def current_state(plan: dict, read: Reader) -> Any:
    """Estado actual del recurso afectado (para detectar cambios entre la propuesta y la aplicación)."""
    if plan["action"] == "set_rule_enabled":
        rule = _items(read, RULES_PATH).get(plan["before"]["name"])
        return {"name": plan["before"]["name"], "enabled": bool(rule.get("enabled"))} if rule else None
    if plan["action"] == "move_rule":
        return {"order": [r.get("name") for r in read(RULES_PATH)]}
    return None


def drifted(plan: dict, read: Reader) -> str | None:
    """Motivo si el equipo cambió desde la propuesta (el cambio ya no es el que se revisó); None si sigue igual."""
    check = plan["check"]
    if check["kind"] == "absent":
        parent = check["path"].rsplit("/", 1)[0]
        if check["path"].rsplit("/", 1)[1] in _items(read, parent):
            return "El recurso ya existe: alguien lo creó después de la propuesta."
        return None
    if snapshot_hash(current_state(plan, read)) != plan["before_hash"]:
        return "El estado del equipo cambió después de la propuesta; vuelva a proponer el cambio."
    return None


def verify_applied(plan: dict, read: Reader) -> bool | None:
    """¿Se aplicó? True/False, o None si no se puede comprobar (p. ej. mover una regla)."""
    check = plan["check"]
    if check["kind"] == "absent":
        parent, leaf = check["path"].rsplit("/", 1)
        return leaf in _items(read, parent)
    if check["kind"] == "field":
        parent, leaf = check["path"].rsplit("/", 1)
        item = _items(read, parent).get(leaf)
        return bool(item) and item.get(check["field"]) == check["value"]
    if check["kind"] == "order":
        before = plan["before"]["order"]
        after = [r.get("name") for r in read(check["path"])]
        return after != before
    return None


def current_snapshot(plan: dict, client: Any) -> Any:
    """Copia previa del recurso que se va a tocar (obligatoria antes de aplicar; si falla, no se aplica). `client`: `_get`/`_get_all`."""
    if plan["action"] == "set_rule_enabled":
        return {"rule": client._get(plan["path"])}
    if plan["action"] == "move_rule":
        return {"order": [r.get("name") for r in client._get_all(RULES_PATH)]}
    return {"note": "Creación: no existía el recurso, no hay copia previa que guardar."}
