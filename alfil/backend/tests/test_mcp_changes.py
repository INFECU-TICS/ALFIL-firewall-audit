"""Fase 2 del MCP: planificación de cambios (lista blanca, validación, diff y detección de cambios intermedios)."""
import pytest

from app.services import mcp_changes as mc

ANY = {"any": True}
DATA = {
    "/firewall/rules/ipv4": [{"name": "web", "enabled": True}, {"name": "dns", "enabled": False}, {"name": "ssh", "enabled": True}],
    "/network/zones": [{"name": "LAN"}, {"name": "WAN"}, {"name": "DMZ"}],
    "/network/addresses/ipv4": [{"name": "srv-web"}, {"name": "oficina"}],
    "/network/address-groups/ipv4": [{"name": "g-servidores"}],
    "/network/services": [{"name": "HTTPS"}, {"name": "SSH"}],
    "/network/service-groups": [{"name": "Web"}],
}


def read(path):
    return DATA.get(path, [])


def rule_params(**kw):
    return {"name": "ALFIL-web", "action": "accept", "source_zones": ["LAN"], "destination_zones": ["WAN"], "services": ["HTTPS"], **kw}


def test_crear_regla_nace_deshabilitada_y_arma_el_payload():
    plan = mc.build_plan("create_rule", rule_params(source_networks=["oficina", "g-servidores"], services=["HTTPS", "Web"]), read)
    pl = plan["payload"]
    assert plan["method"] == "POST" and plan["path"] == "/firewall/rules/ipv4" and pl["enabled"] is False and pl["position"] == "bottom"
    assert pl["sourceZones"] == {"zones": [{"name": "LAN"}]} and pl["destinationNetworks"] == ANY
    assert pl["sourceNetworks"] == {"ipv4Addresses": [{"name": "oficina"}], "ipv4Groups": [{"name": "g-servidores"}]}
    assert pl["servicesOrGroups"] == {"services": [{"name": "HTTPS"}], "serviceGroups": [{"name": "Web"}]}
    assert "DESHABILITADA" in plan["summary"] and plan["check"]["kind"] == "absent"


def test_crear_regla_habilitada_advierte():
    plan = mc.build_plan("create_rule", rule_params(enabled=True, log_traffic=False), read)
    assert any("HABILITADA" in w for w in plan["warnings"]) and any("sin registro" in w for w in plan["warnings"])


@pytest.mark.parametrize("params,msg", [
    ({"name": "web"}, "Ya existe"), ({"name": "mal;nombre"}, "inválido"), ({"action": "allow"}, "accept, drop o reject"),
    ({"source_zones": ["LANN"]}, "inexistente"), ({"source_networks": ["nadie"]}, "inexistente"), ({"services": ["FTP"]}, "inexistente"),
    ({"position": "before"}, "reference"), ({"position": "before", "reference": "zzz"}, "reference"), ({"position": "medio"}, "position"),
])
def test_crear_regla_rechaza_entradas_invalidas(params, msg):
    with pytest.raises(mc.PlanError, match=msg):
        mc.build_plan("create_rule", rule_params(**params), read)


def test_regla_any_any_accept_esta_bloqueada_pero_drop_si():
    base = {"name": "todo", "action": "accept"}
    with pytest.raises(mc.PlanError, match="Any→Any"):
        mc.build_plan("create_rule", base, read)
    assert mc.build_plan("create_rule", {**base, "action": "drop"}, read)["payload"]["action"] == "drop"


def test_sugerencia_de_nombre_parecido():
    with pytest.raises(mc.PlanError, match="srv-web"):
        mc.build_plan("create_rule", rule_params(destination_networks=["srv-we"]), read)


def test_posicion_relativa():
    pl = mc.build_plan("create_rule", rule_params(position="after", reference="web"), read)["payload"]
    assert pl["position"] == "after" and pl["referenceItem"] == {"name": "web"}


def test_habilitar_deshabilitar():
    plan = mc.build_plan("set_rule_enabled", {"name": "dns", "enabled": True}, read)
    assert plan["method"] == "PATCH" and plan["path"] == "/firewall/rules/ipv4/dns" and plan["payload"] == {"enabled": True} and "HABILITAR" in plan["summary"]
    assert any("de inmediato" in w for w in plan["warnings"])
    off = mc.build_plan("set_rule_enabled", {"name": "web", "enabled": False}, read)
    assert "DESHABILITAR" in off["summary"] and plan["before"] == {"name": "dns", "enabled": False}
    with pytest.raises(mc.PlanError, match="ya está"):
        mc.build_plan("set_rule_enabled", {"name": "web", "enabled": True}, read)
    with pytest.raises(mc.PlanError, match="No existe"):
        mc.build_plan("set_rule_enabled", {"name": "nada", "enabled": True}, read)
    with pytest.raises(mc.PlanError, match="true o false"):
        mc.build_plan("set_rule_enabled", {"name": "web", "enabled": "no"}, read)


def test_mover_regla():
    plan = mc.build_plan("move_rule", {"name": "ssh", "position": "before", "reference": "web"}, read)
    assert plan["path"] == "/firewall/rules/ipv4/move" and plan["payload"] == {"name": "ssh", "position": "before", "referenceItem": {"name": "web"}}
    assert plan["before"]["order"] == ["web", "dns", "ssh"]
    with pytest.raises(mc.PlanError, match="misma regla"):
        mc.build_plan("move_rule", {"name": "ssh", "position": "after", "reference": "ssh"}, read)


def test_mover_a_top_o_bottom_se_traduce_a_before_after_de_la_API():
    # La API de Sophos solo acepta before/after: «allowed values are [after before]» (verificado en el equipo)
    top = mc.build_plan("move_rule", {"name": "ssh", "position": "top"}, read)
    assert top["payload"] == {"name": "ssh", "position": "before", "referenceItem": {"name": "web"}} and "top" in top["summary"]
    bottom = mc.build_plan("move_rule", {"name": "web", "position": "bottom"}, read)
    assert bottom["payload"] == {"name": "web", "position": "after", "referenceItem": {"name": "ssh"}}
    with pytest.raises(mc.PlanError, match="ya está primera"):
        mc.build_plan("move_rule", {"name": "web", "position": "top"}, read)
    with pytest.raises(mc.PlanError, match="ya está última"):
        mc.build_plan("move_rule", {"name": "ssh", "position": "bottom"}, read)


def test_crear_host():
    h = mc.build_plan("create_host", {"name": "nuevo", "ip": "192.0.2.10"}, read)
    assert h["payload"] == {"name": "nuevo", "type": "ipv4Address", "ipv4Address": "192.0.2.10"}
    n = mc.build_plan("create_host", {"name": "red", "network": "198.51.100.0/24"}, read)
    assert n["payload"]["ipv4NetworkAddress"] == "198.51.100.0" and n["payload"]["cidr"] == 24
    for bad, msg in (({"name": "x"}, "exactamente uno"), ({"name": "x", "ip": "1", "network": "1.1.1.0/24"}, "exactamente uno"),
                     ({"name": "x", "ip": "999.1.1.1"}, "inválida"), ({"name": "x", "network": "10.0.0.5/24"}, "inválida"),
                     ({"name": "srv-web", "ip": "10.0.0.1"}, "Ya existe")):
        with pytest.raises(mc.PlanError, match=msg):
            mc.build_plan("create_host", bad, read)


def test_crear_servicio():
    s = mc.build_plan("create_service", {"name": "App", "protocol": "TCP", "port": "8000-8100"}, read)
    assert s["payload"]["services"][0] == {"protocol": "tcp", "destinationPort": {"from": 8000, "to": 8100}, "sourcePort": {"from": 1, "to": 65535}}
    assert "TCP/8000-8100" in s["summary"]
    for bad, msg in (({"name": "A", "protocol": "icmp", "port": "1"}, "tcp o udp"), ({"name": "A", "protocol": "tcp", "port": "70000"}, "fuera de rango"),
                     ({"name": "A", "protocol": "tcp", "port": "9-1"}, "fuera de rango"), ({"name": "A", "protocol": "tcp", "port": "x"}, "puerto"),
                     ({"name": "HTTPS", "protocol": "tcp", "port": "443"}, "Ya existe")):
        with pytest.raises(mc.PlanError, match=msg):
            mc.build_plan("create_service", bad, read)


def test_acciones_fuera_de_la_lista_blanca():
    for bad in ("delete_rule", "patch", "set_password", ""):
        with pytest.raises(mc.PlanError, match="no permitida"):
            mc.build_plan(bad, {}, read)


def test_deteccion_de_cambios_intermedios():
    plan = mc.build_plan("set_rule_enabled", {"name": "dns", "enabled": True}, read)
    assert mc.drifted(plan, read) is None
    changed = {**DATA, "/firewall/rules/ipv4": [{"name": "web", "enabled": True}, {"name": "dns", "enabled": True}]}
    assert "cambió" in mc.drifted(plan, lambda p: changed.get(p, []))
    create = mc.build_plan("create_host", {"name": "nuevo", "ip": "192.0.2.10"}, read)
    assert mc.drifted(create, read) is None
    taken = {**DATA, "/network/addresses/ipv4": [{"name": "nuevo"}]}
    assert "ya existe" in mc.drifted(create, lambda p: taken.get(p, []))
    move = mc.build_plan("move_rule", {"name": "ssh", "position": "top"}, read)
    reordered = {**DATA, "/firewall/rules/ipv4": [{"name": "ssh"}, {"name": "web"}, {"name": "dns"}]}
    assert mc.drifted(move, read) is None and mc.drifted(move, lambda p: reordered.get(p, [])) is not None


def test_verificar_aplicado_tras_un_timeout():
    create = mc.build_plan("create_host", {"name": "nuevo", "ip": "192.0.2.10"}, read)
    assert mc.verify_applied(create, read) is False
    assert mc.verify_applied(create, lambda p: [{"name": "nuevo"}]) is True
    en = mc.build_plan("set_rule_enabled", {"name": "dns", "enabled": True}, read)
    assert mc.verify_applied(en, read) is False
    assert mc.verify_applied(en, lambda p: [{"name": "dns", "enabled": True}]) is True
    move = mc.build_plan("move_rule", {"name": "ssh", "position": "top"}, read)
    assert mc.verify_applied(move, read) is False
    assert mc.verify_applied(move, lambda p: [{"name": "ssh"}, {"name": "web"}, {"name": "dns"}]) is True
