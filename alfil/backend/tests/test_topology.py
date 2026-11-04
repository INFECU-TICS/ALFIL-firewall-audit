"""Grafo de topología: datos sintéticos (rangos de documentación), mismo formato que producen los colectores."""
from app.services import rest_normalizers as nz
from app.services.topology import build_topology, zone_role


def ok(data):
    return {"success": True, "data": data}


def base_raw(**over):
    raw = {
        "zones": ok([{"name": "LAN", "type": "LAN"}, {"name": "WAN", "type": "WAN"}, {"name": "DMZ", "type": "DMZ"}, {"name": "VPN", "type": "VPN"}]),
        "interfaces": ok([
            {"name": "PortA", "zone": "LAN", "ip_address": "10.0.1.1", "netmask": "255.255.255.0", "interface_status": "ON", "type": "physical"},
            {"name": "PortB", "zone": "WAN", "ip_address": "203.0.113.2", "netmask": "255.255.255.252", "interface_status": "ON",
             "type": "physical", "gateway_ip": "203.0.113.1"},
            {"name": "PortC", "zone": "", "ip_address": "", "netmask": "", "interface_status": "OFF", "type": "physical"},
        ]),
        "vlans": ok([{"name": "PortA.10", "zone": "DMZ", "interface": "PortA", "vlan_id": 10, "ip_address": "10.0.10.1",
                      "netmask": "255.255.255.0", "interface_status": "ON"}]),
        "aliases": ok([{"name": "PortB:0", "interface": "PortB", "ip_address": "198.51.100.5", "netmask": "255.255.255.248"}]),
        "static_routes": ok([]),
        "vpn_ipsec_connections": ok([]),
        "hosts": ok([]),
    }
    raw.update(over)
    return raw


def ids(topo, type_=None):
    return {n["id"] for n in topo["nodes"] if type_ is None or n["type"] == type_}


def edge(topo, source, target):
    return any(e["source"] == source and e["target"] == target for e in topo["edges"])


def node(topo, node_id):
    return next(n for n in topo["nodes"] if n["id"] == node_id)


def test_zone_role():
    assert zone_role("Guest-WiFi", "") == "wifi" and zone_role("X", "WAN") == "wan" and zone_role("Servidores", "") == "other"


def test_zonas_interfaces_y_vlan_como_interfaz_fisica():
    t = build_topology(base_raw(), {"name": "fw-lab"})
    assert node(t, "fw")["label"] == "fw-lab"
    assert {"zone:LAN", "zone:WAN", "zone:DMZ"} <= ids(t, "zone")
    vlan = node(t, "if:PortA.10")  # la VLAN es una interfaz más, dentro de su zona
    assert vlan["type"] == "interface" and vlan["parent"] == "zone:DMZ" and vlan["data"]["kind"] == "vlan" and vlan["data"]["vlan_id"] == 10
    assert edge(t, "fw", "if:PortA") and edge(t, "fw", "if:PortA.10")
    assert edge(t, "if:PortA", "net:10.0.1.0/24") and edge(t, "if:PortA.10", "net:10.0.10.0/24")
    assert node(t, "if:PortC")["data"]["unconfigured"] is True


def test_alias_agrega_red_secundaria_a_la_interfaz():
    t = build_topology(base_raw())
    assert edge(t, "if:PortB", "net:198.51.100.0/29")


def test_wan_con_gateway_sale_a_internet():
    t = build_topology(base_raw())
    assert edge(t, "net:203.0.113.0/30", "rt:203.0.113.1") and edge(t, "rt:203.0.113.1", "internet")
    assert node(t, "rt:203.0.113.1")["data"]["gateway"] is True


def test_ruta_estatica_fw_router_red_remota():
    routes = ok([{"Name": "a-sucursal", "DestinationIP": "10.50.0.0", "Netmask": "255.255.255.0", "Gateway": "10.0.1.2", "Interface": "", "Distance": "1"}])
    t = build_topology(base_raw(static_routes=routes))
    assert edge(t, "net:10.0.1.0/24", "rt:10.0.1.2") and edge(t, "rt:10.0.1.2", "rn:10.50.0.0/24")
    assert node(t, "rt:10.0.1.2")["parent"] == "zone:LAN" and node(t, "rn:10.50.0.0/24")["parent"] == "zone:LAN"


def test_ruta_por_defecto_va_a_internet_sin_crear_red_remota():
    routes = ok([{"Name": "default", "DestinationIP": "0.0.0.0", "Netmask": "0.0.0.0", "Gateway": "203.0.113.1", "Interface": "PortB"}])
    t = build_topology(base_raw(static_routes=routes))
    assert edge(t, "rt:203.0.113.1", "internet")
    assert not any(n["id"].startswith("rn:0.0.0.0") for n in t["nodes"])
    assert len([n for n in t["nodes"] if n["type"] == "router"]) == 1  # el gateway de la interfaz y el salto de la ruta son el mismo nodo


def test_salto_inalcanzable_genera_advertencia_critica():
    routes = ok([{"Name": "rota", "DestinationIP": "10.70.0.0", "Netmask": "255.255.0.0", "Gateway": "192.168.99.1"}])
    t = build_topology(base_raw(static_routes=routes))
    assert node(t, "rt:192.168.99.1")["data"]["unreachable"] is True
    assert any(w["code"] == "route_nexthop_unreachable" and w["severity"] == "critical" for w in t["meta"]["warnings"])


def test_ruta_blackhole():
    routes = ok([{"Name": "bh", "DestinationIP": "10.99.0.0", "Netmask": "255.255.0.0", "Gateway": "", "Interface": "Blackhole"}])
    t = build_topology(base_raw(static_routes=routes))
    assert "bh:10.99.0.0/16" in ids(t, "blackhole")


def test_solapamiento_de_red_remota_con_red_conectada():
    routes = ok([{"Name": "solapa", "DestinationIP": "10.0.1.0", "Netmask": "255.255.255.128", "Gateway": "10.0.1.2"}])
    t = build_topology(base_raw(static_routes=routes))
    assert any(w["code"] == "overlapping_subnets" for w in t["meta"]["warnings"])


def test_vpn_fw_tunel_sitio_remoto_y_resolucion_de_redes():
    vpn = ok([{"name": "HQ", "status": "Enable", "connection_type": "policyBased", "local_gateway": "PortB",
               "remote_gateway": "198.51.100.77", "policy": "Default", "local_networks": ["LAN"], "remote_networks": ["Sucursal"]}])
    hosts = ok([{"name": "Sucursal", "type": "Network", "ip_address": "10.60.0.0", "subnet": "255.255.255.0"}])
    t = build_topology(base_raw(vpn_ipsec_connections=vpn, hosts=hosts))
    assert edge(t, "if:PortB", "vpn:HQ") and edge(t, "vpn:HQ", "site:198.51.100.77") and edge(t, "site:198.51.100.77", "rn:10.60.0.0/24")
    assert node(t, "vpn:HQ")["data"]["enabled"] is True


def test_vpn_deshabilitada_se_dibuja_punteada():
    vpn = ok([{"name": "off", "status": "Disable", "remote_gateway": "198.51.100.9", "remote_networks": []}])
    t = build_topology(base_raw(vpn_ipsec_connections=vpn))
    assert all(e["dashed"] for e in t["edges"] if e["kind"] == "vpn" and "vpn:off" in (e["source"], e["target"]))


def test_colector_fallido_deja_nota_y_no_rompe():
    t = build_topology(base_raw(static_routes={"success": False, "error": "timeout"}))
    assert any("Rutas estáticas no disponibles" in n for n in t["meta"]["notes"])
    assert any("ruteo dinámico" in n.lower() for n in t["meta"]["notes"])


def test_interfaz_con_ip_sin_zona_advierte():
    raw = base_raw(interfaces=ok([{"name": "PortZ", "zone": "", "ip_address": "10.9.9.1", "netmask": "255.255.255.0", "interface_status": "ON"}]))
    t = build_topology(raw)
    assert any(w["code"] == "interface_without_zone" for w in t["meta"]["warnings"])
    assert node(t, "if:PortZ")["parent"] == "zone:(sin zona)"


def test_ids_unicos_y_aristas_validas():
    routes = ok([{"DestinationIP": "10.50.0.0", "Netmask": "255.255.255.0", "Gateway": "10.0.1.2"},
                 {"DestinationIP": "10.51.0.0", "Netmask": "255.255.255.0", "Gateway": "10.0.1.2"}])
    t = build_topology(base_raw(static_routes=routes))
    node_ids = [n["id"] for n in t["nodes"]]
    assert len(node_ids) == len(set(node_ids))  # el router compartido no se duplica
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in t["edges"])
    assert all(n["parent"] is None or n["parent"] in node_ids for n in t["nodes"])


# --- Modo REST: JSON v23 -> normalizadores -> grafo ------------------------------------------------------
REST_IFACES = [
    {"name": "PortA", "type": "physical", "enabled": True, "hardwareName": "PortA", "zone": {"name": "LAN"},
     "ipv4": {"assignmentType": "static", "ipv4Address": "10.0.1.1", "cidr": 24, "secondaryAddresses": [{"ipv4Address": "10.0.2.1", "cidr": 24}]}},
    {"name": "PortA.10", "type": "vlan", "enabled": True, "zone": {"name": "DMZ"}, "vlanDetails": {"vlanId": 10, "parentInterface": {"name": "PortA"}},
     "ipv4": {"assignmentType": "static", "ipv4Address": "10.0.10.1", "cidr": 24}},
    {"name": "Lag1", "type": "lag", "enabled": True, "zone": {"name": "LAN"}, "lagDetails": {"members": [{"interface": {"name": "PortX"}}]},
     "ipv4": {"ipv4Address": "10.60.0.1", "cidr": 24}},
]


def test_rest_split_interfaces_en_claves_como_xml():
    parts = nz.split_interfaces(REST_IFACES)
    assert [i["name"] for i in parts["interfaces"]] == ["PortA"]
    assert parts["vlans"][0]["vlan_id"] == 10 and parts["vlans"][0]["interface"] == "PortA" and parts["vlans"][0]["netmask"] == "255.255.255.0"
    assert parts["lags"][0]["members"] == ["PortX"]
    assert parts["aliases"][0]["interface"] == "PortA" and parts["aliases"][0]["ip_address"] == "10.0.2.1"


def test_rest_ruta_vpn_y_host_normalizados():
    r = nz.normalize_static_route({"name": "r", "destinationAddressIpv4": "10.50.0.0", "cidr": 24, "gatewayIpv4": "10.0.1.2", "interface": None, "metric": 5})
    assert (r["DestinationIP"], r["Netmask"], r["Gateway"], r["Interface"]) == ("10.50.0.0", "255.255.255.0", "10.0.1.2", "")
    v = nz.normalize_vpn_ipsec({"name": "HQ", "type": "policyBased", "activateConnection": True, "profile": {"name": "P"},
                                "gatewaySettings": {"localGateway": {"name": "#Port2"}, "remoteGateway": {"ipv4Address": "203.0.113.20"}},
                                "protectedNetworks": {"localNetworksIpv4": {"ipv4Addresses": [{"ipv4Address": {"name": "LAN"}}]},
                                                      "remoteNetworksIpv4": {"ipv4Addresses": [{"name": "Sucursal"}]}}})
    assert (v["local_gateway"], v["remote_gateway"], v["local_networks"], v["remote_networks"], v["status"]) == ("Port2", "203.0.113.20", ["LAN"], ["Sucursal"], "Enable")
    h = nz.normalize_host({"name": "Sucursal", "type": "ipv4Network", "ipv4NetworkAddress": "10.60.0.0", "cidr": 24})
    assert (h["type"], h["ip_address"], h["subnet"]) == ("Network", "10.60.0.0", "255.255.255.0")


def test_rest_a_grafo_de_extremo_a_extremo():
    parts = nz.split_interfaces(REST_IFACES)
    raw = {k: ok(v) for k, v in parts.items()}
    raw["zones"] = ok([nz.normalize_zone({"name": n, "type": n.lower(), "services": []}) for n in ("LAN", "DMZ")])
    raw["static_routes"] = ok([nz.normalize_static_route({"name": "r", "destinationAddressIpv4": "10.50.0.0", "cidr": 24, "gatewayIpv4": "10.0.1.2"})])
    t = build_topology(raw, {"api_type": "rest", "name": "lab"})
    assert t["meta"]["source"] == "rest"
    assert node(t, "if:PortA.10")["parent"] == "zone:DMZ" and edge(t, "if:PortA", "net:10.0.2.0/24")  # alias
    assert edge(t, "net:10.0.1.0/24", "rt:10.0.1.2") and edge(t, "rt:10.0.1.2", "rn:10.50.0.0/24")
