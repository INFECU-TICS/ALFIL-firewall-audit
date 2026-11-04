import requests
import xmltodict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict
import logging

from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class SophosFirewallClient:
    """Cliente para la API XML de Sophos Firewall (SFOS/XG)"""

    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = False,
                 timeout: int | None = None, max_workers: int | None = None):
        from app.config import get_settings
        settings = get_settings()
        self.timeout = timeout or settings.sophos_request_timeout
        self.max_workers = max_workers or settings.sophos_collect_workers
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}/webconsole/APIController"

    def _build_xml(self, entity: str, extra: str = "") -> str:
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f"<Request>"
            f"<Login><Username>{self.username}</Username><Password>{self.password}</Password></Login>"
            f"<Get><{entity}>{extra}</{entity}></Get>"
            f"</Request>"
        )

    @staticmethod
    def _module_error(data: Any) -> str | None:
        """HTTP 200 no implica éxito: el firewall responde <Status code="529"> si la entidad no existe en esa versión."""
        response = data.get("Response", {}) if isinstance(data, dict) else {}
        for key, node in response.items():
            if key.startswith("@") or key == "Login" or not isinstance(node, dict):
                continue
            status = node.get("Status")
            if isinstance(status, dict) and status.get("@code") == "529" and set(node) <= {"Status", "@transactionid"}:
                return f"Entidad '{key}' no disponible en esta versión del firewall (529: {status.get('#text', 'módulo inválido')})"
        return None

    def _make_request(self, xml_payload: str, timeout: int | None = None) -> tuple[bool, Any]:
        timeout = timeout or self.timeout
        try:
            # multipart/form-data igual que: curl --form 'reqxml=...'
            response = requests.post(
                self.base_url,
                files={"reqxml": (None, xml_payload)},
                verify=self.verify_ssl,
                timeout=timeout,
            )
            logger.info("Sophos API %s:%s → HTTP %s", self.host, self.port, response.status_code)

            if response.status_code != 200:
                return False, {"error": f"HTTP {response.status_code}", "unreachable": True}

            try:
                data = xmltodict.parse(response.text)
            except Exception as e:
                return False, {"error": f"XML parse error: {e}"}
            module_error = self._module_error(data)
            if module_error:
                return False, {"error": module_error, "unsupported": True}
            return True, data

        except requests.exceptions.Timeout:
            return False, {"error": f"El equipo no responde (timeout de {timeout} s)", "unreachable": True}
        except requests.exceptions.ConnectionError:
            return False, {"error": "No se puede conectar – verifique host y puerto", "unreachable": True}
        except requests.exceptions.RequestException as e:
            return False, {"error": f"Error de red: {e}", "unreachable": True}

    def _make_request_with_raw(self, xml_payload: str, timeout: int | None = None) -> tuple[bool, Any, str]:
        """Como _make_request pero también devuelve el XML de respuesta sin parsear."""
        timeout = timeout or self.timeout
        try:
            response = requests.post(
                self.base_url,
                files={"reqxml": (None, xml_payload)},
                verify=self.verify_ssl,
                timeout=timeout,
            )
            raw = response.text
            if response.status_code != 200:
                return False, {"error": f"HTTP {response.status_code}", "unreachable": True}, raw
            try:
                data = xmltodict.parse(raw)
            except Exception as e:
                return False, {"error": f"XML parse error: {e}"}, raw
            module_error = self._module_error(data)
            if module_error:
                return False, {"error": module_error, "unsupported": True}, raw
            return True, data, raw
        except requests.exceptions.Timeout:
            return False, {"error": f"El equipo no responde (timeout de {timeout} s)", "unreachable": True}, ""
        except requests.exceptions.ConnectionError:
            return False, {"error": "No se puede conectar – verifique host y puerto", "unreachable": True}, ""
        except requests.exceptions.RequestException as e:
            return False, {"error": f"Error de red: {e}", "unreachable": True}, ""

    # Tipos de consulta disponibles en la página "Obtener Info"
    _QUERY_ENTITIES: dict = {
        "firewall_rules": "FirewallRule",
        "interface_info": None,  # multi-entity, manejado en run_query
        "users": "User",
        "host_objects": None,   # multi-entity: IPHost + MACHost + FQDNHost
        "services": "Services",
    }

    def run_query(self, query_type: str) -> Dict[str, Any]:
        """Ejecuta una consulta directa y devuelve raw_xml + datos parseados."""
        if query_type not in self._QUERY_ENTITIES:
            return {"success": False, "error": f"Tipo desconocido: {query_type}", "raw_xml": ""}

        # ---- Firewall Rules ----
        if query_type == "firewall_rules":
            xml = self._build_xml("FirewallRule")
            success, result, raw_xml = self._make_request_with_raw(xml)
            if not success:
                return {"success": False, "error": result.get("error"), "raw_xml": raw_xml}
            rules = self._to_list(result.get("Response", {}).get("FirewallRule"))
            parsed = []
            for r in rules:
                if not isinstance(r, dict):
                    continue
                policy_type = r.get("PolicyType", "")
                net = r.get("NetworkPolicy", {}) if isinstance(r.get("NetworkPolicy"), dict) else {}
                http = r.get("HTTPBasedPolicy", {}) if isinstance(r.get("HTTPBasedPolicy"), dict) else {}
                parsed.append({
                    "name": r.get("Name", ""),
                    "description": r.get("Description", ""),
                    "ip_family": r.get("IPFamily", ""),
                    "status": r.get("Status", ""),
                    "position": r.get("Position", ""),
                    "policy_type": policy_type,
                    "action": net.get("Action", ""),
                    "log_traffic": net.get("LogTraffic", "Disable"),
                    "schedule": net.get("Schedule", ""),
                    "source_zones": _extract_list(net, "SourceZones", "Zone"),
                    "destination_zones": _extract_list(net, "DestinationZones", "Zone"),
                    "source_networks": _extract_list(net, "SourceNetworks", "Network"),
                    "destination_networks": _extract_list(net, "DestinationNetworks", "Network"),
                    "services": _extract_list(net, "Services", "Service"),
                    "web_filter": net.get("WebFilter", ""),
                    "application_control": net.get("ApplicationControl", ""),
                    "intrusion_prevention": net.get("IntrusionPrevention", ""),
                    "hosted_address": http.get("HostedAddress", ""),
                    "listen_port": http.get("ListenPort", ""),
                    "domains": _extract_list(http, "Domains", "Domain"),
                })
            return {"success": True, "raw_xml": raw_xml, "data": parsed, "count": len(parsed)}

        # ---- Interface Info (Interface + VLAN + Alias + LAG) ----
        if query_type == "interface_info":
            with ThreadPoolExecutor(max_workers=4) as ex:
                f_iface = ex.submit(self._make_request_with_raw, self._build_xml("Interface"))
                f_vlan  = ex.submit(self._make_request_with_raw, self._build_xml("VLAN"))
                f_alias = ex.submit(self._make_request_with_raw, self._build_xml("Alias"))
                f_lag   = ex.submit(self._make_request_with_raw, self._build_xml("LAG"))

            ok_i, res_i, xml_i = f_iface.result()
            ok_v, res_v, xml_v = f_vlan.result()
            ok_a, res_a, xml_a = f_alias.result()
            ok_l, res_l, xml_l = f_lag.result()

            ifaces  = self._to_list(res_i.get("Response", {}).get("Interface")) if ok_i else []
            vlans   = self._to_list(res_v.get("Response", {}).get("VLAN"))      if ok_v else []
            aliases = self._to_list(res_a.get("Response", {}).get("Alias"))     if ok_a else []
            lags    = self._to_list(res_l.get("Response", {}).get("LAG"))       if ok_l else []

            parsed = []
            for i in ifaces:
                if not isinstance(i, dict):
                    continue
                name = i.get("Name", "")
                parsed.append({
                    "name": name,
                    "hardware": i.get("Hardware", ""),
                    "zone": i.get("NetworkZone", ""),
                    "interface_status": i.get("InterfaceStatus", ""),
                    "ip_address": i.get("IPAddress", ""),
                    "netmask": i.get("Netmask", ""),
                    "ipv4_assignment": i.get("IPv4Assignment", ""),
                    "mtu": i.get("MTU", ""),
                    "mac_address": i.get("MACAddress", ""),
                    "vlans": [
                        {
                            "name": v.get("Name", ""),
                            "vlan_id": v.get("VLANID", ""),
                            "zone": v.get("Zone", ""),
                            "ip_address": v.get("IPAddress", ""),
                            "netmask": v.get("Netmask", ""),
                            "status": v.get("InterfaceStatus", ""),
                        }
                        for v in vlans
                        if isinstance(v, dict) and v.get("Interface") == name
                    ],
                    "aliases": [
                        {
                            "name": a.get("Name", ""),
                            "ip_address": a.get("IPAddress", ""),
                            "netmask": a.get("Netmask", ""),
                        }
                        for a in aliases
                        if isinstance(a, dict) and a.get("Interface") == name
                    ],
                    "lags": [
                        {
                            "name": l.get("Name", ""),
                            "members": _extract_list(l, "Interfaces", "Interface")
                                       or _extract_list(l, "Members", "Member")
                                       or _extract_list(l, "Ports", "Port"),
                        }
                        for l in lags
                        if isinstance(l, dict) and l.get("Interface") == name
                    ],
                })

            # LAGs sin Interface padre (son interfaces por sí mismos)
            orphan_lags = [
                l for l in lags
                if isinstance(l, dict) and not l.get("Interface")
            ]
            for l in orphan_lags:
                parsed.append({
                    "name": l.get("Name", ""),
                    "hardware": "",
                    "zone": l.get("NetworkZone", l.get("Zone", "")),
                    "interface_status": l.get("InterfaceStatus", ""),
                    "ip_address": l.get("IPAddress", ""),
                    "netmask": l.get("Netmask", ""),
                    "ipv4_assignment": l.get("IPv4Assignment", ""),
                    "mtu": l.get("MTU", ""),
                    "mac_address": "",
                    "vlans": [], "aliases": [],
                    "lags": [{
                        "name": l.get("Name", ""),
                        "members": _extract_list(l, "Interfaces", "Interface")
                                   or _extract_list(l, "Members", "Member")
                                   or _extract_list(l, "Ports", "Port"),
                    }],
                })

            combined_xml = (
                f"<!-- Interface -->\n{xml_i}\n\n"
                f"<!-- VLAN -->\n{xml_v}\n\n"
                f"<!-- Alias -->\n{xml_a}\n\n"
                f"<!-- LAG -->\n{xml_l}"
            )
            return {"success": True, "raw_xml": combined_xml, "data": parsed, "count": len(parsed)}

        # ---- Users ----
        if query_type == "users":
            xml = self._build_xml("User")
            success, result, raw_xml = self._make_request_with_raw(xml)
            if not success:
                return {"success": False, "error": result.get("error"), "raw_xml": raw_xml}
            users = self._to_list(result.get("Response", {}).get("User"))
            parsed = []
            for u in users:
                if not isinstance(u, dict):
                    continue
                parsed.append({
                    "username": u.get("Username", ""),
                    "name": u.get("Name", ""),
                    "user_type": u.get("UserType", ""),
                    "group": u.get("Group", ""),
                    "status": u.get("Status", ""),
                    "ssl_vpn_policy": u.get("SSLVPNPolicy", ""),
                    "access_time_policy": u.get("AccessTimePolicy", ""),
                    "surfing_quota": u.get("SurfingQuotaPolicy", ""),
                    "login_restriction": u.get("LoginRestriction", ""),
                    "simultaneous_logins": u.get("SimultaneousLoginsGlobal", ""),
                })
            return {"success": True, "raw_xml": raw_xml, "data": parsed, "count": len(parsed)}

        # ---- Host Objects (IPHost + MACHost + FQDNHost) ----
        if query_type == "host_objects":
            with ThreadPoolExecutor(max_workers=3) as ex:
                f_ip   = ex.submit(self._make_request_with_raw, self._build_xml("IPHost"))
                f_mac  = ex.submit(self._make_request_with_raw, self._build_xml("MACHost"))
                f_fqdn = ex.submit(self._make_request_with_raw, self._build_xml("FQDNHost"))

            ok_ip,   res_ip,   xml_ip   = f_ip.result()
            ok_mac,  res_mac,  xml_mac  = f_mac.result()
            ok_fqdn, res_fqdn, xml_fqdn = f_fqdn.result()

            ip_hosts = self._to_list(res_ip.get("Response", {}).get("IPHost"))     if ok_ip   else []
            mac_hosts = self._to_list(res_mac.get("Response", {}).get("MACHost"))   if ok_mac  else []
            fqdn_hosts = self._to_list(res_fqdn.get("Response", {}).get("FQDNHost")) if ok_fqdn else []

            parsed_ip = []
            for h in ip_hosts:
                if not isinstance(h, dict):
                    continue
                parsed_ip.append({
                    "name": h.get("Name", ""),
                    "description": h.get("Description", ""),
                    "ip_family": h.get("IPFamily", ""),
                    "type": h.get("HostType", ""),
                    "ip_address": h.get("IPAddress", ""),
                    "subnet": h.get("Subnet", ""),
                    "start_ip": h.get("StartIPAddress", ""),
                    "end_ip": h.get("EndIPAddress", ""),
                })

            parsed_mac = []
            for h in mac_hosts:
                if not isinstance(h, dict):
                    continue
                mac_list_raw = h.get("MACList", {})
                macs = self._to_list(mac_list_raw.get("MACAddress")) if isinstance(mac_list_raw, dict) else []
                parsed_mac.append({
                    "name": h.get("Name", ""),
                    "description": h.get("Description", ""),
                    "type": h.get("Type", ""),
                    "mac_address": h.get("MACAddress", ""),
                    "mac_list": [m if isinstance(m, str) else str(m) for m in macs],
                })

            parsed_fqdn = []
            for h in fqdn_hosts:
                if not isinstance(h, dict):
                    continue
                group_list = h.get("FQDNHostGroupList", {})
                groups = self._to_list(group_list.get("FQDNHostGroup")) if isinstance(group_list, dict) else []
                parsed_fqdn.append({
                    "name": h.get("Name", ""),
                    "fqdn": h.get("FQDN", ""),
                    "description": h.get("Description", ""),
                    "groups": [g if isinstance(g, str) else str(g) for g in groups],
                })

            combined_xml = (
                f"<!-- IPHost -->\n{xml_ip}\n\n"
                f"<!-- MACHost -->\n{xml_mac}\n\n"
                f"<!-- FQDNHost -->\n{xml_fqdn}"
            )
            return {
                "success": True,
                "raw_xml": combined_xml,
                "data": {
                    "ip_hosts": parsed_ip,
                    "mac_hosts": parsed_mac,
                    "fqdn_hosts": parsed_fqdn,
                },
                "count": len(parsed_ip) + len(parsed_mac) + len(parsed_fqdn),
            }

        # ---- Services ----
        if query_type == "services":
            xml = self._build_xml("Services")
            success, result, raw_xml = self._make_request_with_raw(xml)
            if not success:
                return {"success": False, "error": result.get("error"), "raw_xml": raw_xml}
            services = self._to_list(result.get("Response", {}).get("Services"))
            parsed = []
            for s in services:
                if not isinstance(s, dict):
                    continue
                name = s.get("Name", "")
                svc_type = s.get("Type", "")
                # ServiceDetails puede tener uno o varios ServiceDetail
                details_wrap = s.get("ServiceDetails", {})
                details_raw = details_wrap.get("ServiceDetail", []) if isinstance(details_wrap, dict) else []
                details = self._to_list(details_raw)
                if details:
                    for d in details:
                        if not isinstance(d, dict):
                            continue
                        parsed.append({
                            "name": name,
                            "type": svc_type,
                            "protocol": d.get("Protocol", ""),
                            "src_port": d.get("SourcePort", "Any"),
                            "dst_port": d.get("DestinationPort", ""),
                            "icmp_type": d.get("ICMPType", ""),
                            "icmp_code": d.get("ICMPCode", ""),
                        })
                else:
                    # Servicio sin detalles (ej: ANY)
                    parsed.append({
                        "name": name,
                        "type": svc_type,
                        "protocol": "",
                        "src_port": "",
                        "dst_port": "",
                        "icmp_type": "",
                        "icmp_code": "",
                    })
            return {"success": True, "raw_xml": raw_xml, "data": parsed, "count": len(parsed)}

        return {"success": True, "raw_xml": "", "data": []}

    @staticmethod
    def _to_list(value) -> list:
        """Normaliza None / dict / list → list."""
        if value is None:
            return []
        items = value if isinstance(value, list) else [value]
        # Entidad vacía: el firewall devuelve <Entidad><Status>No. of records Zero.</Status></Entidad>
        return [i for i in items if not (isinstance(i, dict) and set(i) <= {"Status", "@transactionid"})]

    def _get_entity_list(self, entity_name: str) -> Dict[str, Any]:
        """Colector genérico: obtiene una entidad y devuelve la lista completa sin filtrar campos."""
        xml = self._build_xml(entity_name)
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        data = self._to_list(result.get("Response", {}).get(entity_name))
        return {"success": True, "data": data}

    # -------------------------------------------------------------------------
    # Conectividad
    # -------------------------------------------------------------------------

    def test_connection(self) -> Dict[str, Any]:
        """
        Autentica contra el firewall usando solo el bloque <Login>.
        Formato exacto: multipart/form-data con campo reqxml.
        Respuesta exitosa: HTTP 200 + <Login><status>Authentication Successful</status></Login>
        """
        xml = (
            "<Request>"
            f"<Login><Username>{self.username}</Username><Password>{self.password}</Password></Login>"
            "</Request>"
        )
        success, result = self._make_request(xml, timeout=10)

        if not success:
            # No-200 o error de red
            if result.get("unreachable"):
                return {"success": False, "message": result["error"]}
            return {"success": False, "message": result.get("error", "Error desconocido")}

        response = result.get("Response", {})
        api_version = response.get("@APIVersion", "")
        fw_version = response.get("@FWVersion", "")
        login = response.get("Login", {})

        # xmltodict parsea <status>texto</status> como {"status": "texto"} (sin @)
        status = login.get("status", "") if isinstance(login, dict) else ""

        if status == "Authentication Successful":
            return {
                "success": True,
                "message": "Autenticación exitosa",
                "api_version": api_version,
                "firmware": fw_version,
            }

        # HTTP 200 pero status distinto → credenciales incorrectas
        return {
            "success": False,
            "message": f"Credenciales incorrectas (status: {status or 'desconocido'})",
        }

    # -------------------------------------------------------------------------
    # Sistema
    # -------------------------------------------------------------------------

    def get_system_status(self) -> Dict[str, Any]:
        xml = self._build_xml("SystemStatus")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        return {"success": True, "data": result.get("Response", {}).get("SystemStatus", {})}

    def get_admin_settings(self) -> Dict[str, Any]:
        """Hostname, acceso por zona, configuración del panel de administración."""
        xml = self._build_xml("AdminSettings")  # v23: la entidad "Admin" responde 529
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        return {"success": True, "data": result.get("Response", {}).get("AdminSettings", {})}

    def get_device_access(self) -> Dict[str, Any]:
        """Reglas de ACL local: servicios habilitados por zona (WebAdmin, SSH, Ping, etc.)."""
        xml = self._build_xml("LocalServiceACL")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        acls = self._to_list(result.get("Response", {}).get("LocalServiceACL"))
        parsed = []
        for a in acls:
            if not isinstance(a, dict):
                continue
            parsed.append({
                "rule_name": a.get("RuleName", ""),
                "description": a.get("Description", ""),
                "position": a.get("Position", ""),
                "ip_family": a.get("IPFamily", ""),
                "source_zone": a.get("SourceZone", ""),
                "hosts": _extract_list(a, "Hosts", "Host"),
                "services": _extract_list(a, "Services", "Service"),
                "action": a.get("Action", ""),
                "raw": a,
            })
        return {"success": True, "data": parsed}

    def get_time_settings(self) -> Dict[str, Any]:
        xml = self._build_xml("Time")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        return {"success": True, "data": result.get("Response", {}).get("Time", {})}

    def get_notification_settings(self) -> Dict[str, Any]:
        xml = self._build_xml("NotificationList")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        response = result.get("Response", {})
        node = next((v for k, v in response.items() if k.lower() == "notificationlist"), None)  # v23: "Notificationlist"
        return {"success": True, "data": self._to_list(node)}

    # -------------------------------------------------------------------------
    # Administradores
    # -------------------------------------------------------------------------

    def get_admin_users(self) -> Dict[str, Any]:
        xml = self._build_xml("Administrator")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        users = self._to_list(result.get("Response", {}).get("Administrator"))
        parsed = []
        for u in users:
            if not isinstance(u, dict):
                continue
            parsed.append({
                "name": u.get("@name", u.get("Name", "Unknown")),
                "profile": u.get("Profile", ""),
                "email": u.get("EmailAddress", ""),
                "otp_enabled": str(u.get("OTPStatus", "Disable")).lower() in ("enable", "enabled", "true"),
                "login_restriction": u.get("LoginRestriction", ""),
                "allowed_networks": u.get("NetworkAddress", ""),
                "raw": u,
            })
        return {"success": True, "data": parsed}

    # -------------------------------------------------------------------------
    # Red
    # -------------------------------------------------------------------------

    def get_network_zones(self) -> Dict[str, Any]:
        xml = self._build_xml("Zone")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        zones = self._to_list(result.get("Response", {}).get("Zone"))
        parsed = []
        for z in zones:
            if not isinstance(z, dict):
                continue
            parsed.append({
                "name": z.get("Name", ""),
                "type": z.get("Type", ""),
                "description": z.get("Description", ""),
                "appliance_access": z.get("ApplianceAccess", {}),
                "raw": z,
            })
        return {"success": True, "data": parsed}

    def get_interfaces(self) -> Dict[str, Any]:
        xml = self._build_xml("Interface")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        ifaces = self._to_list(result.get("Response", {}).get("Interface"))
        parsed = []
        for i in ifaces:
            if not isinstance(i, dict):
                continue
            parsed.append({
                "name": i.get("Name", ""),
                "hardware": i.get("Hardware", ""),
                "zone": i.get("NetworkZone", ""),
                "interface_status": i.get("InterfaceStatus", ""),
                "ip_address": i.get("IPAddress", ""),
                "netmask": i.get("Netmask", ""),
                "ipv4_assignment": i.get("IPv4Assignment", ""),
                "status": i.get("Status", ""),
                "mtu": i.get("MTU", ""),
                "mac_address": i.get("MACAddress", ""),
                "raw": i,
            })
        return {"success": True, "data": parsed}

    # -------------------------------------------------------------------------
    # Objetos de red
    # -------------------------------------------------------------------------

    def get_hosts(self) -> Dict[str, Any]:
        xml = self._build_xml("IPHost")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        hosts = self._to_list(result.get("Response", {}).get("IPHost"))
        parsed = []
        for h in hosts:
            if not isinstance(h, dict):
                continue
            parsed.append({
                "name": h.get("Name", ""),
                "description": h.get("Description", ""),
                "ip_family": h.get("IPFamily", ""),
                "type": h.get("HostType", ""),
                "ip_address": h.get("IPAddress", ""),
                "subnet": h.get("Subnet", ""),
                "start_ip": h.get("StartIPAddress", ""),
                "end_ip": h.get("EndIPAddress", ""),
                "raw": h,
            })
        return {"success": True, "data": parsed}

    def get_host_groups(self) -> Dict[str, Any]:
        xml = self._build_xml("IPHostGroup")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        groups = self._to_list(result.get("Response", {}).get("IPHostGroup"))
        parsed = []
        for g in groups:
            if not isinstance(g, dict):
                continue
            host_list = g.get("HostList", {})
            if isinstance(host_list, dict):
                members = self._to_list(host_list.get("Host"))
            else:
                members = self._to_list(host_list)
            parsed.append({
                "name": g.get("Name", ""),
                "description": g.get("Description", ""),
                "hosts": [m if isinstance(m, str) else m.get("#text", str(m)) for m in members],
                "raw": g,
            })
        return {"success": True, "data": parsed}

    def get_services(self) -> Dict[str, Any]:
        xml = self._build_xml("Services")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        services = self._to_list(result.get("Response", {}).get("Services"))
        parsed = []
        for s in services:
            if not isinstance(s, dict):
                continue
            # ServiceDetails puede ser dict o lista
            details = s.get("ServiceDetails", {})
            if isinstance(details, dict):
                sd = details.get("ServiceDetail", {})
                if isinstance(sd, dict):
                    src_port = sd.get("SourcePort", "")
                    dst_port = sd.get("DestinationPort", "")
                    protocol = sd.get("Protocol", "")
                else:
                    src_port = dst_port = protocol = ""
            else:
                src_port = dst_port = protocol = ""
            parsed.append({
                "name": s.get("Name", ""),
                "type": s.get("Type", ""),
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "raw": s,
            })
        return {"success": True, "data": parsed}

    def get_service_groups(self) -> Dict[str, Any]:
        xml = self._build_xml("ServiceGroup")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        return {"success": True, "data": self._to_list(result.get("Response", {}).get("ServiceGroup"))}

    # -------------------------------------------------------------------------
    # Políticas de firewall
    # -------------------------------------------------------------------------

    def get_firewall_rules(self) -> Dict[str, Any]:
        """
        Obtiene todas las reglas de firewall.
        Los campos de tráfico están dentro de <NetworkPolicy> o <HTTPBasedPolicy>.
        """
        xml = self._build_xml("FirewallRule")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        rules = self._to_list(result.get("Response", {}).get("FirewallRule"))
        parsed = []
        for r in rules:
            if not isinstance(r, dict):
                continue
            policy_type = r.get("PolicyType", "")
            net = r.get("NetworkPolicy", {}) if isinstance(r.get("NetworkPolicy"), dict) else {}
            http = r.get("HTTPBasedPolicy", {}) if isinstance(r.get("HTTPBasedPolicy"), dict) else {}

            parsed.append({
                "name": r.get("Name", ""),
                "description": r.get("Description", ""),
                "ip_family": r.get("IPFamily", ""),
                "status": r.get("Status", ""),
                "position": r.get("Position", ""),
                "policy_type": policy_type,
                # Campos de NetworkPolicy
                "action": net.get("Action", ""),
                "log_traffic": net.get("LogTraffic", "Disable"),
                "schedule": net.get("Schedule", ""),
                "source_zones": _extract_list(net, "SourceZones", "Zone"),
                "destination_zones": _extract_list(net, "DestinationZones", "Zone"),
                "source_networks": _extract_list(net, "SourceNetworks", "Network"),
                "destination_networks": _extract_list(net, "DestinationNetworks", "Network"),
                "services": _extract_list(net, "Services", "Service"),
                "web_filter": net.get("WebFilter", ""),
                "application_control": net.get("ApplicationControl", ""),
                "intrusion_prevention": net.get("IntrusionPrevention", ""),
                "scan_virus": net.get("ScanVirus", ""),
                "decrypt_https": net.get("DecryptHTTPS", ""),
                # Campos de HTTPBasedPolicy (WAF)
                "hosted_address": http.get("HostedAddress", ""),
                "listen_port": http.get("ListenPort", ""),
                "domains": _extract_list(http, "Domains", "Domain"),
                "raw": r,
            })
        return {"success": True, "data": parsed, "count": len(parsed)}

    def get_firewall_rule_groups(self) -> Dict[str, Any]:
        """
        Obtiene los grupos de reglas de firewall.
        Cada grupo contiene una lista de SecurityPolicy (nombres de reglas).
        """
        xml = self._build_xml("FirewallRuleGroup")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        groups = self._to_list(result.get("Response", {}).get("FirewallRuleGroup"))
        parsed = []
        for g in groups:
            if not isinstance(g, dict):
                continue
            policy_list = g.get("SecurityPolicyList", {})
            if isinstance(policy_list, dict):
                policies = self._to_list(policy_list.get("SecurityPolicy"))
            else:
                policies = []
            parsed.append({
                "name": g.get("Name", ""),
                "description": g.get("Description", ""),
                "policy_type": g.get("Policytype", ""),
                "source_zones": _extract_list(g, "SourceZones", "Zone"),
                "policies": [p if isinstance(p, str) else str(p) for p in policies],
                "raw": g,
            })
        return {"success": True, "data": parsed}

    def get_nat_rules(self) -> Dict[str, Any]:
        xml = self._build_xml("NATRule")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        rules = self._to_list(result.get("Response", {}).get("NATRule"))
        parsed = []
        for r in rules:
            if not isinstance(r, dict):
                continue
            translated_src = r.get("TranslatedSource", "")
            translated_dst = r.get("TranslatedDestination", "")
            # Determinar tipo de NAT: DNAT si cambia destino, SNAT/MASQ si cambia origen
            if translated_dst not in ("", "Original"):
                nat_type = "DNAT"
            elif translated_src == "MASQ":
                nat_type = "MASQ"
            elif translated_src not in ("", "Original"):
                nat_type = "SNAT"
            else:
                nat_type = "NAT"
            parsed.append({
                "name": r.get("Name", ""),
                "description": r.get("Description", ""),
                "ip_family": r.get("IPFamily", ""),
                "status": r.get("Status", ""),
                "position": r.get("Position", ""),
                "nat_type": nat_type,
                "linked_firewall_rule": r.get("LinkedFirewallrule", ""),
                "original_source_networks": _extract_list(r, "OriginalSourceNetworks", "Network"),
                "original_destination_networks": _extract_list(r, "OriginalDestinationNetworks", "Network"),
                "original_services": _extract_list(r, "OriginalServices", "Service"),
                "translated_source": translated_src,
                "translated_destination": translated_dst,
                "translated_service": r.get("TranslatedService", ""),
                "inbound_interfaces": _extract_list(r, "InboundInterfaces", "Interface"),
                "outbound_interfaces": _extract_list(r, "OutboundInterfaces", "Interface"),
                "override_interface_nat": r.get("OverrideInterfaceNATPolicy", ""),
                "nat_method": r.get("NATMethod", ""),
                "health_check": r.get("HealthCheck", ""),
                "raw": r,
            })
        return {"success": True, "data": parsed, "count": len(parsed)}

    # -------------------------------------------------------------------------
    # Políticas de contenido
    # -------------------------------------------------------------------------

    def get_web_filter_policies(self) -> Dict[str, Any]:
        xml = self._build_xml("WebFilterPolicy")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        policies = self._to_list(result.get("Response", {}).get("WebFilterPolicy"))
        parsed = [
            {"name": p.get("@name", ""), "description": p.get("Description", ""), "default_action": p.get("DefaultAction", ""), "raw": p}
            for p in policies if isinstance(p, dict)
        ]
        return {"success": True, "data": parsed}

    def get_app_filter_policies(self) -> Dict[str, Any]:
        xml = self._build_xml("ApplicationFilterPolicy")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        policies = self._to_list(result.get("Response", {}).get("ApplicationFilterPolicy"))
        parsed = [
            {"name": p.get("@name", ""), "description": p.get("Description", ""), "raw": p}
            for p in policies if isinstance(p, dict)
        ]
        return {"success": True, "data": parsed}

    # -------------------------------------------------------------------------
    # Reglas y políticas adicionales
    # -------------------------------------------------------------------------

    def get_ssl_tls_rules(self) -> Dict[str, Any]:
        xml = self._build_xml("SSLTLSInspectionRule")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        rules = self._to_list(result.get("Response", {}).get("SSLTLSInspectionRule"))
        parsed = []
        for r in rules:
            if not isinstance(r, dict):
                continue
            parsed.append({
                "name": r.get("Name", ""),
                "description": r.get("Description", ""),
                "enabled": r.get("Enable", ""),
                "is_default": r.get("IsDefault", ""),
                "log_connections": r.get("LogConnections", ""),
                "source_zones": _extract_list(r, "SourceZones", "Zone"),
                "source_networks": _extract_list(r, "SourceNetworks", "Network"),
                "destination_zones": _extract_list(r, "DestinationZones", "Zone"),
                "destination_networks": _extract_list(r, "DestinationNetworks", "Network"),
                "services": _extract_list(r, "Services", "Service"),
                "decrypt_action": r.get("DecryptAction", ""),
                "decryption_profile": r.get("DecryptionProfile", ""),
                "raw": r,
            })
        return {"success": True, "data": parsed}

    def get_ssl_tls_settings(self) -> Dict[str, Any]:
        xml = self._build_xml("SSLTLSInspectionSettings")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        data = result.get("Response", {}).get("SSLTLSInspectionSettings", {})
        return {"success": True, "data": data}

    def get_web_filter_exceptions(self) -> Dict[str, Any]:
        return self._get_entity_list("WebFilterException")

    def get_decryption_profiles(self) -> Dict[str, Any]:
        xml = self._build_xml("DecryptionProfile")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        profiles = self._to_list(result.get("Response", {}).get("DecryptionProfile"))
        parsed = []
        for p in profiles:
            if not isinstance(p, dict):
                continue
            parsed.append({
                "name": p.get("Name", ""),
                "description": p.get("Description", ""),
                "is_default": p.get("IsDefault", ""),
                "min_tls_version": p.get("MinTLSVersion", ""),
                "max_tls_version": p.get("MaxTLSVersion", ""),
                "block_untrusted_issuer": p.get("BlockUntrustedIssuer", ""),
                "block_invalid_date": p.get("BlockInvalidDate", ""),
                "block_self_signed": p.get("BlockSelfSigned", ""),
                "block_revoked": p.get("BlockRevoked", ""),
                "ssl_v2_v3": p.get("SSLv2SSLv3", ""),
                "raw": p,
            })
        return {"success": True, "data": parsed}

    # -------------------------------------------------------------------------
    # Red adicional
    # -------------------------------------------------------------------------

    def get_vlans(self) -> Dict[str, Any]:
        xml = self._build_xml("VLAN")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        vlans = self._to_list(result.get("Response", {}).get("VLAN"))
        parsed = []
        for v in vlans:
            if not isinstance(v, dict):
                continue
            parsed.append({
                "name": v.get("Name", ""),
                "vlan_id": v.get("VLANID", ""),
                "zone": v.get("Zone", ""),
                "interface": v.get("Interface", ""),
                "hardware": v.get("Hardware", ""),
                "interface_status": v.get("InterfaceStatus", ""),
                "ip_address": v.get("IPAddress", ""),
                "netmask": v.get("Netmask", ""),
                "ipv4_assignment": v.get("IPv4Assignment", ""),
                "status": v.get("Status", ""),
                "raw": v,
            })
        return {"success": True, "data": parsed}

    def get_aliases(self) -> Dict[str, Any]:
        xml = self._build_xml("Alias")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        aliases = self._to_list(result.get("Response", {}).get("Alias"))
        parsed = []
        for a in aliases:
            if not isinstance(a, dict):
                continue
            parsed.append({
                "name": a.get("Name", ""),
                "interface": a.get("Interface", ""),
                "ip_family": a.get("IPFamily", ""),
                "ip_address": a.get("IPAddress", ""),
                "netmask": a.get("Netmask", ""),
                "raw": a,
            })
        return {"success": True, "data": parsed}

    def get_lags(self) -> Dict[str, Any]:
        return self._get_entity_list("LAG")

    def get_dns(self) -> Dict[str, Any]:
        xml = self._build_xml("DNS")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        data = result.get("Response", {}).get("DNS", {})
        return {"success": True, "data": data}

    def get_dns_request_routes(self) -> Dict[str, Any]:
        return self._get_entity_list("DNSRequestRoute")

    def get_gateways(self) -> Dict[str, Any]:
        xml = self._build_xml("GatewayConfiguration")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        data = result.get("Response", {}).get("GatewayConfiguration", {})
        return {"success": True, "data": data}

    # -------------------------------------------------------------------------
    # Enrutamiento
    # -------------------------------------------------------------------------

    def get_static_routes(self) -> Dict[str, Any]:
        xml = self._build_xml("UnicastRoute")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        raw = self._to_list(result.get("Response", {}).get("UnicastRoute"))
        # Filtrar respuesta vacía ("No. of records Zero.")
        data = [r for r in raw if isinstance(r, dict) and "DestinationIP" in r]
        return {"success": True, "data": data}

    def get_sdwan_policy_routes(self) -> Dict[str, Any]:
        xml = self._build_xml("SDWANPolicyRoute")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        routes = self._to_list(result.get("Response", {}).get("SDWANPolicyRoute"))
        parsed = []
        for r in routes:
            if not isinstance(r, dict):
                continue
            parsed.append({
                "name": r.get("Name", ""),
                "description": r.get("Description", ""),
                "ip_family": r.get("IPFamily", ""),
                "status": "Enable" if str(r.get("Status", "")).strip() == "1" else r.get("Status", ""),
                "link_selection": r.get("LinkSelection", ""),
                "gateway": r.get("Gateway", ""),
                "backup_gateway": r.get("BackupGateway", ""),
                "healthcheck": r.get("Healthcheck", ""),
                "source_networks": _extract_list(r, "SourceNetworks", "Network"),
                "destination_networks": _extract_list(r, "DestinationNetworks", "Network"),
                "services": _extract_list(r, "Services", "Service"),
                "raw": r,
            })
        return {"success": True, "data": parsed}

    def get_sdwan_profiles(self) -> Dict[str, Any]:
        return self._get_entity_list("SDWANProfile")

    def get_health_check_profiles(self) -> Dict[str, Any]:
        return self._get_entity_list("HealthCheckProfile")

    # -------------------------------------------------------------------------
    # VPN
    # -------------------------------------------------------------------------

    def get_vpn_ipsec_connections(self) -> Dict[str, Any]:
        xml = self._build_xml("VPNIPSecConnection")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        raw = self._to_list(result.get("Response", {}).get("VPNIPSecConnection"))
        parsed = []
        for v in raw:
            if not isinstance(v, dict):
                continue
            # Puede venir como {"Configuration": {"Status": "No. of records Zero."}} cuando vacío
            conf = v.get("Configuration", v)
            if isinstance(conf, dict) and "No. of records" in str(conf.get("Status", "")):
                continue
            # Si no es vacío, buscar campos directamente o dentro de Configuration
            item = conf if isinstance(conf, dict) else v
            parsed.append({
                "name": item.get("Name", v.get("Name", "")),
                "description": item.get("Description", ""),
                "status": item.get("ConnectionStatus", item.get("Status", "")),
                "connection_type": item.get("ConnectionType", ""),
                "local_gateway": item.get("LocalGateway", ""),
                "remote_gateway": item.get("RemoteGateway", ""),
                "policy": item.get("Policy", ""),
                # Campos de redes protegidas: nombres de etiqueta por confirmar con un equipo que tenga VPN (best-effort)
                "local_networks": _flatten_strings({k: x for k, x in item.items() if "local" in k.lower() and ("subnet" in k.lower() or "network" in k.lower())}),
                "remote_networks": _flatten_strings({k: x for k, x in item.items() if "remote" in k.lower() and ("subnet" in k.lower() or "network" in k.lower())}),
                "raw": v,
            })
        return {"success": True, "data": parsed}

    # -------------------------------------------------------------------------
    # Objetos adicionales
    # -------------------------------------------------------------------------

    def get_mac_hosts(self) -> Dict[str, Any]:
        xml = self._build_xml("MACHost")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        hosts = self._to_list(result.get("Response", {}).get("MACHost"))
        parsed = []
        for h in hosts:
            if not isinstance(h, dict):
                continue
            mac_list = h.get("MACList", {})
            if isinstance(mac_list, dict):
                macs = self._to_list(mac_list.get("MACAddress"))
            else:
                macs = []
            parsed.append({
                "name": h.get("Name", ""),
                "description": h.get("Description", ""),
                "type": h.get("Type", ""),
                "mac_address": h.get("MACAddress", ""),
                "mac_list": [m if isinstance(m, str) else str(m) for m in macs],
                "raw": h,
            })
        return {"success": True, "data": parsed}

    def get_fqdn_hosts(self) -> Dict[str, Any]:
        xml = self._build_xml("FQDNHost")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        hosts = self._to_list(result.get("Response", {}).get("FQDNHost"))
        parsed = []
        for h in hosts:
            if not isinstance(h, dict):
                continue
            group_list = h.get("FQDNHostGroupList", {})
            if isinstance(group_list, dict):
                groups = self._to_list(group_list.get("FQDNHostGroup"))
            else:
                groups = []
            parsed.append({
                "name": h.get("Name", ""),
                "fqdn": h.get("FQDN", ""),
                "description": h.get("Description", ""),
                "groups": [g if isinstance(g, str) else str(g) for g in groups],
                "raw": h,
            })
        return {"success": True, "data": parsed}

    def get_fqdn_host_groups(self) -> Dict[str, Any]:
        xml = self._build_xml("FQDNHostGroup")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        groups = self._to_list(result.get("Response", {}).get("FQDNHostGroup"))
        parsed = []
        for g in groups:
            if not isinstance(g, dict):
                continue
            parsed.append({
                "name": g.get("Name", ""),
                "description": g.get("Description", ""),
                "raw": g,
            })
        return {"success": True, "data": parsed}

    # -------------------------------------------------------------------------
    # Autenticación
    # -------------------------------------------------------------------------

    def get_auth_users(self) -> Dict[str, Any]:
        xml = self._build_xml("User")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        users = self._to_list(result.get("Response", {}).get("User"))
        parsed = []
        for u in users:
            if not isinstance(u, dict):
                continue
            parsed.append({
                "username": u.get("Username", ""),
                "name": u.get("Name", ""),
                "user_type": u.get("UserType", ""),
                "group": u.get("Group", ""),
                "status": u.get("Status", ""),
                "ssl_vpn_policy": u.get("SSLVPNPolicy", ""),
                "access_time_policy": u.get("AccessTimePolicy", ""),
                "surfing_quota": u.get("SurfingQuotaPolicy", ""),
                "login_restriction": u.get("LoginRestriction", ""),
                "simultaneous_logins": u.get("SimultaneousLoginsGlobal", ""),
                "raw": u,
            })
        return {"success": True, "data": parsed}

    # -------------------------------------------------------------------------
    # Administración adicional
    # -------------------------------------------------------------------------

    def get_backup_restore(self) -> Dict[str, Any]:
        xml = self._build_xml("BackupRestore")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        raw = result.get("Response", {}).get("BackupRestore", {})
        sched = raw.get("ScheduleBackup", {}) if isinstance(raw, dict) else {}
        data = {
            "mode": sched.get("BackupMode", ""),
            "prefix": sched.get("BackupPrefix", ""),
            "frequency": sched.get("BackupFrequency", ""),
            "day": sched.get("Day", sched.get("Date", "")),
            "time": f"{sched.get('Hour', '00')}:{sched.get('Minute', '00')}",
            "email": sched.get("EmailAddress", ""),
            "ftp_server": sched.get("FTPServer", ""),
            "ftp_path": sched.get("FtpPath", ""),
            "ftp_user": sched.get("Username", ""),
        }
        return {"success": True, "data": data}

    def get_schedules(self) -> Dict[str, Any]:
        xml = self._build_xml("Schedule")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        schedules = self._to_list(result.get("Response", {}).get("Schedule"))
        parsed = []
        for s in schedules:
            if not isinstance(s, dict):
                continue
            # Extraer detalle(s) del horario
            details = s.get("ScheduleDetails", {})
            if isinstance(details, dict):
                detail = details.get("ScheduleDetail", {})
                if isinstance(detail, dict):
                    days = detail.get("Days", "")
                    start = detail.get("StartTime", "")
                    stop = detail.get("StopTime", "")
                elif isinstance(detail, list):
                    days = "; ".join(d.get("Days", "") for d in detail if isinstance(d, dict))
                    start = detail[0].get("StartTime", "") if detail else ""
                    stop = detail[0].get("StopTime", "") if detail else ""
                else:
                    days = start = stop = ""
            else:
                days = start = stop = ""
            parsed.append({
                "name": s.get("Name", ""),
                "description": s.get("Description", ""),
                "type": s.get("Type", ""),
                "days": days,
                "start_time": start,
                "stop_time": stop,
                "raw": s,
            })
        return {"success": True, "data": parsed}

    def get_access_time_policies(self) -> Dict[str, Any]:
        return self._get_entity_list("AccessTimePolicy")

    def get_surfing_quota_policies(self) -> Dict[str, Any]:
        return self._get_entity_list("SurfingQuotaPolicy")

    def get_data_transfer_policies(self) -> Dict[str, Any]:
        return self._get_entity_list("DataTransferPolicy")

    # -------------------------------------------------------------------------
    # Recolección completa para auditoría
    # -------------------------------------------------------------------------

    def collect_audit_data(self) -> Dict[str, Any]:
        """Recolecta todos los datos en paralelo. Continúa aunque algún módulo falle."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        collectors = {
            # Sistema
            "system_status":          self.get_system_status,
            "admin_settings":         self.get_admin_settings,
            "time_settings":          self.get_time_settings,
            "device_access":          self.get_device_access,
            "notification_settings":  self.get_notification_settings,
            "backup_restore":         self.get_backup_restore,
            # Administradores
            "admin_users":            self.get_admin_users,
            # Red
            "zones":                  self.get_network_zones,
            "interfaces":             self.get_interfaces,
            "vlans":                  self.get_vlans,
            "aliases":                self.get_aliases,
            "lags":                   self.get_lags,
            "dns":                    self.get_dns,
            "dns_request_routes":     self.get_dns_request_routes,
            "gateways":               self.get_gateways,
            # Enrutamiento
            "static_routes":          self.get_static_routes,
            "sdwan_policy_routes":    self.get_sdwan_policy_routes,
            "sdwan_profiles":         self.get_sdwan_profiles,
            "health_check_profiles":  self.get_health_check_profiles,
            # Objetos de red
            "hosts":                  self.get_hosts,
            "host_groups":            self.get_host_groups,
            "mac_hosts":              self.get_mac_hosts,
            "fqdn_hosts":             self.get_fqdn_hosts,
            "fqdn_host_groups":       self.get_fqdn_host_groups,
            # Servicios
            "services":               self.get_services,
            "service_groups":         self.get_service_groups,
            # Reglas de firewall y NAT
            "firewall_rules":         self.get_firewall_rules,
            "firewall_rule_groups":   self.get_firewall_rule_groups,
            "nat_rules":              self.get_nat_rules,
            # SSL/TLS
            "ssl_tls_rules":          self.get_ssl_tls_rules,
            "ssl_tls_settings":       self.get_ssl_tls_settings,
            # Políticas de contenido
            "web_filter_policies":    self.get_web_filter_policies,
            "web_filter_exceptions":  self.get_web_filter_exceptions,
            "app_filter_policies":    self.get_app_filter_policies,
            # VPN
            "vpn_ipsec_connections":  self.get_vpn_ipsec_connections,
            # Autenticación
            "auth_users":             self.get_auth_users,
            # Políticas de administración
            "schedules":              self.get_schedules,
            "decryption_profiles":    self.get_decryption_profiles,
            "access_time_policies":   self.get_access_time_policies,
            "surfing_quota_policies": self.get_surfing_quota_policies,
            "data_transfer_policies": self.get_data_transfer_policies,
        }
        results = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_key = {executor.submit(fn): key for key, fn in collectors.items()}
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    results[key] = future.result()
                except Exception as e:
                    logger.warning("Collector '%s' failed: %s", key, e)
                    results[key] = {"success": False, "error": str(e)}
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_strings(value: Any) -> list:
    """Aplana str/dict/list anidados (salida de xmltodict) a una lista de textos."""
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, dict):
        return [t for v in value.values() for t in _flatten_strings(v)]
    if isinstance(value, list):
        return [t for v in value for t in _flatten_strings(v)]
    return []


def _extract_list(rule: dict, container_key: str, item_key: str) -> list:
    """Extrae una lista de strings de estructuras anidadas del XML parseado."""
    container = rule.get(container_key)
    if not container:
        return []
    if isinstance(container, str):
        return [container]
    if isinstance(container, dict):
        items = container.get(item_key, [])
        if isinstance(items, str):
            return [items]
        if isinstance(items, list):
            return [i if isinstance(i, str) else i.get("#text", str(i)) for i in items]
    return []
