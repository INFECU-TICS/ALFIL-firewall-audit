import requests
import xmltodict
from typing import Any, Dict
import logging

from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class SophosFirewallClient:
    """Cliente para la API XML de Sophos Firewall (SFOS/XG)"""

    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = False):
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

    def _make_request(self, xml_payload: str, timeout: int = 10) -> tuple[bool, Any]:
        try:
            response = requests.post(
                self.base_url,
                data={"reqxml": xml_payload},
                verify=self.verify_ssl,
                timeout=timeout,
            )
            logger.info("Sophos API %s:%s → HTTP %s", self.host, self.port, response.status_code)

            if response.status_code == 401:
                return False, {"error": "Authentication failed"}
            if response.status_code != 200:
                return False, {"error": f"HTTP {response.status_code}: {response.text[:200]}"}

            try:
                data = xmltodict.parse(response.text)
                return True, data
            except Exception as e:
                return False, {"error": f"XML parse error: {e}"}

        except requests.exceptions.Timeout:
            return False, {"error": "Connection timeout"}
        except requests.exceptions.ConnectionError:
            return False, {"error": "Connection error – check host and port"}
        except requests.exceptions.RequestException as e:
            return False, {"error": f"Request failed: {e}"}

    @staticmethod
    def _to_list(value) -> list:
        """Normaliza None / dict / list → list."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    # -------------------------------------------------------------------------
    # Conectividad
    # -------------------------------------------------------------------------

    def test_connection(self) -> Dict[str, Any]:
        xml = self._build_xml("Admin")
        success, result = self._make_request(xml, timeout=10)
        if not success:
            return {"success": False, "message": result.get("error", "Unknown error")}

        response = result.get("Response", {})
        api_version = response.get("@APIVersion", "")
        fw_version = response.get("@FWVersion", "")

        login = response.get("Login", {})
        if isinstance(login, dict) and login.get("@status") == "Authentication Successful":
            return {"success": True, "message": "Connection successful", "api_version": api_version, "firmware": fw_version}

        if api_version:
            return {"success": True, "message": "Connection successful", "api_version": api_version, "firmware": fw_version}

        return {"success": False, "message": "Authentication failed – invalid credentials"}

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
        xml = self._build_xml("Admin")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        return {"success": True, "data": result.get("Response", {}).get("Admin", {})}

    def get_device_access(self) -> Dict[str, Any]:
        """Servicios habilitados por zona (WebAdmin, SSH, Ping, etc.)."""
        xml = self._build_xml("LocalServiceACL")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        data = self._to_list(result.get("Response", {}).get("LocalServiceACL"))
        return {"success": True, "data": data}

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
        return {"success": True, "data": self._to_list(result.get("Response", {}).get("NotificationList"))}

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
                "name": z.get("@name", ""),
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
                "name": i.get("@name", ""),
                "type": i.get("Type", ""),
                "ip_address": i.get("IPAddress", ""),
                "netmask": i.get("Netmask", ""),
                "zone": i.get("Zone", ""),
                "status": i.get("Status", ""),
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
                "name": h.get("@name", ""),
                "type": h.get("HostType", ""),
                "ip_address": h.get("IPAddress", ""),
                "subnet": h.get("Subnet", ""),
                "start_ip": h.get("StartIP", ""),
                "end_ip": h.get("EndIP", ""),
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
                "name": g.get("@name", ""),
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
            proto = s.get("Protocol", {})
            parsed.append({
                "name": s.get("@name", ""),
                "type": s.get("Type", ""),
                "protocol": proto.get("@name", "") if isinstance(proto, dict) else proto,
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
        xml = self._build_xml("FirewallRule")
        success, result = self._make_request(xml)
        if not success:
            return {"success": False, "error": result.get("error")}
        rules = self._to_list(result.get("Response", {}).get("FirewallRule"))
        parsed = []
        for r in rules:
            if not isinstance(r, dict):
                continue
            net_policy = r.get("NetworkPolicy", {}) if isinstance(r.get("NetworkPolicy"), dict) else {}
            parsed.append({
                "name": r.get("@name", ""),
                "description": r.get("Description", ""),
                "status": r.get("Status", ""),
                "position": r.get("Position", ""),
                "action": net_policy.get("Action", r.get("Action", "")),
                "source_zones": _extract_list(r, "SourceZones", "Zone"),
                "destination_zones": _extract_list(r, "DestinationZones", "Zone"),
                "source_networks": _extract_list(r, "SourceNetworks", "Network"),
                "destination_networks": _extract_list(r, "DestinationNetworks", "Network"),
                "services": _extract_list(r, "Services", "Service"),
                "log_traffic": r.get("LogTraffic", "Disable"),
                "policy_type": r.get("PolicyType", ""),
                "raw": r,
            })
        return {"success": True, "data": parsed, "count": len(parsed)}

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
            parsed.append({
                "name": r.get("@name", ""),
                "description": r.get("Description", ""),
                "status": r.get("Status", ""),
                "position": r.get("Position", ""),
                "nat_type": r.get("NATType", ""),
                "inbound_interface": r.get("InboundInterface", ""),
                "outbound_interface": r.get("OutboundInterface", ""),
                "source_zones": _extract_list(r, "OriginalSourceZone", "Zone"),
                "original_source": r.get("OriginalSource", ""),
                "translated_source": r.get("TranslatedSource", ""),
                "original_destination": r.get("OriginalDestination", ""),
                "translated_destination": r.get("TranslatedDestination", ""),
                "original_service": r.get("OriginalService", ""),
                "translated_service": r.get("TranslatedService", ""),
                "log_traffic": r.get("LogTraffic", "Disable"),
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
    # Recolección completa para auditoría
    # -------------------------------------------------------------------------

    def collect_audit_data(self) -> Dict[str, Any]:
        """Recolecta todos los datos en paralelo. Continúa aunque algún módulo falle."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        collectors = {
            "system_status": self.get_system_status,
            "admin_settings": self.get_admin_settings,
            "time_settings": self.get_time_settings,
            "device_access": self.get_device_access,
            "admin_users": self.get_admin_users,
            "zones": self.get_network_zones,
            "interfaces": self.get_interfaces,
            "hosts": self.get_hosts,
            "host_groups": self.get_host_groups,
            "services": self.get_services,
            "firewall_rules": self.get_firewall_rules,
            "nat_rules": self.get_nat_rules,
            "web_filter_policies": self.get_web_filter_policies,
            "app_filter_policies": self.get_app_filter_policies,
            "notification_settings": self.get_notification_settings,
        }
        results = {}
        with ThreadPoolExecutor(max_workers=8) as executor:
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
