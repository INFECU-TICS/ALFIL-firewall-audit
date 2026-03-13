import requests
import xmltodict
from typing import Optional, Dict, Any
import logging

# Disable SSL warnings for self-signed certificates
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class SophosFirewallClient:
    """Cliente para interactuar con la API XML de Sophos Firewall"""

    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}/webconsole/APIController"

    def _make_request(self, xml_payload: str, timeout: int = 30) -> tuple[bool, Any]:
        """Make a request to the Sophos API"""
        try:
            response = requests.post(
                self.base_url,
                data={"reqxml": xml_payload},
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=timeout
            )

            # Log only status, not credentials
            logger.info(f"Request to {self.host}:{self.port} - Status: {response.status_code}")

            if response.status_code == 401:
                return False, {"error": "Authentication failed - check credentials"}

            if response.status_code != 200:
                return False, {"error": f"HTTP {response.status_code}: {response.text}"}

            # Parse XML response
            try:
                data = xmltodict.parse(response.text)
                return True, data
            except Exception as e:
                return False, {"error": f"Failed to parse XML: {str(e)}"}

        except requests.exceptions.Timeout:
            return False, {"error": "Connection timeout - check if firewall is reachable"}
        except requests.exceptions.ConnectionError:
            return False, {"error": "Connection error - check host and port"}
        except requests.exceptions.RequestException as e:
            return False, {"error": f"Request failed: {str(e)}"}

    def test_connection(self) -> Dict[str, Any]:
        """Prueba autenticacion contra el firewall"""
        # Try to get a simple status request
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Get>
                <Admin>
                </Admin>
            </Get>
        </Request>
        """.format(username=self.username, password=self.password)

        success, result = self._make_request(xml_payload, timeout=10)

        if success:
            # Check if the response contains valid data
            if 'Response' in result and '@APIVersion' in result.get('Response', {}):
                return {
                    "success": True,
                    "message": "Connection successful",
                    "api_version": result['Response'].get('@APIVersion', 'Unknown'),
                    "firmware": result['Response'].get('@FWVersion', 'Unknown'),
                    "details": result
                }
            elif 'Response' in result and 'Login' in result.get('Response', {}):
                # Check for login error
                login_status = result['Response'].get('Login', {}).get('@status', '')
                if login_status == 'Failed':
                    return {
                        "success": False,
                        "message": "Authentication failed - invalid credentials",
                        "details": result
                    }

        return {
            "success": success,
            "message": result.get('error', 'Unknown error') if not success else "Connection successful",
            "details": result if success else None
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Obtiene estado general del sistema"""
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Get>
                <SystemStatus>
                </SystemStatus>
            </Get>
        </Request>
        """.format(username=self.username, password=self.password)

        success, result = self._make_request(xml_payload)

        if success and 'Response' in result:
            status_data = result['Response'].get('SystemStatus', {})
            return {
                "success": True,
                "data": {
                    "hostname": status_data.get('Hostname', 'Unknown'),
                    "firmware": status_data.get('FirmwareVersion', 'Unknown'),
                    "model": status_data.get('Model', 'Unknown'),
                    "uptime": status_data.get('UpTime', 'Unknown'),
                    "cpu": status_data.get('CPU', 'Unknown'),
                    "memory": status_data.get('Memory', 'Unknown'),
                    "disk": status_data.get('Disk', 'Unknown'),
                    "raw": status_data
                }
            }

        return {"success": False, "error": result.get('error', 'Failed to get system status')}

    def get_firewall_rules(self) -> Dict[str, Any]:
        """Obtiene reglas de firewall"""
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Get>
                <FirewallRule>
                </FirewallRule>
            </Get>
        </Request>
        """.format(username=self.username, password=self.password)

        success, result = self._make_request(xml_payload)

        if success and 'Response' in result:
            rules_data = result['Response'].get('FirewallRule', [])
            if not isinstance(rules_data, list):
                rules_data = [rules_data] if rules_data else []

            parsed_rules = []
            for rule in rules_data:
                if rule and isinstance(rule, dict):
                    parsed_rules.append({
                        "name": rule.get('@name', 'Unnamed'),
                        "description": rule.get('Description', ''),
                        "status": rule.get('Status', 'Unknown'),
                        "action": rule.get('Action', 'Unknown'),
                        "source_zones": rule.get('SourceZones', ''),
                        "destination_zones": rule.get('DestZones', ''),
                        "source_networks": rule.get('SourceNetworks', ''),
                        "destination_networks": rule.get('DestNetworks', ''),
                        "services": rule.get('Services', ''),
                        "raw": rule
                    })

            return {"success": True, "data": parsed_rules, "count": len(parsed_rules)}

        return {"success": False, "error": result.get('error', 'Failed to get firewall rules')}

    def get_network_zones(self) -> Dict[str, Any]:
        """Obtiene zonas de red configuradas"""
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Get>
                <Zone>
                </Zone>
            </Get>
        </Request>
        """.format(username=self.username, password=self.password)

        success, result = self._make_request(xml_payload)

        if success and 'Response' in result:
            zones_data = result['Response'].get('Zone', [])
            if not isinstance(zones_data, list):
                zones_data = [zones_data] if zones_data else []

            parsed_zones = []
            for zone in zones_data:
                if zone and isinstance(zone, dict):
                    parsed_zones.append({
                        "name": zone.get('@name', 'Unnamed'),
                        "type": zone.get('Type', 'Unknown'),
                        "description": zone.get('Description', ''),
                        "appliance_access": zone.get('ApplianceAccess', {}),
                        "raw": zone
                    })

            return {"success": True, "data": parsed_zones, "count": len(parsed_zones)}

        return {"success": False, "error": result.get('error', 'Failed to get network zones')}

    def get_interfaces(self) -> Dict[str, Any]:
        """Obtiene interfaces de red"""
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Get>
                <Interface>
                </Interface>
            </Get>
        </Request>
        """.format(username=self.username, password=self.password)

        success, result = self._make_request(xml_payload)

        if success and 'Response' in result:
            interfaces_data = result['Response'].get('Interface', [])
            if not isinstance(interfaces_data, list):
                interfaces_data = [interfaces_data] if interfaces_data else []

            parsed_interfaces = []
            for interface in interfaces_data:
                if interface and isinstance(interface, dict):
                    parsed_interfaces.append({
                        "name": interface.get('@name', 'Unnamed'),
                        "type": interface.get('Type', 'Unknown'),
                        "ip_address": interface.get('IPAddress', ''),
                        "netmask": interface.get('Netmask', ''),
                        "zone": interface.get('Zone', ''),
                        "status": interface.get('Status', 'Unknown'),
                        "raw": interface
                    })

            return {"success": True, "data": parsed_interfaces, "count": len(parsed_interfaces)}

        return {"success": False, "error": result.get('error', 'Failed to get interfaces')}
