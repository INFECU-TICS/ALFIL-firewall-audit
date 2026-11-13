"""Cliente de la REST API v1 de Sophos Firewall v23 (/api/firewall-config/v1, Bearer token). Solo lectura.

Expone la misma interfaz que SophosFirewallClient (XML) y devuelve datos normalizados al mismo formato,
de modo que el auditor y el frontend no distinguen el modo de conexión.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict

import requests
import urllib3

from app.services import rest_normalizers as nz

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

BASE_PATH = "/api/firewall-config/v1"
PAGE_SIZE = 100  # máximo documentado en la spec OpenAPI
FALLBACK_PAGE_SIZE = 50  # algunas rutas (p. ej. /application/policies) solo admiten 50 y responden 400 «Invalid page size»
UNSUPPORTED = {"success": False, "error": "No disponible aún en modo REST", "unsupported": True}

# Claves que produce collect_audit_data del cliente XML; las no implementadas en REST se marcan como no disponibles.
ALL_KEYS = (
    "system_status", "admin_settings", "time_settings", "device_access", "notification_settings", "backup_restore",
    "admin_users", "zones", "interfaces", "vlans", "aliases", "lags", "dns", "dns_request_routes", "gateways",
    "static_routes", "sdwan_policy_routes", "sdwan_profiles", "health_check_profiles", "hosts", "host_groups",
    "mac_hosts", "fqdn_hosts", "fqdn_host_groups", "services", "service_groups", "firewall_rules",
    "firewall_rule_groups", "nat_rules", "ssl_tls_rules", "ssl_tls_settings", "web_filter_policies",
    "web_filter_exceptions", "app_filter_policies", "vpn_ipsec_connections", "auth_users", "schedules",
    "decryption_profiles", "access_time_policies", "surfing_quota_policies", "data_transfer_policies",
)


class RestError(RuntimeError):
    pass


class SophosRestClient:
    api_type = "rest"

    def __init__(self, host: str, port: int, api_key: str, verify_ssl: bool = False,
                 timeout: int | None = None, max_workers: int | None = None):
        from app.config import get_settings
        settings = get_settings()
        self.host, self.port, self.verify_ssl = host, port, verify_ssl
        self.timeout = timeout or settings.sophos_request_timeout
        self.max_workers = max_workers or settings.sophos_collect_workers
        self.base_url = f"https://{host}:{port}{BASE_PATH}"
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {api_key}", "Accept": "application/json"})

    # -- HTTP ---------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> Any:
        try:
            resp = self._session.get(self.base_url + path, params=params, verify=self.verify_ssl, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise RestError(f"El equipo no responde (timeout de {self.timeout} s)")
        except requests.exceptions.SSLError:
            raise RestError("Error TLS: certificado no verificable (desactive 'Verificar SSL' para equipos con certificado propio)")
        except requests.exceptions.ConnectionError:
            raise RestError("No se puede conectar – verifique host y puerto")
        except requests.exceptions.RequestException as e:
            raise RestError(f"Error de red: {type(e).__name__}")
        if resp.status_code in (401, 403):
            raise RestError(f"API key rechazada (HTTP {resp.status_code}). Verifique la clave y que la IP de ALFIL esté permitida en Administration › API access.")
        if resp.status_code == 404:
            raise RestError("Ruta no encontrada: ¿el firewall es v23 con la API REST habilitada?")
        if resp.status_code >= 400:
            try:
                detail = str(resp.json().get("message", ""))
            except (ValueError, AttributeError):
                detail = ""
            raise RestError(f"HTTP {resp.status_code}: {detail}" if detail else f"HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError:
            raise RestError("Respuesta no es JSON")

    def _get_all(self, path: str, params: dict | None = None, max_items: int = 5000) -> list[dict]:
        items: list[dict] = []
        page, size = 1, PAGE_SIZE
        while len(items) < max_items:
            try:
                data = self._get(path, {**(params or {}), "page": page, "pageSize": size})
            except RestError as e:
                if page == 1 and size == PAGE_SIZE and "page size" in str(e).lower():
                    size = FALLBACK_PAGE_SIZE  # la ruta admite un tamaño menor: reintentar desde el inicio
                    continue
                raise
            batch = data.get("items", []) if isinstance(data, dict) else []
            items.extend(batch)
            if len(batch) < size:
                break
            page += 1
        return items

    # -- Conectividad -------------------------------------------------------

    def test_connection(self) -> Dict[str, Any]:
        try:
            self._get("/network/zones", {"pageSize": 1})
        except RestError as e:
            return {"success": False, "message": str(e)}
        return {"success": True, "message": "Autenticación exitosa (REST API v1)", "api_version": "REST v1", "firmware": ""}

    # -- Colectores ---------------------------------------------------------

    def _list(self, path: str, normalize: Callable[..., dict], positional: bool = False) -> Dict[str, Any]:
        try:
            items = self._get_all(path)
        except RestError as e:
            return {"success": False, "error": str(e)}
        data = [normalize(x, i + 1) if positional else normalize(x) for i, x in enumerate(items)]
        return {"success": True, "data": data, "count": len(data)}

    def get_firewall_rules(self):
        return self._list("/firewall/rules/ipv4", nz.normalize_firewall_rule, positional=True)

    def get_nat_rules(self):
        return self._list("/nat/rules/ipv4", nz.normalize_nat_rule, positional=True)

    def get_network_zones(self):
        return self._list("/network/zones", nz.normalize_zone)

    def get_hosts(self):
        try:
            hosts = [h for h in self._get_all("/network/addresses/ipv4") if not h.get("isInternal")]
        except RestError as e:
            return {"success": False, "error": str(e)}
        return {"success": True, "data": [nz.normalize_host(h) for h in hosts]}

    def get_services(self):
        return self._list("/network/services", nz.normalize_named_object)

    def get_service_groups(self):
        return self._list("/network/service-groups", nz.normalize_named_object)

    def get_interface_bundle(self) -> Dict[str, Dict[str, Any]]:
        """Un solo pedido alimenta interfaces, vlans, lags y aliases (en REST son el mismo recurso)."""
        try:
            parts = nz.split_interfaces(self._get_all("/network/interfaces/network-interfaces"))
        except RestError as e:
            err = {"success": False, "error": str(e)}
            return {k: dict(err) for k in ("interfaces", "vlans", "lags", "aliases")}
        return {k: {"success": True, "data": v, "count": len(v)} for k, v in parts.items()}

    def get_interfaces(self):
        return self.get_interface_bundle()["interfaces"]

    def get_static_routes(self):
        return self._list("/routing/static-unicast-routes/ipv4", nz.normalize_static_route)

    def get_vpn_ipsec_connections(self):
        return self._list("/ipsec-vpn/site-to-site/connections/ipv4", nz.normalize_vpn_ipsec)

    def get_gateways(self):
        return self._list("/routing/gateways/ipv4", nz.normalize_gateway)

    def get_admin_users(self):
        try:
            admins = self._get_all("/authentication/users/administrators")
            totp = self._get("/authentication/multi-factor-authentication/totp-settings")
        except RestError as e:
            return {"success": False, "error": str(e)}
        return {"success": True, "data": nz.normalize_admins(admins, totp if isinstance(totp, dict) else {})}

    def get_admin_settings(self):
        try:
            return {"success": True, "data": nz.normalize_admin_settings(self._get("/administration/system-settings"))}
        except RestError as e:
            return {"success": False, "error": str(e)}

    def get_notification_settings(self):
        try:
            return {"success": True, "data": nz.normalize_notifications(self._get("/notification/notifications"))}
        except RestError as e:
            return {"success": False, "error": str(e)}

    def get_device_access(self):
        try:
            zones = self._get_all("/network/zones")
            acl = self._get_all("/acl-exception-rules/ipv4")
        except RestError as e:
            return {"success": False, "error": str(e)}
        return {"success": True, "data": nz.build_device_access(zones, acl)}

    # -- Objetos, políticas y ajustes adicionales ---------------------------

    def _simple(self, path: str, normalize: Callable[[dict], dict]) -> Dict[str, Any]:
        return self._list(path, normalize)

    def get_host_groups(self):
        return self._simple("/network/address-groups/ipv4", nz.normalize_host_group)

    def get_mac_hosts(self):
        return self._simple("/network/addresses/mac", nz.normalize_mac_host)

    def get_fqdn_hosts(self):
        try:
            hosts, groups = self._get_all("/network/addresses/fqdn"), self._get_all("/network/address-groups/fqdn")
        except RestError as e:
            return {"success": False, "error": str(e)}
        data = nz.normalize_fqdn_hosts(hosts, groups)
        return {"success": True, "data": data, "count": len(data)}

    def get_fqdn_host_groups(self):
        return self._simple("/network/address-groups/fqdn", nz.normalize_fqdn_group)

    def get_schedules(self):
        return self._simple("/administration/schedules", nz.normalize_schedule)

    def get_auth_users(self):
        return self._simple("/authentication/users", nz.normalize_user)

    def get_ssl_tls_rules(self):
        return self._simple("/tls-inspection/rules/ipv4", nz.normalize_tls_rule)

    def get_decryption_profiles(self):
        return self._simple("/tls-inspection/decryption-profiles", nz.normalize_decryption_profile)

    def get_web_filter_policies(self):
        return self._simple("/web/policies", nz.normalize_policy)

    def get_web_filter_exceptions(self):
        return self._simple("/web/exceptions", nz.normalize_named_object)

    def get_app_filter_policies(self):
        return self._simple("/application/policies", nz.normalize_policy)

    def get_dns_request_routes(self):
        return self._simple("/network/dns/request-routes", nz.normalize_named_object)

    def get_access_time_policies(self):
        return self._simple("/authentication/policies/access-times", nz.normalize_named_object)

    def get_surfing_quota_policies(self):
        return self._simple("/authentication/policies/surfing-quotas", nz.normalize_named_object)

    def get_data_transfer_policies(self):
        return self._simple("/authentication/policies/network-traffic-quotas", nz.normalize_named_object)

    def _single(self, path: str, normalize: Callable[[dict], Any] = lambda d: d) -> Dict[str, Any]:
        try:
            data = self._get(path)
        except RestError as e:
            return {"success": False, "error": str(e)}
        return {"success": True, "data": normalize(data if isinstance(data, dict) else {})}

    def get_dns(self):
        return self._single("/network/dns/settings")

    def get_ssl_tls_settings(self):
        return self._single("/tls-inspection/settings")

    def get_backup_restore(self):
        return self._single("/system/backup/settings", nz.normalize_backup)

    def collect_topology_data(self) -> Dict[str, Any]:
        """Solo lo que necesita `build_topology` (zonas, interfaces, rutas, VPN, hosts, nombre del equipo)."""
        implemented: Dict[str, Callable[[], Dict[str, Any]]] = {
            "admin_settings": self.get_admin_settings, "zones": self.get_network_zones,
            "static_routes": self.get_static_routes, "vpn_ipsec_connections": self.get_vpn_ipsec_connections,
            "hosts": self.get_hosts, "_interface_bundle": self.get_interface_bundle,
        }
        results: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(fn): key for key, fn in implemented.items()}
            for fut in as_completed(futures):
                key = futures[fut]
                try:
                    results[key] = fut.result()
                except Exception as e:
                    results[key] = {"success": False, "error": str(e)}
        bundle = results.pop("_interface_bundle", {})
        if "success" in bundle:
            bundle = {k: dict(bundle) for k in ("interfaces", "vlans", "lags", "aliases")}
        results.update(bundle)
        return results

    def collect_audit_data(self) -> Dict[str, Any]:
        implemented: Dict[str, Callable[[], Dict[str, Any]]] = {
            "admin_settings": self.get_admin_settings, "device_access": self.get_device_access,
            "notification_settings": self.get_notification_settings, "admin_users": self.get_admin_users,
            "zones": self.get_network_zones, "gateways": self.get_gateways,
            "static_routes": self.get_static_routes, "vpn_ipsec_connections": self.get_vpn_ipsec_connections,
            "_interface_bundle": self.get_interface_bundle,
            "hosts": self.get_hosts, "services": self.get_services, "service_groups": self.get_service_groups,
            "firewall_rules": self.get_firewall_rules, "nat_rules": self.get_nat_rules,
            "host_groups": self.get_host_groups, "mac_hosts": self.get_mac_hosts, "fqdn_hosts": self.get_fqdn_hosts,
            "fqdn_host_groups": self.get_fqdn_host_groups, "schedules": self.get_schedules, "auth_users": self.get_auth_users,
            "ssl_tls_rules": self.get_ssl_tls_rules, "ssl_tls_settings": self.get_ssl_tls_settings,
            "decryption_profiles": self.get_decryption_profiles, "web_filter_policies": self.get_web_filter_policies,
            "web_filter_exceptions": self.get_web_filter_exceptions, "app_filter_policies": self.get_app_filter_policies,
            "dns": self.get_dns, "dns_request_routes": self.get_dns_request_routes, "backup_restore": self.get_backup_restore,
            "access_time_policies": self.get_access_time_policies, "surfing_quota_policies": self.get_surfing_quota_policies,
            "data_transfer_policies": self.get_data_transfer_policies,
        }
        results: Dict[str, Any] = {k: dict(UNSUPPORTED) for k in ALL_KEYS}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(fn): key for key, fn in implemented.items()}
            for fut in as_completed(futures):
                key = futures[fut]
                try:
                    results[key] = fut.result()
                except Exception as e:  # un colector no debe tumbar la auditoría
                    logger.warning("Collector REST '%s' failed: %s", key, e)
                    results[key] = {"success": False, "error": str(e)}
        bundle = results.pop("_interface_bundle", {})
        if "success" in bundle:  # el pedido falló: propagar el error a las cuatro claves
            bundle = {k: dict(bundle) for k in ("interfaces", "vlans", "lags", "aliases")}
        results.update(bundle)  # interfaces, vlans, lags, aliases
        return results

    # -- Consultas ad-hoc ("Obtener Info") ----------------------------------

    def run_query(self, query_type: str) -> Dict[str, Any]:
        """Misma estructura que la versión XML. `raw_xml` conserva el nombre que consume el frontend; aquí contiene JSON."""
        import json
        paths = {
            "firewall_rules": "/firewall/rules/ipv4",
            "services": "/network/services",
            "interface_info": "/network/interfaces/network-interfaces",
            "host_objects": "/network/addresses/ipv4",
            "users": "/authentication/users",
        }
        if query_type not in paths:
            return {"success": False, "error": f"Tipo desconocido: {query_type}", "raw_xml": ""}
        try:
            raw = self._get_all(paths[query_type])
            if query_type == "host_objects":
                raw_mac = self._get_all("/network/addresses/mac")
                raw_fqdn = self._get_all("/network/addresses/fqdn")
                raw_fqdn_groups = self._get_all("/network/address-groups/fqdn")
        except RestError as e:
            return {"success": False, "error": str(e), "raw_xml": ""}

        if query_type == "firewall_rules":
            data: Any = [nz.normalize_firewall_rule(r, i + 1) for i, r in enumerate(raw)]
        elif query_type == "services":
            data = [nz.normalize_named_object(x) for x in raw]
        elif query_type == "users":
            data = [nz.normalize_user(u) for u in raw]
        elif query_type == "interface_info":
            parts = nz.split_interfaces(raw)
            data = [{**i,
                     "vlans": [v for v in parts["vlans"] if v["interface"] == i["name"]],
                     "aliases": [a for a in parts["aliases"] if a["interface"] == i["name"]],
                     "lags": [l for l in parts["lags"] if i["name"] in l["members"]]} for i in parts["interfaces"]]
        else:
            data = {
                "ip_hosts": [nz.normalize_host(h) for h in raw],
                "mac_hosts": [nz.normalize_mac_host(h) for h in raw_mac],
                "fqdn_hosts": nz.normalize_fqdn_hosts(raw_fqdn, raw_fqdn_groups),
            }
            raw = {"ip_hosts": raw, "mac_hosts": raw_mac, "fqdn_hosts": raw_fqdn}
        count = sum(len(v) for v in data.values()) if isinstance(data, dict) else len(data)
        return {"success": True, "raw_xml": json.dumps(raw, ensure_ascii=False, indent=2), "data": data, "count": count}
