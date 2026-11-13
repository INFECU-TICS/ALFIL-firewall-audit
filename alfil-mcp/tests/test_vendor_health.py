"""get_vendor_health_check: resumen de la verificación de políticas del propio firewall."""
import httpx

from alfil_mcp import server
from alfil_mcp.analysis.vendor_health import effective_status, summarize
from alfil_mcp.config import AlfilSettings

ITEMS = [
    {"policy": "MFA VPN", "policyKey": "RemoteVpnMfaConfig", "module": "Authentication", "severity": "high", "status": "nonCompliant", "overriddenStatus": None, "standards": ["CIS"]},
    {"policy": "Correo", "policyKey": "NotificationEmails", "module": "Notification settings", "severity": "low", "status": "nonCompliant", "overriddenStatus": None},
    {"policy": "Hotfix", "policyKey": "Hotfix", "module": "System", "severity": "medium", "status": "nonCompliant", "overriddenStatus": "compliant"},
    {"policy": "IPS", "policyKey": "Ips", "module": "IPS", "severity": "high", "status": "compliant", "overriddenStatus": None},
    {"policy": "Admin web", "policyKey": "AdminWeb", "module": "Authentication", "severity": "high", "status": "nonCompliant", "overriddenStatus": None},
]


def test_estado_manual_tiene_prioridad():
    assert effective_status(ITEMS[2]) == "compliant" and effective_status(ITEMS[0]) == "nonCompliant"


def test_resumen_cuenta_y_ordena_por_severidad():
    r = summarize(ITEMS)
    assert r["total"] == 5 and r["by_status"] == {"nonCompliant": 3, "compliant": 2}
    assert [p["key"] for p in r["policies"]] == ["AdminWeb", "RemoteVpnMfaConfig", "NotificationEmails"]  # high (por módulo/nombre), luego low
    assert r["by_severity"]["high"] == {"nonCompliant": 2, "compliant": 1} and r["by_module"]["Authentication"] == 2


def test_filtros_incluir_conformes_severidad_y_limite():
    assert summarize(ITEMS, only_noncompliant=False)["matching"] == 5
    assert [p["key"] for p in summarize(ITEMS, severity="low")["policies"]] == ["NotificationEmails"]
    r = summarize(ITEMS, limit=1)
    assert r["listed"] == 1 and r["matching"] == 3 and len(r["policies"]) == 1


def test_politica_sobrescrita_se_marca():
    r = summarize(ITEMS, only_noncompliant=False, severity="medium")
    assert r["policies"][0]["overridden"] is True and r["policies"][0]["status"] == "compliant"


async def test_tool_solo_lee_ruta_del_catalogo(monkeypatch):
    from alfil_mcp.client import is_known_get_path
    for var in ("SFOS_HOST", "SFOS_TOKEN", "API_KEY", "SFOS_ENV_FILE", "ALFIL_URL", "ALFIL_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    server.reset_state()
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/v1/mcp/connections":
            return httpx.Response(200, json=[{"id": 1, "name": "lab-rest", "host": "fw.test", "port": 4444, "verify_ssl": False}])
        seen.append((req.method, req.url.params["path"]))
        return httpx.Response(200, json={"items": ITEMS})

    server._hub = server.AlfilHub(AlfilSettings(url="http://alfil.test", token="alfil_mcp_t"), transport=httpx.MockTransport(handler))
    res = await server.get_vendor_health_check(severity="high")
    assert res["connection"] == "lab-rest" and res["matching"] == 2
    assert seen == [("GET", "/firewall-health-check/policies")] and is_known_get_path(seen[0][1])
    server.reset_state()
