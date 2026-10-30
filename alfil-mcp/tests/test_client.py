import httpx
import pytest

from alfil_mcp.client import ReadOnlyError, SophosApiError, SophosClient, is_known_get_path, search_catalog
from alfil_mcp.config import Settings


def make_client(handler):
    return SophosClient(Settings(host="fw.test", token="t0ken"), transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE", "post"])
async def test_non_get_blocked_before_network(method):
    calls = []
    client = make_client(lambda req: calls.append(req) or httpx.Response(200, json={}))
    with pytest.raises(ReadOnlyError):
        await client.request(method, "/firewall/rules/ipv4")
    assert calls == []


def test_catalog_has_get_only_endpoints():
    assert len(search_catalog("", 1000)) == 266
    assert is_known_get_path("/network/zones")
    assert is_known_get_path("/firewall/rules/ipv4/mi-regla")
    assert not is_known_get_path("/network/zones/a/b")  # más segmentos que la plantilla
    assert not is_known_get_path("/network/zones/../../x")
    assert not is_known_get_path("/network/zones?x=1")


async def test_unknown_path_rejected():
    client = make_client(lambda req: httpx.Response(200, json={}))
    with pytest.raises(SophosApiError):
        await client.get("/no/existe")


async def test_bearer_header_and_pagination():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        page = int(req.url.params["page"])
        n = 100 if page == 1 else 5
        return httpx.Response(200, json={"items": [{"name": f"z{page}-{i}"} for i in range(n)]})

    client = make_client(handler)
    items = await client.get_all("/network/zones")
    assert len(items) == 105 and len(seen) == 2
    assert seen[0].headers["authorization"] == "Bearer t0ken"
    assert seen[0].url.path == "/api/firewall-config/v1/network/zones"


async def test_html_404_and_json_error_normalized():
    client = make_client(lambda req: httpx.Response(404, text="<html>404</html>"))
    with pytest.raises(SophosApiError, match="404"):
        await client.get("/network/zones")
    client = make_client(lambda req: httpx.Response(401, json={"error": "notAuthorized", "message": "Authentication required."}))
    with pytest.raises(SophosApiError, match="notAuthorized"):
        await client.get("/network/zones")


def test_token_not_in_repr():
    assert "t0ken" not in repr(Settings(host="fw.test", token="t0ken"))
