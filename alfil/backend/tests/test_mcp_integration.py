"""Integración con el MCP: estado, token, latido, conexiones habilitadas y proxy de solo lectura."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.mcp_access import McpToken
from app.services.sophos_rest_client import RestError, SophosRestClient


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    c = TestClient(app)
    c.Session = Session
    yield c
    app.dependency_overrides.clear()


def make_conn(client, name="lab-rest", api_type="rest", mcp=True, **extra):
    body = {"name": name, "host": "fw.test", "port": 4444, "password": "secreto-del-firewall", "verify_ssl": False,
            "api_type": api_type, "mcp_enabled": mcp, **extra}
    if api_type == "xml":
        body["username"] = "admin"
    return client.post("/api/v1/connections", json=body)


def new_token(client, name=None, **body):
    name = name or f"agente-{len(client.get('/api/v1/mcp/status').json()['tokens']) + 1}"
    r = client.post("/api/v1/mcp/tokens", json={"name": name, **body})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_estados_del_mcp_y_token_solo_como_hash(client):
    assert client.get("/api/v1/mcp/status").json()["state"] == "sin_token"
    token = new_token(client)
    assert token.startswith("alfil_mcp_")
    st = client.get("/api/v1/mcp/status").json()
    assert st["state"] == "sin_actividad" and st["tokens"][0]["token_prefix"] == token[:14]
    with client.Session() as db:  # el token en claro no se guarda
        row = db.query(McpToken).first()
        assert token not in (row.token_hash or "") and len(row.token_hash) == 64
    assert client.post("/api/v1/mcp/heartbeat", json={"version": "0.1.0", "tools": 5, "read_only": True}, headers=auth(token)).status_code == 204
    st = client.get("/api/v1/mcp/status").json()
    assert st["state"] == "en_linea" and st["info"]["version"] == "0.1.0" and st["info"]["tools"] == 5
    with client.Session() as db:  # latido antiguo -> fuera de línea
        row = db.query(McpToken).first()
        row.last_seen_at = datetime.now(timezone.utc) - timedelta(seconds=600)
        db.commit()
    assert client.get("/api/v1/mcp/status").json()["state"] == "fuera_de_linea"


def test_endpoints_del_mcp_exigen_token_valido(client):
    make_conn(client)
    for method, url in (("post", "/api/v1/mcp/heartbeat"), ("get", "/api/v1/mcp/connections"), ("get", "/api/v1/mcp/connections/1/get?path=/network/zones")):
        kwargs = {"json": {}} if method == "post" else {}
        assert getattr(client, method)(url, **kwargs).status_code == 401                       # sin token
        assert getattr(client, method)(url, headers=auth("alfil_mcp_falso"), **kwargs).status_code == 401  # token inventado
    token = new_token(client)
    assert client.get("/api/v1/mcp/connections", headers=auth(token)).status_code == 200
    tid = client.get("/api/v1/mcp/status").json()["tokens"][0]["id"]
    assert client.delete(f"/api/v1/mcp/tokens/{tid}").status_code == 204  # revocar
    assert client.get("/api/v1/mcp/connections", headers=auth(token)).status_code == 401
    assert client.get("/api/v1/mcp/status").json()["state"] == "sin_token"


def test_un_token_por_agente_y_revocacion_individual(client):
    a = new_token(client, "claude-ana")
    b = new_token(client, "opencode-luis")
    assert client.post("/api/v1/mcp/tokens", json={"name": "claude-ana"}).status_code == 409   # nombre único
    assert client.post("/api/v1/mcp/tokens", json={"name": "  "}).status_code == 422
    tokens = {t["name"]: t for t in client.get("/api/v1/mcp/status").json()["tokens"]}
    assert set(tokens) == {"claude-ana", "opencode-luis"}
    assert client.get("/api/v1/mcp/connections", headers=auth(a)).status_code == 200
    assert client.get("/api/v1/mcp/connections", headers=auth(b)).status_code == 200
    assert client.delete(f"/api/v1/mcp/tokens/{tokens['claude-ana']['id']}").status_code == 204
    assert client.get("/api/v1/mcp/connections", headers=auth(a)).status_code == 401
    assert client.get("/api/v1/mcp/connections", headers=auth(b)).status_code == 200     # el otro sigue vivo
    assert client.delete("/api/v1/mcp/tokens/9999").status_code == 404


def test_caducidad_por_defecto_7_dias_y_token_caducado_se_rechaza(client):
    token = new_token(client, "temporal")
    t = client.get("/api/v1/mcp/status").json()["tokens"][0]
    created, expires = datetime.fromisoformat(t["created_at"]), datetime.fromisoformat(t["expires_at"])
    assert (expires - created).days == 7 and client.get("/api/v1/mcp/status").json()["default_expires_days"] == 7
    with client.Session() as db:
        row = db.query(McpToken).first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    r = client.get("/api/v1/mcp/connections", headers=auth(token))
    assert r.status_code == 401 and "caducado" in r.json()["detail"]
    st = client.get("/api/v1/mcp/status").json()
    assert st["tokens"][0]["expired"] is True and st["state"] == "sin_token" and st["token_configured"] is False


def test_token_sin_caducidad_y_limites(client):
    token = new_token(client, "permanente", expires_days=None)
    assert client.get("/api/v1/mcp/status").json()["tokens"][0]["expires_at"] is None
    assert client.get("/api/v1/mcp/connections", headers=auth(token)).status_code == 200
    assert client.post("/api/v1/mcp/tokens", json={"name": "x", "expires_days": 0}).status_code == 422
    assert client.post("/api/v1/mcp/tokens", json={"name": "y", "expires_days": 366}).status_code == 422


def test_solo_conexiones_habilitadas_y_sin_credenciales(client):
    make_conn(client, "habilitada", mcp=True)
    make_conn(client, "apagada", mcp=False)
    make_conn(client, "xml", api_type="xml", mcp=False)
    token = new_token(client)
    r = client.get("/api/v1/mcp/connections", headers=auth(token))
    assert [c["name"] for c in r.json()] == ["habilitada"]
    assert set(r.json()[0]) == {"id", "name", "host", "port", "verify_ssl"}
    assert "secreto" not in r.text and "password" not in r.text
    assert client.get("/api/v1/mcp/status").json()["enabled_connections"] == 1


def test_mcp_enabled_solo_para_rest(client):
    assert make_conn(client, "x", api_type="xml", mcp=True).status_code == 422       # alta XML con MCP
    cid = make_conn(client, "r", mcp=True).json()["id"]
    assert client.get(f"/api/v1/connections/{cid}").json()["mcp_enabled"] is True
    r = client.put(f"/api/v1/connections/{cid}", json={"api_type": "xml", "password": "p", "mcp_enabled": True})
    assert r.status_code == 400
    r = client.put(f"/api/v1/connections/{cid}", json={"api_type": "xml", "username": "admin", "password": "p"})
    assert r.json()["api_type"] == "xml" and r.json()["mcp_enabled"] is False        # al pasar a XML se retira del MCP
    xml_id = make_conn(client, "otra-xml", api_type="xml", mcp=False).json()["id"]
    assert client.put(f"/api/v1/connections/{xml_id}", json={"mcp_enabled": True}).status_code == 400


def test_proxy_lee_rutas_get_de_la_spec(client, monkeypatch):
    seen = {}

    def fake_get(self, path, params=None):
        seen.update(path=path, params=params, host=self.host)
        return {"items": [{"name": "LAN"}], "pages": {"current": 1}}

    monkeypatch.setattr(SophosRestClient, "_get", fake_get)
    cid = make_conn(client).json()["id"]
    h = auth(new_token(client))
    r = client.get(f"/api/v1/mcp/connections/{cid}/get", params={"path": "/network/zones", "page": 2, "pageSize": 100}, headers=h)
    assert r.status_code == 200 and r.json()["items"][0]["name"] == "LAN"
    assert seen["path"] == "/network/zones" and seen["params"] == {"page": "2", "pageSize": "100"} and seen["host"] == "fw.test"
    assert client.get("/api/v1/mcp/connections/lab-rest/get", params={"path": "/firewall/rules/ipv4/mi-regla"}, headers=h).status_code == 200  # por nombre


def test_proxy_rechaza_rutas_fuera_de_la_spec_y_conexiones_no_habilitadas(client, monkeypatch):
    monkeypatch.setattr(SophosRestClient, "_get", lambda self, path, params=None: {"ok": True})
    on = make_conn(client, "on", mcp=True).json()["id"]
    off = make_conn(client, "off", mcp=False).json()["id"]
    xml = make_conn(client, "xml", api_type="xml", mcp=False).json()["id"]
    h = auth(new_token(client))
    for bad in ("/no/existe", "/network/zones/../../x", "network/zones", "/network/zones?x=1", "/network/zones#a"):
        assert client.get(f"/api/v1/mcp/connections/{on}/get", params={"path": bad}, headers=h).status_code == 400, bad
    for cid in (off, xml, 9999):
        assert client.get(f"/api/v1/mcp/connections/{cid}/get", params={"path": "/network/zones"}, headers=h).status_code == 404


def test_proxy_traduce_errores_del_firewall(client, monkeypatch):
    def boom(self, path, params=None):
        raise RestError("API key rechazada (HTTP 401)")

    monkeypatch.setattr(SophosRestClient, "_get", boom)
    cid = make_conn(client).json()["id"]
    r = client.get(f"/api/v1/mcp/connections/{cid}/get", params={"path": "/network/zones"}, headers=auth(new_token(client)))
    assert r.status_code == 502 and "rechazada" in r.json()["detail"]


def test_estado_del_servicio_remoto_y_ultimo_uso(client, monkeypatch):
    import requests
    from app.config import get_settings
    from app.routers import mcp as mcp_router

    assert client.get("/api/v1/mcp/status").json()["remote"] == {"configured": False}
    monkeypatch.setattr(mcp_router, "get_settings", lambda: get_settings().model_copy(update={"mcp_service_url": "http://amcp:8765"}))

    class Resp:
        def raise_for_status(self): pass
        def json(self): return {"status": "ok", "version": "0.2.0", "tools": 6, "transport": "http"}

    monkeypatch.setattr(requests, "get", lambda url, timeout: Resp())
    remote = client.get("/api/v1/mcp/status").json()["remote"]
    assert remote == {"configured": True, "reachable": True, "version": "0.2.0", "tools": 6, "transport": "http"}

    def down(url, timeout):
        raise requests.ConnectionError("sin red")

    monkeypatch.setattr(requests, "get", down)
    assert client.get("/api/v1/mcp/status").json()["remote"] == {"configured": True, "reachable": False, "error": "ConnectionError"}

    # último uso: lo registra la lectura de un agente, no el latido
    token = new_token(client)
    assert client.get("/api/v1/mcp/status").json()["last_used_at"] is None
    client.post("/api/v1/mcp/heartbeat", json={"version": "x", "tools": 1}, headers=auth(token))
    assert client.get("/api/v1/mcp/status").json()["last_used_at"] is None
    client.get("/api/v1/mcp/connections", headers=auth(token))
    assert client.get("/api/v1/mcp/status").json()["last_used_at"] is not None


def test_topologia_en_vivo_para_el_mcp(client, monkeypatch):
    from tests.test_topology import base_raw
    monkeypatch.setattr(SophosRestClient, "collect_topology_data", lambda self: base_raw())
    cid = make_conn(client).json()["id"]
    h = auth(new_token(client))
    assert client.get(f"/api/v1/mcp/connections/{cid}/topology").status_code == 401           # exige token
    r = client.get(f"/api/v1/mcp/connections/{cid}/topology", headers=h)
    assert r.status_code == 200
    topo = r.json()
    assert {n["id"] for n in topo["nodes"]} >= {"fw", "zone:LAN", "if:PortA", "net:10.0.1.0/24"} and topo["meta"]["source"] == "rest"
    assert "secreto" not in r.text and "password" not in r.text
    off = make_conn(client, "off", mcp=False).json()["id"]
    assert client.get(f"/api/v1/mcp/connections/{off}/topology", headers=h).status_code == 404  # solo habilitadas


def test_topologia_sin_datos_de_red_es_502(client, monkeypatch):
    fail = {"success": False, "error": "HTTP 500"}
    monkeypatch.setattr(SophosRestClient, "collect_topology_data", lambda self: {"zones": fail, "interfaces": fail})
    cid = make_conn(client).json()["id"]
    r = client.get(f"/api/v1/mcp/connections/{cid}/topology", headers=auth(new_token(client)))
    assert r.status_code == 502 and "HTTP 500" in r.json()["detail"]
