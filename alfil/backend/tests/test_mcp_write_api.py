"""Fase 2 por HTTP: las tres llaves (servidor, token, conexión), confirmación, caducidad, deriva y auditoría."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.database import Base, get_db
from app.main import app
from app.models.connection import ConnectionConfig
from app.models.mcp_access import McpChange
from app.routers import mcp as mcp_router
from app.services.sophos_rest_client import RestError, RestTimeout, SophosRestClient


class FakeFirewall:
    """Sustituye a SophosRestClient: guarda el estado en memoria y registra las escrituras."""

    def __init__(self):
        self.rules = [{"name": "web", "enabled": True}, {"name": "dns", "enabled": False}]
        self.hosts = [{"name": "oficina"}]
        self.writes, self.fail, self.timeout_applies = [], None, None

    def _get_all(self, path, params=None):
        return {"/firewall/rules/ipv4": self.rules, "/network/addresses/ipv4": self.hosts, "/network/zones": [{"name": "LAN"}, {"name": "WAN"}],
                "/network/address-groups/ipv4": [], "/network/services": [{"name": "HTTPS"}], "/network/service-groups": []}.get(path, [])

    def _get(self, path, params=None):
        if self.fail == "read":
            raise RestError("no responde")
        return next((r for r in self.rules if path.endswith("/" + r["name"])), {})

    def _write(self, method, path, payload=None, timeout=150):
        if self.fail == "timeout":
            if self.timeout_applies:
                self._apply(method, path, payload)
            raise RestTimeout("tarda")
        if self.fail == "reject":
            raise RestError("El equipo rechazó el cambio (HTTP 400): bad")
        self.writes.append((method, path, payload))
        self._apply(method, path, payload)
        return {}

    def _apply(self, method, path, payload):
        if method == "PATCH":
            next(r for r in self.rules if path.endswith("/" + r["name"])).update(payload)
        elif path.endswith("/move"):
            r = next(x for x in self.rules if x["name"] == payload["name"])
            self.rules.remove(r)
            self.rules.insert(0, r)
        elif path.endswith("addresses/ipv4"):
            self.hosts.append({"name": payload["name"]})


@pytest.fixture
def env(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    fw = FakeFirewall()
    monkeypatch.setattr(mcp_router, "client_for_connection", lambda conn: fw)
    monkeypatch.setattr(mcp_router, "SophosRestClient", FakeFirewall)
    monkeypatch.setenv("MCP_ALLOW_WRITE", "true")
    get_settings.cache_clear()
    c = TestClient(app)
    with Session() as db:
        db.add(ConnectionConfig(name="lab", host="fw.test", port=4444, username="api-key", password_encrypted="x", verify_ssl=False,
                                api_type="rest", mcp_enabled=True, mcp_write_enabled=True, is_active=True))
        db.commit()
    yield c, fw, Session
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def token(c, name="agente", can_write=True):
    r = c.post("/api/v1/mcp/tokens", json={"name": name, "expires_days": 1, "can_write": can_write})
    assert r.status_code == 201 and r.json()["can_write"] is can_write
    return {"Authorization": "Bearer " + r.json()["token"]}


def propose(c, h, kind="set_rule_enabled", **params):
    params = params or {"name": "dns", "enabled": True}
    return c.post("/api/v1/mcp/connections/lab/changes", headers=h, json={"action": kind, "params": params})


def test_flujo_completo_propone_confirma_y_aplica(env):
    c, fw, _ = env
    h = token(c)
    r = propose(c, h)
    assert r.status_code == 201
    ch = r.json()
    assert ch["status"] == "proposed" and "HABILITAR" in ch["summary"] and ch["request"]["payload"] == {"enabled": True} and fw.writes == []
    done = c.post(f"/api/v1/mcp/changes/{ch['change_id']}/apply", headers=h, json={"confirm": True})
    assert done.status_code == 200 and done.json()["status"] == "applied" and done.json()["result"]["verified"] is True
    assert fw.writes == [("PATCH", "/firewall/rules/ipv4/dns", {"enabled": True})] and done.json()["result"]["snapshot"]["rule"]["name"] == "dns"
    again = c.post(f"/api/v1/mcp/changes/{ch['change_id']}/apply", headers=h, json={"confirm": True})
    assert again.status_code == 409 and len(fw.writes) == 1
    events = [e["event"] for e in c.get("/api/v1/mcp/audit-log").json()]
    assert events[:2] == ["applied", "proposed"]


def test_sin_confirmacion_no_se_aplica(env):
    c, fw, _ = env
    h = token(c)
    cid = propose(c, h).json()["change_id"]
    for body in ({}, {"confirm": False}):
        assert c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json=body).status_code == 422
    assert fw.writes == []


def test_las_tres_llaves(env, monkeypatch):
    c, fw, Session = env
    ro = token(c, "solo-lectura", can_write=False)
    r = propose(c, ro)
    assert r.status_code == 403 and "solo lectura" in r.json()["detail"]
    h = token(c)
    with Session() as db:
        conn = db.query(ConnectionConfig).first()
        conn.mcp_write_enabled = False
        db.commit()
    assert "no permite cambios" in propose(c, h).json()["detail"]
    with Session() as db:
        conn = db.query(ConnectionConfig).first()
        conn.mcp_write_enabled = True
        db.commit()
    monkeypatch.setenv("MCP_ALLOW_WRITE", "false")
    get_settings.cache_clear()
    assert "deshabilitada en el servidor" in propose(c, h).json()["detail"]
    assert fw.writes == []
    assert [e["event"] for e in c.get("/api/v1/mcp/audit-log").json()].count("rejected") == 3


def test_otro_token_no_puede_aplicar(env):
    c, fw, _ = env
    a, b = token(c, "a"), token(c, "b")
    cid = propose(c, a).json()["change_id"]
    assert c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=b, json={"confirm": True}).status_code == 404
    assert fw.writes == []


def test_propuesta_caducada(env):
    c, fw, Session = env
    h = token(c)
    cid = propose(c, h).json()["change_id"]
    with Session() as db:
        ch = db.get(McpChange, cid)
        ch.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    r = c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json={"confirm": True})
    assert r.status_code == 410 and fw.writes == []
    assert c.get("/api/v1/mcp/changes", headers=h).json()[0]["status"] == "expired"


def test_si_el_equipo_cambio_no_se_aplica(env):
    c, fw, _ = env
    h = token(c)
    cid = propose(c, h).json()["change_id"]
    fw.rules[1]["enabled"] = True  # alguien la habilitó entre la propuesta y la confirmación
    r = c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json={"confirm": True})
    assert r.status_code == 409 and "cambió" in r.json()["detail"] and fw.writes == []


def test_propuesta_invalida_da_422_y_se_audita(env):
    c, fw, _ = env
    h = token(c)
    r = propose(c, h, "create_rule", name="todo", action="accept")
    assert r.status_code == 422 and "Any→Any" in r.json()["detail"]
    assert propose(c, h, "delete_rule", name="web").status_code == 422
    assert c.get("/api/v1/mcp/audit-log").json()[0]["event"] == "rejected"


def test_el_equipo_rechaza_el_cambio(env):
    c, fw, _ = env
    h = token(c)
    cid = propose(c, h).json()["change_id"]
    fw.fail = "reject"
    r = c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json={"confirm": True})
    assert r.status_code == 200 and r.json()["status"] == "failed" and "rechazó" in r.json()["result"]["message"]


@pytest.mark.parametrize("applies,status", [(True, "applied"), (False, "failed")])
def test_timeout_consulta_el_estado_antes_de_concluir(env, applies, status):
    c, fw, _ = env
    h = token(c)
    cid = propose(c, h).json()["change_id"]
    fw.fail, fw.timeout_applies = "timeout", applies
    r = c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json={"confirm": True})
    assert r.json()["status"] == status


def test_timeout_sin_poder_verificar_queda_desconocido(env):
    c, fw, _ = env
    h = token(c)
    cid = propose(c, h, "move_rule", name="dns", position="top").json()["change_id"]
    fw.fail = "timeout"
    fw.timeout_applies = False
    # el orden no cambió -> verify_applied devuelve False (no aplicado); simulamos que el equipo ya no responde a lecturas
    fw._get_all = lambda path, params=None: (_ for _ in ()).throw(RestError("caído"))
    assert c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json={"confirm": True}).status_code == 502


def test_sin_copia_previa_no_se_aplica(env):
    c, fw, _ = env
    h = token(c)
    cid = propose(c, h).json()["change_id"]
    fw.fail = "read"
    r = c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json={"confirm": True})
    assert r.status_code == 502 and "no se aplicó nada" in r.json()["detail"] and fw.writes == []


def test_crear_host_y_mover_regla(env):
    c, fw, _ = env
    h = token(c)
    for action, params in (("create_host", {"name": "nuevo", "ip": "192.0.2.10"}), ("move_rule", {"name": "dns", "position": "top"})):
        cid = propose(c, h, action, **params).json()["change_id"]
        r = c.post(f"/api/v1/mcp/changes/{cid}/apply", headers=h, json={"confirm": True})
        assert r.json()["status"] == "applied", r.text
    assert [w[0] for w in fw.writes] == ["POST", "POST"] and fw.rules[0]["name"] == "dns"


def test_estado_del_mcp_informa_la_escritura(env):
    c, _, _ = env
    token(c)
    s = c.get("/api/v1/mcp/status").json()
    assert s["write_allowed"] is True and s["write_connections"] == 1 and s["tokens"][0]["can_write"] is True


def test_cliente_real_solo_escribe_post_y_patch():
    client = SophosRestClient("fw.test", 4444, "k")
    with pytest.raises(RestError, match="no permitido"):
        client._write("DELETE", "/firewall/rules/ipv4/x")
