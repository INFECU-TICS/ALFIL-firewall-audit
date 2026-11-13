"""Topología F3: hallazgos por nodo, matriz zona→zona y comparación entre auditorías."""
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.audit_report import AuditReport
from app.models.connection import ConnectionConfig
from app.services.audit_diff import diff_reports
from app.services.topology_insights import findings_by_node, zone_matrix

NODES = [{"id": "fw", "label": "fw1"}, {"id": "zone:LAN", "label": "LAN"}, {"id": "zone:WAN", "label": "WAN"}, {"id": "if:PortC", "label": "PortC"}]


def rule(name, action="Accept", status="Enable", sz=("LAN",), dz=("WAN",), sn=("Any",), dn=("Any",), svc=("Any",), log="Enable"):
    return {"name": name, "action": action, "status": status, "source_zones": list(sz), "destination_zones": list(dz), "source_networks": list(sn),
            "destination_networks": list(dn), "services": list(svc), "log_traffic": log}


def issue(sev, cat, title, ref="", rec=""):
    return {"severity": sev, "category": cat, "title": title, "reference": ref, "recommendation": rec}


# ---- hallazgos por nodo ----------------------------------------------------------------------

def test_hallazgos_se_asignan_a_zona_o_firewall():
    issues = [issue("critical", "device_access", "Acceso admin desde WAN", ref="WAN"),
              issue("critical", "admin_users", "Admin sin MFA"),
              issue("warning", "firewall_rules", "Regla sin logging: 'r1'", ref="r1"),
              issue("warning", "firewall_rules", "Regla Any", ref="r2"),
              issue("info", "hosts", "3 host(s) sin uso")]
    rules = [rule("r1", sz=("LAN",), dz=("WAN",)), rule("r2", sz=("Any",), dz=("Any",))]
    out = findings_by_node(issues, rules, NODES, [{"node": "if:PortC", "severity": "warning", "message": "Interfaz sin zona"}])
    assert [f["title"] for f in out["zone:WAN"]] == ["Acceso admin desde WAN", "Regla sin logging: 'r1'"]
    assert [f["title"] for f in out["zone:LAN"]] == ["Regla sin logging: 'r1'"]
    assert {f["title"] for f in out["fw"]} == {"Admin sin MFA", "Regla Any", "3 host(s) sin uso"}
    assert out["if:PortC"][0]["category"] == "topology"
    assert out["fw"][0]["severity"] == "critical"  # ordenado por severidad


def test_nodo_inexistente_cae_en_el_firewall_y_sin_duplicados():
    out = findings_by_node([issue("warning", "device_access", "X", ref="Fantasma"), issue("warning", "device_access", "X", ref="Fantasma")], [], NODES)
    assert list(out) == ["fw"] and len(out["fw"]) == 1


# ---- matriz de zonas -------------------------------------------------------------------------

def test_matriz_expande_any_y_marca_permisivas():
    m = zone_matrix([rule("todo", sz=("Any",), dz=("Any",)), rule("web", sz=("LAN",), dz=("WAN",), svc=("HTTPS",), sn=("Any",), dn=("Any",))], ["LAN", "WAN", "DMZ"])
    assert m["zones"] == ["LAN", "WAN", "DMZ"] and len(m["cells"]) == 9
    lw = m["cells"]["LAN|WAN"]
    assert lw["accept"] == 2 and lw["permissive"] is True and [r["name"] for r in lw["rules"]] == ["todo", "web"]
    assert m["cells"]["DMZ|DMZ"]["accept"] == 1  # Any→Any también cubre mismas zonas


def test_matriz_cuenta_bloqueos_ignora_deshabilitadas_y_regla_acotada_no_es_permisiva():
    rules = [rule("bloq", action="Drop", sz=("WAN",), dz=("LAN",)), rule("rej", action="Reject", sz=("WAN",), dz=("LAN",)),
             rule("off", status="Disable", sz=("LAN",), dz=("WAN",)),
             rule("acotada", sz=("LAN",), dz=("WAN",), sn=("oficina",), svc=("HTTPS",), log="Disable")]
    m = zone_matrix(rules, ["LAN", "WAN"])
    assert m["cells"]["WAN|LAN"]["deny"] == 2 and m["cells"]["WAN|LAN"]["accept"] == 0
    lw = m["cells"]["LAN|WAN"]
    assert lw["accept"] == 1 and lw["permissive"] is False and lw["no_log"] == 1 and [r["name"] for r in lw["rules"]] == ["acotada"]


def test_matriz_sin_reglas_o_sin_zonas():
    assert zone_matrix([], ["A"])["cells"]["A|A"]["accept"] == 0
    assert zone_matrix([rule("r")], [])["zones"] == ["LAN", "WAN"]  # zonas tomadas de las propias reglas
    assert zone_matrix([], [])["cells"] == {}


# ---- diff ------------------------------------------------------------------------------------

def rep(issues, rules=(), score=50, nodes=()):
    return {"issues": issues, "summary": {"score": score}, "sections": {"firewall_rules": {"data": list(rules)}}, "topology": {"nodes": list(nodes)}}


def test_diff_hallazgos_nuevos_resueltos_y_persistentes():
    old = rep([issue("critical", "admin_users", "Admin 'a' sin MFA"), issue("warning", "firewall_rules", "Regla sin logging: 'r'"), issue("info", "hosts", "14 host(s) sin uso en reglas ni NAT")], score=40)
    new = rep([issue("warning", "firewall_rules", "Regla sin logging: 'r'"), issue("critical", "device_access", "Admin desde WAN"), issue("info", "hosts", "12 host(s) sin uso en reglas ni NAT")], score=55)
    d = diff_reports(old, new)
    assert d["score"] == {"before": 40, "after": 55, "delta": 15}
    assert d["counts"] == {"new": 1, "resolved": 1, "persisting": 2}
    assert d["issues"]["new"][0]["title"] == "Admin desde WAN" and d["issues"]["resolved"][0]["title"] == "Admin 'a' sin MFA"


def test_diff_formato_anterior_de_hosts_sin_uso_no_genera_ruido():
    old = rep([issue("info", "hosts", "Host sin uso en reglas: 'a'"), issue("info", "hosts", "Host sin uso en reglas: 'b'")])
    new = rep([issue("info", "hosts", "2 host(s) sin uso en reglas ni NAT")])
    d = diff_reports(old, new)
    assert d["counts"] == {"new": 0, "resolved": 0, "persisting": 1}


def test_diff_severidad_cambiada():
    d = diff_reports(rep([issue("warning", "x", "T")]), rep([issue("critical", "x", "T")]))
    assert d["issues"]["severity_changed"][0]["was"] == "warning" and d["counts"]["persisting"] == 1


def test_diff_reglas_agregadas_quitadas_cambiadas_y_reordenadas():
    old = rep([], [rule("a"), rule("b"), rule("c")])
    new = rep([], [rule("c"), rule("a", action="Drop"), rule("d")])
    d = diff_reports(old, new)["rules"]
    assert d["added"] == ["d"] and d["removed"] == ["b"] and d["reordered"] is True
    assert d["changed"] == [{"name": "a", "changes": {"action": {"antes": "Accept", "ahora": "Drop"}}}]
    assert diff_reports(old, old)["rules"] == {"added": [], "removed": [], "changed": [], "reordered": False}


def test_diff_topologia_y_puntaje_ausente():
    d = diff_reports({"issues": [], "topology": {"nodes": [{"id": "1", "label": "PortA"}]}}, {"issues": [], "topology": {"nodes": [{"id": "2", "label": "PortB"}]}})
    assert d["topology"] == {"added": ["PortB"], "removed": ["PortA"]} and d["score"]["delta"] is None


# ---- endpoints -------------------------------------------------------------------------------

@pytest.fixture
def client():
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
    with Session() as db:
        for cid in (1, 2):
            db.add(ConnectionConfig(id=cid, name=f"c{cid}", host="h", port=4444, username="u", password_encrypted="x", api_type="rest"))
        topo = {"nodes": NODES, "edges": [], "meta": {"warnings": []}}
        sections = {"firewall_rules": {"data": [rule("r1")]}, "zones": {"data": [{"name": "LAN"}, {"name": "WAN"}]}}
        base = dict(report={"issues": [issue("critical", "admin_users", "Admin sin MFA")], "summary": {"score": 40}, "sections": sections, "topology": topo}, status="completed")
        db.add(AuditReport(id=1, connection_id=1, **base))
        db.add(AuditReport(id=2, connection_id=1, status="completed", report={**base["report"], "issues": [], "summary": {"score": 90}}))
        db.add(AuditReport(id=3, connection_id=2, **base))
        db.add(AuditReport(id=4, connection_id=1, status="running", report=None))
        db.commit()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_endpoint_topologia_incluye_hallazgos_por_nodo(client):
    r = client.get("/api/v1/audit/reports/1/topology")
    assert r.status_code == 200 and r.json()["findings"]["fw"][0]["title"] == "Admin sin MFA" and r.json()["nodes"]


def test_endpoint_matriz_de_zonas(client):
    r = client.get("/api/v1/audit/reports/1/zone-matrix")
    assert r.status_code == 200 and r.json()["cells"]["LAN|WAN"]["accept"] == 1
    assert client.get("/api/v1/audit/reports/4/zone-matrix").status_code == 409


def test_endpoint_diff(client):
    r = client.get("/api/v1/audit/reports/2/diff?base=1")
    assert r.status_code == 200 and r.json()["score"]["delta"] == 50 and r.json()["counts"]["resolved"] == 1 and r.json()["base_id"] == 1
    assert client.get("/api/v1/audit/reports/2/diff?base=2").status_code == 400
    assert "misma conexión" in client.get("/api/v1/audit/reports/2/diff?base=3").json()["detail"]
    assert client.get("/api/v1/audit/reports/2/diff?base=4").status_code == 409
    assert client.get("/api/v1/audit/reports/2/diff?base=99").status_code == 404
