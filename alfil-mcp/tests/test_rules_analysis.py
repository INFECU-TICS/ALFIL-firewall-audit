from alfil_mcp.analysis.rules import audit_rules, find_duplicates, is_any_to_any

ANY = {"any": True}


def rule(name, **kw):
    base = {
        "id": name, "name": name, "enabled": True, "action": "accept", "logTraffic": True,
        "sourceZones": {"zones": ["LAN"]}, "destinationZones": {"zones": ["WAN"]},
        "sourceNetworks": ANY, "destinationNetworks": ANY,
        "servicesOrGroups": {"services": [{"name": "HTTPS"}], "serviceGroups": []},
    }
    return {**base, **kw}


def test_any_any_detected():
    r = rule("a", sourceZones=ANY, destinationZones=ANY, servicesOrGroups=ANY)
    assert is_any_to_any(r)
    assert not is_any_to_any(rule("b"))


def test_duplicates_ignore_disabled_and_name():
    rules = [rule("a"), rule("b"), rule("c", enabled=False), rule("d", destinationZones={"zones": ["DMZ"]})]
    dups = find_duplicates(rules)
    assert [d["rule"] for d in dups] == ["b"] and dups[0]["duplicateOf"] == "a"


def test_score_formula_and_findings():
    rules = [rule("a", sourceZones=ANY, destinationZones=ANY, servicesOrGroups=ANY, logTraffic=False),
             rule("off", enabled=False)]
    out = audit_rules(rules)
    assert out["counts"] == {"critical": 0, "warning": 2, "info": 1}
    assert out["score"] == 100 - 2 * 5 - 1


def test_clean_ruleset_scores_100():
    assert audit_rules([rule("a")])["score"] == 100
