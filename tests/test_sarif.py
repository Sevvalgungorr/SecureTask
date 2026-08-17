"""Importing code-scanning reports (SARIF).

Nothing here scans anything. The report is produced where the code already is —
a developer's machine or their pipeline — and only its findings arrive. That is
the whole design: cloning a repository to scan it would mean running untrusted
code and holding someone else's source, for no gain the tracker needs.
"""
import json


def _sarif(results, tool="Semgrep", rules=None):
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "rules": rules or []}},
            "results": results,
        }],
    })


def _result(rule_id="python.lang.security.dangerous-subprocess",
            uri="app/main.py", line=42, level="error", message="Güvensiz alt süreç çağrısı"):
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            }
        }],
    }


def _post(client, body):
    return client.post("/import/sarif", content=body)


def test_sarif_import_requires_authentication(client):
    assert client.post("/import/sarif", content=_sarif([])).status_code == 401


def test_a_code_finding_becomes_a_tracked_finding(client):
    client.login_as("alice")

    res = _post(client, _sarif([_result()]))
    assert res.status_code == 200
    body = res.json()
    assert body["created"] == 1
    assert body["tool"] == "semgrep"

    finding = client.get("/findings").json()[0]
    # The file is the asset: it is the thing the problem lives on.
    assert finding["asset"] == "app/main.py"
    assert finding["source"] == "semgrep"
    assert finding["source_ref"] == "python.lang.security.dangerous-subprocess"
    assert "satır 42" in finding["description"]
    # And it joins the normal lifecycle, deadline included.
    assert finding["due_date"] is not None


def test_the_tool_name_comes_from_the_report(client):
    """One reader, many scanners — the report says which one wrote it."""
    client.login_as("alice")
    _post(client, _sarif([_result()], tool="Bandit"))

    assert client.get("/findings").json()[0]["source"] == "bandit"


def test_sarif_levels_map_to_severities(client):
    client.login_as("alice")
    _post(client, _sarif([
        _result("rule-error", "a.py", level="error"),
        _result("rule-warning", "b.py", level="warning"),
        _result("rule-note", "c.py", level="note"),
    ]))

    by_asset = {f["asset"]: f["severity"] for f in client.get("/findings").json()}
    assert by_asset == {"a.py": "high", "b.py": "medium", "c.py": "low"}


def test_a_security_severity_score_outranks_the_level(client):
    """GitHub's convention carries a CVSS-like number; it is more precise."""
    client.login_as("alice")
    _post(client, _sarif(
        [_result("rule-rce", level="warning")],
        rules=[{"id": "rule-rce", "properties": {"security-severity": "9.4"}}],
    ))

    assert client.get("/findings").json()[0]["severity"] == "critical"


def test_the_rule_description_is_preferred_as_the_title(client):
    client.login_as("alice")
    _post(client, _sarif(
        [_result("rule-x", message="şu satırda görüldü")],
        rules=[{"id": "rule-x", "shortDescription": {"text": "Komut enjeksiyonu riski"}}],
    ))

    assert client.get("/findings").json()[0]["title"] == "Komut enjeksiyonu riski"


def test_rescanning_the_same_code_does_not_duplicate(client):
    client.login_as("alice")
    _post(client, _sarif([_result()]))

    second = _post(client, _sarif([_result()])).json()
    assert second["created"] == 0
    assert second["unchanged"] == 1
    assert len(client.get("/findings").json()) == 1


def test_the_same_rule_in_another_file_is_a_separate_finding(client):
    client.login_as("alice")
    _post(client, _sarif([_result(uri="app/a.py"), _result(uri="app/b.py")]))

    assert sorted(f["asset"] for f in client.get("/findings").json()) == [
        "app/a.py", "app/b.py",
    ]


def test_a_fixed_code_finding_the_scanner_still_sees_is_reopened(client):
    client.login_as("alice")
    _post(client, _sarif([_result()]))
    finding = client.get("/findings").json()[0]

    client.put(f"/findings/{finding['id']}", json={**finding, "status": "fixed"})
    assert _post(client, _sarif([_result()])).json()["reopened"] == 1
    assert client.get(f"/findings/{finding['id']}").json()["status"] == "open"


def test_results_without_a_rule_or_a_file_are_counted_not_fatal(client):
    client.login_as("alice")

    body = _sarif([
        _result(),
        {"level": "error", "message": {"text": "ruleId yok"}},
        {"ruleId": "no-location"},
        "bir dize",
    ])
    res = _post(client, body).json()

    assert res["created"] == 1
    assert res["skipped"] == 3


def test_a_file_that_is_not_sarif_is_rejected(client):
    client.login_as("alice")
    assert client.post("/import/sarif", content="bu json değil").status_code == 400


def test_an_empty_run_is_rejected(client):
    """A report with no results at all is more likely a mistake than news."""
    client.login_as("alice")
    assert _post(client, _sarif([])).status_code == 400


def test_the_import_is_logged_with_the_tool_name(client):
    client.login_as("alice")
    _post(client, _sarif([_result()], tool="CodeQL"))

    entry = next(e for e in client.get("/audit/me").json() if e["action"] == "imported")
    assert "codeql" in entry["detail"]
    assert "1 yeni" in entry["detail"]
