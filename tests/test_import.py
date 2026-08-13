"""Importing scanner output.

The rules that matter are not about parsing — they are about what an import is
allowed to do to a finding a person has already judged.
"""
import json
from datetime import date, timedelta

REASON = "Sağlayıcı yaması çıkana kadar ağ tarafında sınırlandırıldı"

from app.importers import MAX_RESULTS


def _result(template_id="missing-hsts", host="https://app.example.test",
            severity="medium", name="HSTS başlığı eksik"):
    return {
        "template-id": template_id,
        "host": host,
        "matched-at": host + "/",
        "info": {"name": name, "severity": severity, "description": "kanıt"},
    }


def _post(client, entries, as_lines=False):
    body = (
        "\n".join(json.dumps(e) for e in entries) if as_lines else json.dumps(entries)
    )
    return client.post("/import/nuclei", content=body)


def test_import_requires_authentication(client):
    assert client.post("/import/nuclei", content="[]").status_code == 401


def test_creates_findings_with_sla_and_source(client):
    client.login_as("alice")

    res = _post(client, [_result(), _result("old-tls", severity="high", name="Eski TLS")])
    assert res.status_code == 200
    assert res.json()["created"] == 2

    findings = {f["title"]: f for f in client.get("/findings").json()}
    assert findings["HSTS başlığı eksik"]["asset"] == "app.example.test"
    assert findings["HSTS başlığı eksik"]["severity"] == "medium"
    assert findings["HSTS başlığı eksik"]["source"] == "nuclei"
    assert findings["HSTS başlığı eksik"]["source_ref"] == "missing-hsts"
    # SLA comes from severity, exactly as a hand-filed finding would get.
    assert findings["HSTS başlığı eksik"]["due_date"] is not None
    assert findings["Eski TLS"]["severity"] == "high"


def test_jsonl_is_accepted_too(client):
    """nuclei writes one object per line as often as an array."""
    client.login_as("alice")
    assert _post(client, [_result(), _result("dir-listing")], as_lines=True).json()["created"] == 2


def test_rescanning_does_not_duplicate(client):
    client.login_as("alice")
    _post(client, [_result()])

    second = _post(client, [_result()]).json()
    assert second == {"created": 0, "reopened": 0, "escalated": 0,
                      "unchanged": 1, "kept_accepted": 0, "skipped": 0}
    assert len(client.get("/findings").json()) == 1


def test_the_same_rule_on_another_host_is_a_separate_finding(client):
    client.login_as("alice")
    _post(client, [_result(host="https://a.example.test")])
    _post(client, [_result(host="https://b.example.test")])

    assert sorted(f["asset"] for f in client.get("/findings").json()) == [
        "a.example.test", "b.example.test",
    ]


def test_a_fixed_finding_the_scanner_still_sees_is_reopened(client):
    """Evidence beats the checkbox: it was not fixed."""
    client.login_as("alice")
    _post(client, [_result()])
    finding = client.get("/findings").json()[0]

    client.put(f"/findings/{finding['id']}", json={**finding, "status": "fixed"})
    assert _post(client, [_result()]).json()["reopened"] == 1

    reopened = client.get(f"/findings/{finding['id']}").json()
    assert reopened["status"] == "open"

    entry = next(
        e for e in client.get("/audit/me").json()
        if "fixed→open" in (e["detail"] or "")
    )
    assert "tarama hâlâ görüyor" in entry["detail"]


def test_an_accepted_risk_is_left_alone(client):
    """Finding it again is the expected outcome of accepting it, not news.

    An import must not undo a decision that itself required a second factor.
    """
    client.login_as("alice", amr=["otp"])
    _post(client, [_result()])
    finding = client.get("/findings").json()[0]
    client.put(f"/findings/{finding['id']}", json={
        **finding, "status": "accepted_risk", "accepted_reason": REASON,
        "accepted_until": str(date.today() + timedelta(days=30)),
    })

    assert _post(client, [_result()]).json()["kept_accepted"] == 1
    assert client.get(f"/findings/{finding['id']}").json()["status"] == "accepted_risk"


def test_scanner_does_not_overrule_a_triaged_severity(client):
    """Someone downgraded this on purpose; the next scan is not a veto."""
    client.login_as("alice")
    _post(client, [_result(severity="high")])
    finding = client.get("/findings").json()[0]
    client.put(f"/findings/{finding['id']}", json={**finding, "severity": "low"})

    _post(client, [_result(severity="high")])
    assert client.get(f"/findings/{finding['id']}").json()["severity"] == "low"


def test_imports_are_isolated_per_user(client):
    client.login_as("alice")
    _post(client, [_result()])

    client.login_as("bob")
    assert client.get("/findings").json() == []
    # Bob's identical scan is his own finding, not a hit on Alice's.
    assert _post(client, [_result()]).json()["created"] == 1


def test_unusable_entries_are_counted_not_fatal(client):
    client.login_as("alice")

    res = _post(client, [
        _result(),
        {"info": {"name": "template-id yok"}},            # no template-id
        {"template-id": "no-host"},                        # no host
        "bir dize",                                        # not an object
    ]).json()

    assert res["created"] == 1
    assert res["skipped"] == 3


def test_a_broken_line_does_not_lose_the_rest(client):
    client.login_as("alice")
    body = json.dumps(_result()) + "\n{bozuk\n" + json.dumps(_result("dir-listing"))

    res = client.post("/import/nuclei", content=body).json()
    assert res["created"] == 2
    assert res["skipped"] == 1


def test_empty_body_is_rejected(client):
    client.login_as("alice")
    assert client.post("/import/nuclei", content="").status_code == 400


def test_an_import_is_capped(client):
    """An authenticated user is still not a way to fill the database."""
    client.login_as("alice")
    entries = [_result(template_id=f"rule-{i}") for i in range(MAX_RESULTS + 50)]

    assert _post(client, entries).json()["created"] == MAX_RESULTS


def test_the_import_itself_is_logged(client):
    client.login_as("alice")
    _post(client, [_result()])

    entry = next(e for e in client.get("/audit/me").json() if e["action"] == "imported")
    assert "1 yeni" in entry["detail"]
    assert entry["finding_id"] is None


def test_info_severity_becomes_low(client):
    """Not a vulnerability, but still inventory — kept at the bottom."""
    client.login_as("alice")
    _post(client, [_result(severity="info")])

    assert client.get("/findings").json()[0]["severity"] == "low"


def test_a_worse_rating_from_the_scanner_escalates(client):
    """The template started rating this critical; that is a different fact."""
    client.login_as("alice")
    _post(client, [_result(severity="medium")])

    assert _post(client, [_result(severity="critical")]).json()["escalated"] == 1
    assert client.get("/findings").json()[0]["severity"] == "critical"
