"""Monitoring: the SSRF guard, and what a check may do to a finding.

No test here touches the network. The checks are replaced with a stub, because
what needs proving is the bookkeeping — which findings get opened, escalated,
reopened and closed — not that httpx can make a request.
"""
import pytest

import app.main as main_module
from app.monitor import CheckResult, TargetRefused


@pytest.fixture()
def checks(monkeypatch):
    """Control what the checks 'observe' for each host."""
    observed: dict[str, list[CheckResult]] = {}

    def fake_run_checks(host):
        if host in observed and observed[host] == "refuse":
            raise TargetRefused("test: reddedildi")
        return observed.get(host, [])

    monkeypatch.setattr(main_module, "run_checks", fake_run_checks)
    # Registration resolves the name for real; the tests are not about DNS.
    monkeypatch.setattr(main_module, "assert_target_allowed", lambda host: None)
    return observed


def _result(check_id="header-strict-transport-security", severity="high",
            title="HSTS başlığı eksik", detail="yanıtta yok"):
    return CheckResult(check_id, title, severity, detail)


def _register(client, host="app.example.test"):
    return client.post("/assets", json={"host": host, "label": "test"})


# --- registering a target --------------------------------------------------


def test_assets_require_authentication(client):
    assert client.get("/assets").status_code == 401


def test_a_host_is_registered_and_listed(client, checks):
    client.login_as("alice")

    created = _register(client)
    assert created.status_code == 200
    assert created.json()["host"] == "app.example.test"

    assert [a["host"] for a in client.get("/assets").json()] == ["app.example.test"]


def test_a_url_is_not_a_host(client, checks):
    client.login_as("alice")

    for bad in ("https://app.example.test", "app.example.test/admin", "a b"):
        assert client.post("/assets", json={"host": bad}).status_code == 422, bad


def test_the_same_host_is_not_registered_twice(client, checks):
    client.login_as("alice")
    _register(client)

    assert _register(client).status_code == 409


def test_assets_are_isolated_per_user(client, checks):
    client.login_as("alice")
    asset_id = _register(client).json()["id"]

    client.login_as("bob")
    assert client.get("/assets").json() == []
    assert client.delete(f"/assets/{asset_id}").status_code == 404


def test_a_private_address_is_refused_at_registration(client, monkeypatch):
    """The guard runs before the target is stored, not only before it is used.

    Accepting it now and refusing it later would leave a list of targets that
    look accepted and silently never run.
    """
    client.login_as("alice")
    assert client.post("/assets", json={"host": "localhost"}).status_code == 422
    assert client.post("/assets", json={"host": "127.0.0.1"}).status_code == 422


# --- what a run does to findings -------------------------------------------


def test_a_failing_check_opens_a_finding_with_an_sla(client, checks):
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [_result()]

    assert client.post("/monitor/run").json()["created"] == 1

    finding = client.get("/findings").json()[0]
    assert finding["title"] == "HSTS başlığı eksik"
    assert finding["asset"] == "app.example.test"
    assert finding["severity"] == "high"
    assert finding["source"] == "monitor"
    assert finding["due_date"] is not None


def test_running_twice_does_not_duplicate(client, checks):
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [_result()]
    client.post("/monitor/run")

    assert client.post("/monitor/run").json() == {
        "checked": 1, "refused": [], "created": 0, "reopened": 0, "escalated": 0,
        "resolved": 0, "unchanged": 1, "kept_accepted": 0,
    }
    assert len(client.get("/findings").json()) == 1


def test_a_check_that_starts_passing_closes_its_finding(client, checks):
    """The monitor may close what the monitor opened."""
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [_result()]
    client.post("/monitor/run")

    checks["app.example.test"] = []          # header is back
    assert client.post("/monitor/run").json()["resolved"] == 1
    assert client.get("/findings").json()[0]["status"] == "fixed"

    entry = next(
        e for e in client.get("/audit/me").json()
        if "kontrol artık geçiyor" in (e["detail"] or "")
    )
    assert "open→fixed" in entry["detail"]


def test_a_regression_reopens_the_finding(client, checks):
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [_result()]
    client.post("/monitor/run")
    checks["app.example.test"] = []
    client.post("/monitor/run")              # closed

    checks["app.example.test"] = [_result()]  # someone removed it again
    assert client.post("/monitor/run").json()["reopened"] == 1
    assert client.get("/findings").json()[0]["status"] == "open"


def test_worsening_evidence_escalates_severity(client, checks):
    """A certificate with two days left is a different fact, not a re-argument."""
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [
        _result("tls-cert-expiry", "medium", "Sertifika doluyor", "28 gün kaldı")
    ]
    client.post("/monitor/run")

    checks["app.example.test"] = [
        _result("tls-cert-expiry", "critical", "Sertifika doluyor", "süresi doldu")
    ]
    assert client.post("/monitor/run").json()["escalated"] == 1

    finding = client.get("/findings").json()[0]
    assert finding["severity"] == "critical"
    assert finding["description"] == "süresi doldu"

    entry = next(
        e for e in client.get("/audit/me").json()
        if "severity medium→critical" in (e["detail"] or "")
    )
    assert "monitör" in entry["detail"]


def test_severity_is_never_lowered_automatically(client, checks):
    """Someone downgraded this deliberately; a passing-but-still-failing check
    does not get to undo that."""
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [_result(severity="high")]
    client.post("/monitor/run")

    finding = client.get("/findings").json()[0]
    client.put(f"/findings/{finding['id']}", json={**finding, "severity": "low"})

    checks["app.example.test"] = [_result(severity="high")]
    client.post("/monitor/run")

    assert client.get(f"/findings/{finding['id']}").json()["severity"] == "low"


def test_an_accepted_risk_survives_a_run(client, checks):
    client.login_as("alice", amr=["otp"])
    _register(client)
    checks["app.example.test"] = [_result()]
    client.post("/monitor/run")

    finding = client.get("/findings").json()[0]
    client.put(f"/findings/{finding['id']}", json={**finding, "status": "accepted_risk"})

    assert client.post("/monitor/run").json()["kept_accepted"] == 1
    assert client.get(f"/findings/{finding['id']}").json()["status"] == "accepted_risk"


def test_it_never_closes_a_finding_it_did_not_open(client, checks):
    """A hand-filed finding is not the monitor's to resolve."""
    client.login_as("alice")
    _register(client)
    manual = client.post(
        "/findings", json={"title": "Elle girildi", "asset": "app.example.test"}
    ).json()

    checks["app.example.test"] = []
    assert client.post("/monitor/run").json()["resolved"] == 0
    assert client.get(f"/findings/{manual['id']}").json()["status"] == "open"


def test_a_target_that_starts_resolving_internally_is_refused_mid_run(client, checks):
    """Registration passed, but the name now points somewhere else."""
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = "refuse"

    body = client.post("/monitor/run").json()
    assert body["refused"] == [{"host": "app.example.test", "reason": "test: reddedildi"}]
    assert body["created"] == 0


def test_the_run_is_logged(client, checks):
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [_result()]
    client.post("/monitor/run")

    entry = next(e for e in client.get("/audit/me").json() if e["action"] == "monitored")
    assert "1 varlık" in entry["detail"]
    assert entry["finding_id"] is None


def test_runs_only_cover_your_own_assets(client, checks):
    client.login_as("alice")
    _register(client)
    checks["app.example.test"] = [_result()]

    client.login_as("bob")
    assert client.post("/monitor/run").json()["checked"] == 0
    assert client.get("/findings").json() == []
