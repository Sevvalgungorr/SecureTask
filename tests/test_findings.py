"""Finding CRUD, per-user ownership, SLA dates, and admin access."""
from datetime import date, timedelta


def test_requires_authentication(client):
    # No login_as() -> the real auth dependency runs and rejects.
    assert client.get("/findings").status_code == 401


def test_create_and_list_own_finding(client):
    client.login_as("alice")

    created = client.post(
        "/findings",
        json={"title": "Missing HSTS header", "asset": "app.example.test"},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["title"] == "Missing HSTS header"
    assert body["asset"] == "app.example.test"
    assert body["severity"] == "medium"  # default
    assert body["status"] == "open"  # default

    listed = client.get("/findings").json()
    assert [f["title"] for f in listed] == ["Missing HSTS header"]


def test_findings_are_isolated_per_user(client):
    client.login_as("alice")
    finding_id = client.post("/findings", json={"title": "Alice secret"}).json()["id"]

    # Bob logs in and must not see or reach Alice's finding.
    client.login_as("bob")
    assert client.get("/findings").json() == []
    assert client.get(f"/findings/{finding_id}").status_code == 404
    assert client.delete(f"/findings/{finding_id}").status_code == 404


def test_due_date_defaults_to_the_severity_sla(client):
    client.login_as("alice")

    critical = client.post(
        "/findings", json={"title": "RCE", "severity": "critical"}
    ).json()
    low = client.post("/findings", json={"title": "Banner", "severity": "low"}).json()

    assert critical["due_date"] == str(date.today() + timedelta(days=7))
    assert low["due_date"] == str(date.today() + timedelta(days=90))


def test_explicit_due_date_is_not_overridden(client):
    client.login_as("alice")

    finding = client.post(
        "/findings",
        json={"title": "Agreed with the team", "severity": "critical",
              "due_date": "2026-12-31"},
    ).json()

    assert finding["due_date"] == "2026-12-31"


def test_update_preserves_severity_and_due_date(client):
    client.login_as("alice")
    finding = client.post(
        "/findings",
        json={"title": "Report", "severity": "high", "due_date": "2026-08-01"},
    ).json()

    # Moving through the workflow must keep severity/due_date (regression guard).
    updated = client.put(
        f"/findings/{finding['id']}",
        json={
            "title": "Report",
            "description": None,
            "asset": "",
            "status": "fixed",
            "severity": "high",
            "due_date": "2026-08-01",
        },
    ).json()
    assert updated["status"] == "fixed"
    assert updated["severity"] == "high"
    assert updated["due_date"] == "2026-08-01"


def test_invalid_severity_rejected(client):
    client.login_as("alice")
    res = client.post("/findings", json={"title": "X", "severity": "urgent"})
    assert res.status_code == 422  # not one of low/medium/high/critical


def test_invalid_status_rejected(client):
    client.login_as("alice")
    res = client.post("/findings", json={"title": "X", "status": "closed"})
    assert res.status_code == 422  # not one of the four workflow states


def test_admin_sees_all_findings_others_forbidden(client):
    client.login_as("alice")
    client.post("/findings", json={"title": "Alice finding"})

    # A non-admin cannot reach the admin endpoint.
    client.login_as("bob")
    assert client.get("/admin/findings").status_code == 403

    # An admin sees every user's finding.
    client.login_as("admin", roles=["admin"])
    all_findings = client.get("/admin/findings").json()
    assert any(f["title"] == "Alice finding" for f in all_findings)
