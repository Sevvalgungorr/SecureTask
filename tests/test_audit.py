"""Audit logging and the per-user history endpoint."""


def _edit(client, finding_id, **fields):
    payload = {
        "title": "Track me",
        "description": None,
        "asset": "",
        "severity": "medium",
        "status": "open",
        "due_date": None,
    }
    payload.update(fields)
    return client.put(f"/findings/{finding_id}", json=payload)


def test_actions_are_recorded_in_audit(client):
    client.login_as("admin", roles=["admin"])

    finding_id = client.post("/findings", json={"title": "Track me"}).json()["id"]
    _edit(client, finding_id, status="fixed")
    client.delete(f"/findings/{finding_id}")

    actions = [e["action"] for e in client.get("/admin/audit").json()]
    assert "created" in actions
    assert "updated" in actions
    assert "deleted" in actions


def test_severity_and_status_changes_are_spelled_out(client):
    """Downgrading a finding or accepting its risk must be readable in the log."""
    # Accepting a risk needs a second factor (see test_step_up.py); this test is
    # about what the log says afterwards, so it starts from an MFA session.
    client.login_as("admin", roles=["admin"], amr=["pwd", "otp"])

    finding_id = client.post(
        "/findings", json={"title": "Track me", "severity": "critical"}
    ).json()["id"]
    _edit(client, finding_id, severity="low", status="accepted_risk")

    entry = next(
        e for e in client.get("/admin/audit").json() if e["action"] == "updated"
    )
    assert "severity critical→low" in entry["detail"]
    assert "status open→accepted_risk" in entry["detail"]


def test_audit_survives_finding_deletion(client):
    client.login_as("admin", roles=["admin"])
    finding_id = client.post("/findings", json={"title": "Doomed"}).json()["id"]
    client.delete(f"/findings/{finding_id}")

    entry = next(
        e for e in client.get("/admin/audit").json()
        if e["action"] == "deleted" and e["finding_id"] == finding_id
    )
    assert entry["detail"] == "Doomed"


def test_audit_me_returns_only_own_entries(client):
    client.login_as("alice")
    client.post("/findings", json={"title": "Alice does this"})

    bob = client.login_as("bob")
    client.post("/findings", json={"title": "Bob does that"})

    # Bob's history has only Bob's action.
    bob_history = client.get("/audit/me").json()
    assert all(e["user_id"] == bob.id for e in bob_history)
    assert any("Bob does that" in (e["detail"] or "") for e in bob_history)
    assert not any("Alice does this" in (e["detail"] or "") for e in bob_history)


def test_audit_me_requires_authentication(client):
    assert client.get("/audit/me").status_code == 401
