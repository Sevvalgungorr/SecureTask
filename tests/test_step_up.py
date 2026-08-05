"""Step-up authentication on the one irreversible decision: accepting a risk.

Fixing a finding removes the problem; accepting its risk leaves the problem in
place by decision. So that transition asks for a second factor even though the
session is already authenticated.
"""


def _payload(**fields):
    payload = {
        "title": "Eski TLS sürümü kabul ediliyor",
        "description": None,
        "asset": "vpn.example.test",
        "severity": "high",
        "status": "open",
        "due_date": None,
    }
    payload.update(fields)
    return payload


def _create(client, **fields):
    return client.post("/findings", json=_payload(**fields))


def test_accepting_risk_without_mfa_is_refused(client):
    client.login_as("alice")  # amr defaults to ["pwd"] — password only
    finding_id = _create(client).json()["id"]

    res = client.put(f"/findings/{finding_id}", json=_payload(status="accepted_risk"))
    assert res.status_code == 403
    assert "faktörlü" in res.json()["detail"]

    # The refusal must not have changed anything.
    assert client.get(f"/findings/{finding_id}").json()["status"] == "open"


def test_accepting_risk_with_mfa_is_allowed_and_logged(client):
    client.login_as("alice", amr=["pwd", "otp"])
    finding_id = _create(client).json()["id"]

    res = client.put(f"/findings/{finding_id}", json=_payload(status="accepted_risk"))
    assert res.status_code == 200
    assert res.json()["status"] == "accepted_risk"

    entry = next(e for e in client.get("/audit/me").json() if e["action"] == "updated")
    assert "status open→accepted_risk" in entry["detail"]
    # The log records that the guard was actually satisfied, not just passed by.
    assert "mfa doğrulandı" in entry["detail"]


def test_acr_also_counts_when_configured(client, monkeypatch):
    """A provider may prove step-up through acr instead of amr."""
    import app.auth as auth

    monkeypatch.setattr(auth, "OIDC_MFA_ACR", frozenset({"level2"}))
    client.login_as("alice", amr=["pwd"], acr="level2")
    finding_id = _create(client).json()["id"]

    res = client.put(f"/findings/{finding_id}", json=_payload(status="accepted_risk"))
    assert res.status_code == 200


def test_password_alone_never_counts_as_a_second_factor(client):
    client.login_as("alice", amr=["pwd", "pwd"])
    finding_id = _create(client).json()["id"]

    assert client.put(
        f"/findings/{finding_id}", json=_payload(status="accepted_risk")
    ).status_code == 403


def test_creating_a_finding_as_accepted_needs_mfa_too(client):
    """Otherwise the guard is bypassed by filing the finding pre-accepted."""
    client.login_as("alice")
    assert _create(client, status="accepted_risk").status_code == 403

    client.login_as("bob", amr=["mfa"])
    assert _create(client, status="accepted_risk").status_code == 200


def test_other_transitions_do_not_require_mfa(client):
    """Fixing a finding removes the risk; it does not need the extra bar."""
    client.login_as("alice")
    finding_id = _create(client).json()["id"]

    for status in ("triaged", "fixed", "open"):
        res = client.put(f"/findings/{finding_id}", json=_payload(status=status))
        assert res.status_code == 200, status


def test_editing_an_already_accepted_finding_stays_open(client):
    """Only the transition is guarded, not every later edit of the row."""
    user = client.login_as("alice", amr=["otp"])
    finding_id = _create(client, status="accepted_risk").json()["id"]

    # Same identity, weaker session: the second factor is gone from the token.
    user.amr = ["pwd"]

    res = client.put(
        f"/findings/{finding_id}",
        json=_payload(status="accepted_risk", title="Eski TLS — gerekçe eklendi"),
    )
    assert res.status_code == 200
    assert res.json()["title"] == "Eski TLS — gerekçe eklendi"


def test_refusal_is_recorded_as_a_denied_access(client):
    """A blocked risk acceptance is a security event, so it lands in the log."""
    client.login_as("admin", roles=["admin"])
    finding_id = _create(client).json()["id"]
    client.put(f"/findings/{finding_id}", json=_payload(status="accepted_risk"))

    denied = [e for e in client.get("/admin/audit").json() if e["action"] == "access_denied"]
    assert any("403 PUT /findings/" in (e["detail"] or "") for e in denied)
