"""The risk acceptance register.

Accepting a risk is the only action here that leaves a known hole open on
purpose. These tests are about the three things that turn that from a way of
closing a ticket into a decision: an argument, an owner, and an end.
"""
from datetime import date, timedelta

from app.models import MAX_ACCEPTANCE_DAYS

REASON = "Sağlayıcı yaması çıkana kadar ağ tarafında sınırlandırıldı"


def _payload(**fields):
    payload = {
        "title": "Eski TLS sürümü kabul ediliyor",
        "description": None,
        "asset": "vpn.example.test",
        "severity": "high",
        "status": "open",
        "due_date": None,
        "accepted_reason": None,
        "accepted_until": None,
    }
    payload.update(fields)
    return payload


def _accept(client, finding_id, **fields):
    body = _payload(
        status="accepted_risk",
        accepted_reason=REASON,
        accepted_until=str(date.today() + timedelta(days=30)),
    )
    body.update(fields)
    return client.put(f"/findings/{finding_id}", json=body)


def _open_finding(client):
    return client.post("/findings", json=_payload()).json()["id"]


# --- an acceptance has to be argued for ------------------------------------


def test_accepting_without_a_reason_is_refused(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)

    res = _accept(client, finding_id, accepted_reason=None)
    assert res.status_code == 422
    assert "gerekçe" in res.json()["detail"]
    assert client.get(f"/findings/{finding_id}").json()["status"] == "open"


def test_a_token_reason_is_not_a_reason(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)

    assert _accept(client, finding_id, accepted_reason="ok").status_code == 422


def test_accepting_without_an_end_date_is_refused(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)

    res = _accept(client, finding_id, accepted_until=None)
    assert res.status_code == 422
    assert "bitiş tarihi" in res.json()["detail"]


def test_an_acceptance_cannot_outlast_the_maximum(client):
    """Nothing is accepted forever; that is how risk accumulates."""
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)

    too_far = date.today() + timedelta(days=MAX_ACCEPTANCE_DAYS + 1)
    res = _accept(client, finding_id, accepted_until=str(too_far))
    assert res.status_code == 422
    assert str(MAX_ACCEPTANCE_DAYS) in res.json()["detail"]


def test_an_end_date_in_the_past_is_refused(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)

    yesterday = date.today() - timedelta(days=1)
    assert _accept(client, finding_id, accepted_until=str(yesterday)).status_code == 422


def test_a_complete_acceptance_is_recorded_with_its_owner(client):
    user = client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)

    assert _accept(client, finding_id).status_code == 200

    finding = client.get(f"/findings/{finding_id}").json()
    assert finding["status"] == "accepted_risk"
    assert finding["accepted_reason"] == REASON
    assert finding["accepted_until"] == str(date.today() + timedelta(days=30))
    assert finding["accepted_by_id"] == user.id
    assert finding["accepted_at"] is not None


def test_the_reason_is_required_when_filing_as_accepted_too(client):
    """Otherwise the requirement is bypassed by creating it pre-accepted."""
    client.login_as("alice", amr=["otp"])

    res = client.post("/findings", json=_payload(status="accepted_risk"))
    assert res.status_code == 422


# --- an acceptance ends ----------------------------------------------------


def test_an_expired_acceptance_reopens(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)
    _accept(client, finding_id)

    # Move the end date into the past, as the passage of time would.
    from app.models import Finding
    db = client.db
    db.query(Finding).filter(Finding.id == finding_id).update(
        {"accepted_until": date.today() - timedelta(days=1)}
    )
    db.commit()

    assert client.post("/risk/expire").json()["reopened"] == 1

    finding = client.get(f"/findings/{finding_id}").json()
    assert finding["status"] == "open"
    # The acceptance is over, so its terms no longer describe the finding.
    assert finding["accepted_reason"] is None
    assert finding["accepted_until"] is None
    # And it gets a live deadline rather than staying overdue from last time.
    assert finding["due_date"] == str(date.today() + timedelta(days=14))


def test_expiry_leaves_a_live_acceptance_alone(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)
    _accept(client, finding_id)

    assert client.post("/risk/expire").json()["reopened"] == 0
    assert client.get(f"/findings/{finding_id}").json()["status"] == "accepted_risk"


def test_the_expiry_is_written_to_the_log(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)
    _accept(client, finding_id)

    from app.models import Finding
    client.db.query(Finding).filter(Finding.id == finding_id).update(
        {"accepted_until": date.today() - timedelta(days=1)}
    )
    client.db.commit()
    client.post("/risk/expire")

    entry = next(
        e for e in client.get("/audit/me").json()
        if "risk kabulünün süresi doldu" in (e["detail"] or "")
        and e["finding_id"] == finding_id
    )
    assert "accepted_risk→open" in entry["detail"]


def test_reaccepting_requires_the_second_factor_again(client):
    """The whole point: the decision has to be made again, not inherited."""
    user = client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)
    _accept(client, finding_id)

    from app.models import Finding
    client.db.query(Finding).filter(Finding.id == finding_id).update(
        {"accepted_until": date.today() - timedelta(days=1)}
    )
    client.db.commit()
    client.post("/risk/expire")

    user.amr = ["pwd"]  # same person, weaker session
    assert _accept(client, finding_id).status_code == 403


def test_leaving_the_accepted_state_clears_the_acceptance(client):
    client.login_as("alice", amr=["otp"])
    finding_id = _open_finding(client)
    _accept(client, finding_id)

    client.put(f"/findings/{finding_id}", json=_payload(status="fixed"))

    finding = client.get(f"/findings/{finding_id}").json()
    assert finding["accepted_reason"] is None
    assert finding["accepted_by_id"] is None
