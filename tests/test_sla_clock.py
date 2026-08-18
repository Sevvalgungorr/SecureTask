"""The two ends of a finding's remediation window.

A deadline on its own only says how much time is left. `created_at` says how
much of the window has been used; `closed_at`, set against the deadline, says
whether the window was met — which is the number the whole SLA exists to
produce, and the one a report would be built on.

Six places in the application move a finding across the open/closed line, so
these tests are mostly about one question: does the timestamp still tell the
truth when the status was changed by something other than a person editing it?
"""
from datetime import date, timedelta

from app.models import Finding

REASON = "Sağlayıcı yaması çıkana kadar ağ tarafında sınırlandırıldı"


def _payload(**fields):
    payload = {
        "title": "Eski TLS sürümü",
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


def _file(client, **fields):
    return client.post("/findings", json=_payload(**fields)).json()


def _put(client, finding_id, **fields):
    return client.put(f"/findings/{finding_id}", json=_payload(**fields))


# --- the window opens -------------------------------------------------------


def test_a_new_finding_starts_its_clock(client):
    client.login_as("alice")

    body = _file(client)

    assert body["created_at"]
    # Nothing has closed it, so there is nothing to measure against yet.
    assert body["closed_at"] is None


def test_the_client_does_not_get_to_set_the_clock(client):
    """A caller that could name its own creation time could file a finding that
    was already late, or one that never ages. Both ends are the server's."""
    client.login_as("alice")

    body = client.post(
        "/findings",
        json={
            **_payload(),
            "created_at": "2001-01-01T00:00:00+00:00",
            "closed_at": "2001-01-02T00:00:00+00:00",
        },
    ).json()

    assert not body["created_at"].startswith("2001")
    assert body["closed_at"] is None


# --- and closes -------------------------------------------------------------


def test_fixing_a_finding_stamps_the_close(client):
    client.login_as("alice")
    finding = _file(client)

    body = _put(client, finding["id"], status="fixed").json()

    assert body["closed_at"] is not None
    # The start is not touched by closing it.
    assert body["created_at"] == finding["created_at"]


def test_accepting_a_risk_stamps_the_close(client):
    """An accepted risk is closed too. It is off the list of work, and the
    difference from `fixed` is the reason, not whether the clock stops."""
    client.login_as("alice", amr=["otp"])
    finding = _file(client)

    body = _put(
        client,
        finding["id"],
        status="accepted_risk",
        accepted_reason=REASON,
        accepted_until=str(date.today() + timedelta(days=30)),
    ).json()

    assert body["closed_at"] is not None


def test_filing_something_already_closed_stamps_it_at_once(client):
    client.login_as("alice")

    assert _file(client, status="fixed")["closed_at"] is not None


def test_reopening_clears_the_close(client):
    """Otherwise the row would carry a close time while sitting open, and every
    SLA figure built on it would be counting a finding that is still live."""
    client.login_as("alice")
    finding = _file(client)
    _put(client, finding["id"], status="fixed")

    body = _put(client, finding["id"], status="triaged").json()

    assert body["closed_at"] is None


def test_changing_the_reason_does_not_restamp(client):
    """fixed → accepted_risk changes why it is closed, not that it is. The
    finding never went back on the list, so the close time is still the first
    one — restamping would quietly turn a late close into a punctual one."""
    client.login_as("alice", amr=["otp"])
    finding = _file(client)
    first = _put(client, finding["id"], status="fixed").json()["closed_at"]

    body = _put(
        client,
        finding["id"],
        status="accepted_risk",
        accepted_reason=REASON,
        accepted_until=str(date.today() + timedelta(days=30)),
    ).json()

    assert body["closed_at"] == first


# --- the four ways the application itself moves a finding -------------------


SARIF = """{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "semgrep"}},
    "results": [{
      "ruleId": "python.lang.security.audit.dangerous-exec",
      "level": "error",
      "message": {"text": "exec ile çalıştırma"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "app/run.py"},
        "region": {"startLine": 9}
      }}]
    }]
  }]
}"""


def _import(client):
    return client.post(
        "/import/sarif",
        content=SARIF,
        headers={"content-type": "application/json"},
    )


def test_an_import_reopening_a_fixed_finding_clears_the_close(client):
    """The scanner still sees it, so the finding goes back on the list. A close
    time surviving that would say the work was finished when it was not."""
    client.login_as("alice")
    _import(client)
    finding = client.get("/findings").json()[0]
    _put(
        client,
        finding["id"],
        title=finding["title"],
        asset=finding["asset"],
        severity=finding["severity"],
        status="fixed",
    )
    assert client.get(f"/findings/{finding['id']}").json()["closed_at"] is not None

    _import(client)

    body = client.get(f"/findings/{finding['id']}").json()
    assert body["status"] == "open"
    assert body["closed_at"] is None


def test_an_expiring_acceptance_clears_the_close(client):
    """The acceptance ended, so the finding is live again — and its next close
    has to be measured from that, not from the acceptance it outlived."""
    client.login_as("alice", amr=["otp"])
    finding = _file(client)
    _put(
        client,
        finding["id"],
        status="accepted_risk",
        accepted_reason=REASON,
        accepted_until=str(date.today() + timedelta(days=5)),
    )

    # Move the expiry into the past the way the calendar would.
    row = client.db.query(Finding).filter(Finding.id == finding["id"]).one()
    row.accepted_until = date.today() - timedelta(days=1)
    client.db.commit()

    client.post("/risk/expire")

    body = client.get(f"/findings/{finding['id']}").json()
    assert body["status"] == "open"
    assert body["closed_at"] is None
