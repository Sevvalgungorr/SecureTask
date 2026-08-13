"""Teams, assignment, and the rule that the reporter may not accept.

Every other control here constrains somebody. These tests are about there being
a somebody: two people on one finding, and what each of them is allowed to do
with it.
"""
from datetime import date, timedelta

REASON = "Sağlayıcı yaması çıkana kadar ağ tarafında sınırlandırıldı"
UNTIL = str(date.today() + timedelta(days=30))


def _payload(**fields):
    payload = {
        "title": "Yönetim ucu kimlik doğrulaması istemiyor",
        "description": None,
        "asset": "portal.example.test",
        "severity": "high",
        "status": "open",
        "due_date": None,
        "team_id": None,
        "accepted_reason": None,
        "accepted_until": None,
    }
    payload.update(fields)
    return payload


def _accept(client, finding_id, team_id):
    return client.put(
        f"/findings/{finding_id}",
        json=_payload(
            team_id=team_id, status="accepted_risk",
            accepted_reason=REASON, accepted_until=UNTIL,
        ),
    )


def _team_with_two(client):
    """A team whose risk owner is `sevval` and whose member is `ahmet`."""
    sevval = client.login_as("sevval", amr=["pwd", "otp"])
    team = client.post("/teams", json={"name": "Altyapı Güvenliği"}).json()

    ahmet = client.login_as("ahmet", amr=["pwd", "otp"])
    client.become(sevval)
    client.post(f"/teams/{team['id']}/members", json={"user_id": ahmet.id})

    return team, sevval, ahmet


# --- Membership ------------------------------------------------------------


def test_creating_a_team_makes_you_its_risk_owner(client):
    """Someone has to be able to accept, or the team could never close that way."""
    client.login_as("sevval")

    team = client.post("/teams", json={"name": "Altyapı Güvenliği"}).json()

    assert team["my_role"] == "risk_owner"
    assert [m["username"] for m in team["members"]] == ["sevval"]


def test_a_plain_member_cannot_add_people(client):
    team, sevval, ahmet = _team_with_two(client)
    client.login_as("mert")
    client.become(ahmet)

    response = client.post(f"/teams/{team['id']}/members", json={"user_id": 99})

    assert response.status_code == 403


def test_a_team_you_are_not_in_reads_as_missing(client):
    """404 rather than 403: the answer does not confirm the team exists."""
    client.login_as("sevval")
    team = client.post("/teams", json={"name": "Altyapı Güvenliği"}).json()

    client.login_as("yabanci")
    response = client.post(f"/teams/{team['id']}/members", json={"user_id": 1})

    assert response.status_code == 404


def test_the_last_risk_owner_cannot_be_removed(client):
    """A team without one could never accept a risk, or renew what it accepted."""
    team, sevval, ahmet = _team_with_two(client)

    response = client.delete(f"/teams/{team['id']}/members/{sevval.id}")

    assert response.status_code == 422
    assert "son risk sahibi" in response.json()["detail"]


# --- Visibility ------------------------------------------------------------


def test_a_teammate_sees_a_finding_they_did_not_file(client):
    team, sevval, ahmet = _team_with_two(client)
    client.become(ahmet)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    client.become(sevval)

    assert client.get(f"/findings/{finding_id}").status_code == 200
    assert [f["id"] for f in client.get("/findings").json()] == [finding_id]


def test_someone_outside_the_team_sees_nothing(client):
    team, sevval, ahmet = _team_with_two(client)
    client.become(ahmet)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    client.login_as("yabanci")

    assert client.get(f"/findings/{finding_id}").status_code == 404
    assert client.get("/findings").json() == []


def test_a_personal_finding_stays_personal(client):
    """No team means visible to its reporter alone — how every row looked before."""
    team, sevval, ahmet = _team_with_two(client)
    client.become(ahmet)
    finding_id = client.post("/findings", json=_payload()).json()["id"]

    client.become(sevval)

    assert client.get(f"/findings/{finding_id}").status_code == 404


def test_filing_into_a_team_you_are_not_in_is_refused(client):
    client.login_as("sevval")
    team = client.post("/teams", json={"name": "Altyapı Güvenliği"}).json()

    client.login_as("yabanci")
    response = client.post("/findings", json=_payload(team_id=team["id"]))

    assert response.status_code == 404


def test_a_finding_cannot_be_moved_between_teams_by_an_edit(client):
    """Which team a finding is in says who may see it; an edit must not move it."""
    team, sevval, ahmet = _team_with_two(client)
    client.become(ahmet)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    response = client.put(f"/findings/{finding_id}", json=_payload(team_id=None))

    assert response.status_code == 422
    assert "ekibi" in response.json()["detail"]


# --- Assignment ------------------------------------------------------------


def test_a_finding_can_be_handed_to_a_teammate(client):
    team, sevval, ahmet = _team_with_two(client)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    response = client.put(
        f"/findings/{finding_id}/assignee", json={"assignee_id": ahmet.id}
    )

    assert response.status_code == 200
    assert response.json()["assignee_id"] == ahmet.id
    entry = next(
        e for e in client.get("/audit/me").json() if e["action"] == "assigned"
    )
    assert "atandı: ahmet" in entry["detail"]


def test_a_finding_can_be_handed_back(client):
    team, sevval, ahmet = _team_with_two(client)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]
    client.put(f"/findings/{finding_id}/assignee", json={"assignee_id": ahmet.id})

    response = client.put(f"/findings/{finding_id}/assignee", json={"assignee_id": None})

    assert response.json()["assignee_id"] is None


def test_assigning_outside_the_team_is_refused(client):
    """Work handed to someone who cannot see it is not handed to anyone."""
    team, sevval, ahmet = _team_with_two(client)
    yabanci = client.login_as("yabanci")
    client.become(sevval)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    response = client.put(
        f"/findings/{finding_id}/assignee", json={"assignee_id": yabanci.id}
    )

    assert response.status_code == 422


def test_a_personal_finding_cannot_be_assigned(client):
    client.login_as("sevval")
    finding_id = client.post("/findings", json=_payload()).json()["id"]

    response = client.put(f"/findings/{finding_id}/assignee", json={"assignee_id": 1})

    assert response.status_code == 422


# --- Separation of duties --------------------------------------------------


def test_the_reporter_cannot_accept_their_own_finding(client):
    """The whole point: whoever says it matters does not get to say it is fine.

    sevval is the team's risk owner and has a second factor — everything else
    that guards an acceptance is satisfied. She filed it, so the answer is no.
    """
    team, sevval, ahmet = _team_with_two(client)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    response = _accept(client, finding_id, team["id"])

    assert response.status_code == 403
    assert "görev ayrılığı" in response.json()["detail"]


def test_another_risk_owner_can_accept_it(client):
    team, sevval, ahmet = _team_with_two(client)
    client.become(ahmet)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    client.become(sevval)
    response = _accept(client, finding_id, team["id"])

    assert response.status_code == 200
    assert response.json()["status"] == "accepted_risk"
    assert response.json()["accepted_reason"] == REASON


def test_a_plain_member_cannot_accept_even_with_a_second_factor(client):
    """Step-up proves who is asking, not that they are allowed to ask."""
    team, sevval, ahmet = _team_with_two(client)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    client.become(ahmet, amr=["pwd", "otp"])
    response = _accept(client, finding_id, team["id"])

    assert response.status_code == 403
    assert "risk sahibi" in response.json()["detail"]


def test_filing_a_team_finding_as_already_accepted_is_refused(client):
    """Filing it accepted is the same decision, made by the same person."""
    team, sevval, ahmet = _team_with_two(client)

    response = client.post(
        "/findings",
        json=_payload(
            team_id=team["id"], status="accepted_risk",
            accepted_reason=REASON, accepted_until=UNTIL,
        ),
    )

    assert response.status_code == 403


def test_a_personal_finding_may_still_be_accepted_by_its_owner(client):
    """One person cannot be two. A personal list has no second person to ask,
    so the rule does not apply to it — and the finding is nobody else's."""
    client.login_as("sevval", amr=["pwd", "otp"])
    finding_id = client.post("/findings", json=_payload()).json()["id"]

    response = client.put(
        f"/findings/{finding_id}",
        json=_payload(
            status="accepted_risk", accepted_reason=REASON, accepted_until=UNTIL
        ),
    )

    assert response.status_code == 200


def test_a_refused_acceptance_is_visible_as_a_denied_access(client):
    """A rejected attempt to close a risk is a security event, not a UI error."""
    team, sevval, ahmet = _team_with_two(client)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    _accept(client, finding_id, team["id"])

    client.become(sevval, roles=["admin"])
    denied = [e for e in client.get("/admin/audit").json() if e["action"] == "access_denied"]
    assert any("403 PUT /findings" in e["detail"] for e in denied)


# --- Deletion --------------------------------------------------------------


def test_a_teammate_cannot_delete_what_someone_else_filed(client):
    """Every other outcome is recorded; deletion removes the row instead."""
    team, sevval, ahmet = _team_with_two(client)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    client.become(ahmet)
    response = client.delete(f"/findings/{finding_id}")

    assert response.status_code == 403


def test_the_reporter_may_withdraw_their_own(client):
    team, sevval, ahmet = _team_with_two(client)
    client.become(ahmet)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    assert client.delete(f"/findings/{finding_id}").status_code == 200


def test_a_risk_owner_may_delete_a_teammates_finding(client):
    team, sevval, ahmet = _team_with_two(client)
    client.become(ahmet)
    finding_id = client.post("/findings", json=_payload(team_id=team["id"])).json()["id"]

    client.become(sevval)

    assert client.delete(f"/findings/{finding_id}").status_code == 200


# --- Tools file into the team ----------------------------------------------


def test_an_import_can_file_into_a_team(client):
    """A scan result belongs to the team, not to whoever ran the scanner."""
    team, sevval, ahmet = _team_with_two(client)
    scan = (
        '{"template-id":"missing-hsts","info":{"name":"HSTS eksik","severity":"medium"},'
        '"host":"portal.example.test"}'
    )

    client.post(f"/import/nuclei?team_id={team['id']}", content=scan)

    client.become(ahmet)
    findings = client.get("/findings").json()
    assert [f["team_id"] for f in findings] == [team["id"]]


def test_importing_into_a_team_you_are_not_in_is_refused(client):
    client.login_as("sevval")
    team = client.post("/teams", json={"name": "Altyapı Güvenliği"}).json()

    client.login_as("yabanci")
    response = client.post(f"/import/nuclei?team_id={team['id']}", content="[]")

    assert response.status_code == 404
