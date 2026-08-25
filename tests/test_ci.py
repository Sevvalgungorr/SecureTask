"""The one door a machine comes through.

Every other endpoint is used by a person holding a session from an identity
provider. This one is used, unattended, by a program running on hardware nobody
in the team controls, holding a credential that sits in a repository's secrets
and is handed to every workflow that repository ever runs.

So the questions are different. Not "can this user do this" but: what does the
credential buy, what happens when it is wrong, what happens when the caller
lies about which repository it is, and what happens when the provider — as
providers do — sends the same thing twice.
"""
import json

import pytest

from app import ci, scanner
import app.main as main_module
from app.models import (
    CiIntegration,
    Finding,
    GATE_FAILED,
    GATE_INCOMPLETE,
    GATE_PASSED,
    PipelineRun,
    ScanRun,
)

REPO = "Sevvalgungorr/SecureTask"
RUN = "9911-1"

RAW_SECRET = "ghp_R7cQm2Vx9LpTz4Nb8KdWfY3JhS1AeG6UoP0i"


def sarif(rule="B608", level="warning", uri="app/reports.py", line=24):
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Bandit"}},
            "results": [{
                "ruleId": rule,
                "level": level,
                "message": {"text": "Possible SQL injection"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "snippet": {"text": "q = f'...'"}},
                }}],
            }],
        }],
    })


CRITICAL_SARIF = json.dumps({
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Bandit"}},
        # security-severity is GitHub's convention and beats the coarse level.
        "tool_": None,
        "results": [{
            "ruleId": "B602",
            "level": "error",
            "message": {"text": "subprocess with shell=True"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/exporters.py"},
                "region": {"startLine": 42, "snippet": {"text": "shell=True"}},
            }}],
        }],
    }],
})
# The rule declaration that makes it critical, added properly.
_doc = json.loads(CRITICAL_SARIF)
_doc["runs"][0]["tool"]["driver"]["rules"] = [
    {"id": "B602", "properties": {"security-severity": "9.5"}}
]
CRITICAL_SARIF = json.dumps(_doc)

PIP_AUDIT = json.dumps({
    "dependencies": [
        {"name": "requests", "version": "2.19.1", "vulns": [
            {"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"],
             "aliases": ["CVE-2018-18074"], "description": "..."}
        ]},
    ],
    "fixes": [],
})

GITLEAKS = json.dumps([{
    "RuleID": "github-pat",
    "Description": "Detected a GitHub Personal Access Token, ...",
    "StartLine": 24,
    "Match": 'TOKEN = "REDACTED"',
    "Secret": "REDACTED",
    "File": "app/config.py",
}])

GITLEAKS_RAW = json.dumps([{
    "RuleID": "github-pat",
    "Description": "Detected a GitHub Personal Access Token, ...",
    "StartLine": 24,
    "Match": f'TOKEN = "{RAW_SECRET}"',
    "Secret": RAW_SECRET,
    "File": "app/config.py",
}])


@pytest.fixture()
def integration(client, db):
    """A registered repository and the token it was issued, once.

    The owning account is kept on the client so a test can come back to *the
    same* alice. login_as() creates a user; calling it twice would make a
    second account with the same identity, which the database refuses — and
    which would not be the tenant the integration points at anyway.
    """
    owner = client.login_as("alice")
    created = client.post("/ci/integrations", json={
        "repository": REPO, "project": "securetask", "label": "main",
    })
    assert created.status_code == 201, created.text
    body = created.json()
    body["owner"] = owner
    # The caller is now a machine, not alice.
    client.logout()
    return body


def ctx(**over):
    base = {
        "repository": REPO,
        "external_run_id": RUN,
        "branch": "main",
        "commit_sha": "a8f21cdb9e4477712ab3c0d1e2f3a4b5c6d7e8f9",
    }
    base.update(over)
    return base


def post(client, path, token, **body):
    return client.post(path, json=ctx(**body), headers={"X-SecureTask-Token": token})


def _wait_scan(client, db, pipeline_id, kind, tries=80):
    import time

    for _ in range(tries):
        row = (
            db.query(ScanRun)
            .filter(ScanRun.pipeline_id == pipeline_id, ScanRun.kind == kind)
            .one_or_none()
        )
        if row is not None:
            db.refresh(row)
            if row.status in ("completed", "failed", "scanner_unavailable"):
                return row
        time.sleep(0.05)

    raise AssertionError("tarama bitmedi")


# --- the credential ----------------------------------------------------------


def test_the_token_is_shown_once_and_never_stored(client, integration, db):
    """A credential that can be read back is a credential in every screenshot
    of the page that shows it, and in every backup of the database."""
    token = integration["token"]
    row = db.query(CiIntegration).one()

    assert row.token_hash == ci.hash_token(token)
    assert token not in row.token_hash
    # There is no column holding it, redacted or otherwise.
    assert not any(
        token in str(getattr(row, column.name) or "")
        for column in row.__table__.columns
    )

    client.become(integration["owner"])
    listed = client.get("/ci/integrations").text

    assert token not in listed
    assert "token" not in json.loads(listed)[0]


def test_an_invalid_token_is_refused_without_saying_why(client, integration):
    """"No token" and "wrong token" get the same answer. Telling a caller
    which one it was is telling them how close they are."""
    for bad in ("", "nonsense", "st_ci_short", ci.TOKEN_PREFIX + "x" * 40):
        response = post(client, "/ci/results", bad, scan_type="sast", payload=sarif())
        assert response.status_code == 401
        assert response.json()["detail"] == "Geçersiz CI jetonu."


def test_the_token_is_not_written_to_the_audit_log(client, integration, db):
    from app.models import AuditLog

    post(client, "/ci/results", integration["token"], scan_type="sast", payload=sarif())

    for entry in db.query(AuditLog).all():
        assert integration["token"] not in (entry.detail or "")
        assert ci.TOKEN_PREFIX not in (entry.detail or "")


def test_a_session_cannot_post_results_and_a_ci_token_cannot_read_findings(
    client, integration
):
    """Two credential kinds, two headers, no overlap. A CI token that could
    read findings would be a read credential for a whole tenant living in a
    repository's secrets."""
    client.become(integration["owner"])
    # A logged-in session with no CI header is still refused here.
    assert client.post("/ci/results", json=ctx(scan_type="sast", payload=sarif())).status_code == 401
    client.logout()

    # And the CI token opens nothing a person's session opens.
    headers = {"X-SecureTask-Token": integration["token"]}
    assert client.get("/findings", headers=headers).status_code == 401
    assert client.get("/pipelines", headers=headers).status_code == 401


def test_a_token_may_not_name_another_repository(client, integration):
    """The repository in the request is not trusted; it is matched against the
    registration. Without this, any valid token could file findings into
    somebody else's list."""
    response = post(
        client, "/ci/results", integration["token"],
        repository="someone-else/their-repo", scan_type="sast", payload=sarif(),
    )

    assert response.status_code == 403


def test_an_unregistered_repository_has_no_token_at_all(client, db):
    """There is no path from "unknown repository" to a finding: a token only
    exists because someone registered a repository against their own account."""
    assert db.query(CiIntegration).count() == 0
    response = post(client, "/ci/results", "st_ci_" + "a" * 40, scan_type="sast", payload=sarif())

    assert response.status_code == 401


def test_findings_land_in_the_registered_tenant_not_a_requested_one(
    client, integration, db
):
    post(client, "/ci/results", integration["token"], scan_type="sast", payload=sarif())

    client.login_as("bob")
    assert client.get("/findings").json() == []
    assert client.get("/pipelines").json() == []

    client.become(integration["owner"])
    assert len(client.get("/findings").json()) == 1
    assert len(client.get("/pipelines").json()) == 1


# --- the pipeline ------------------------------------------------------------


def test_a_run_is_created_once_and_reported_into(client, integration, db):
    post(client, "/ci/results", integration["token"], scan_type="sast", payload=sarif())

    row = db.query(PipelineRun).one()

    assert row.repository == REPO
    assert row.external_run_id == RUN
    assert row.branch == "main"
    assert row.commit_sha.startswith("a8f21cd")


def test_a_retried_request_does_not_import_twice(client, integration, db):
    """CI providers retry: on a timeout, on a network blip, on a re-run of one
    job. A second pipeline for one run would give the same commit two
    different answers."""
    token = integration["token"]

    first = post(client, "/ci/results", token, scan_type="sast", payload=sarif())
    second = post(client, "/ci/results", token, scan_type="sast", payload=sarif())

    assert first.status_code == second.status_code == 200
    assert db.query(PipelineRun).count() == 1
    assert db.query(ScanRun).count() == 1
    assert db.query(Finding).count() == 1


def test_a_different_run_id_is_a_different_pipeline(client, integration, db):
    """A genuine re-run — after a fix — has to be able to reach a new verdict."""
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=sarif())
    post(client, "/ci/results", token, external_run_id="9911-2",
         scan_type="sast", payload=sarif())

    assert db.query(PipelineRun).count() == 2
    # And the finding is still one finding: the commit is not in its identity.
    assert db.query(Finding).count() == 1


def test_the_commit_is_not_part_of_a_findings_identity(client, integration, db):
    """Otherwise every commit files the same vulnerability again, and a week of
    CI produces a list nobody can read."""
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=sarif())
    post(client, "/ci/results", token, external_run_id="9912-1",
         commit_sha="ffffffffffffffffffffffffffffffffffffffff",
         scan_type="sast", payload=sarif())

    assert db.query(Finding).count() == 1


# --- results go through the readers that already exist -----------------------


def test_each_scan_type_uses_the_reader_it_already_had(client, integration, db):
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=sarif())
    post(client, "/ci/results", token, scan_type="sca", payload=PIP_AUDIT)
    post(client, "/ci/results", token, scan_type="secret", payload=GITLEAKS)

    sources = {f.source for f in db.query(Finding).all()}

    assert sources == {"bandit", "pip-audit", "gitleaks"}
    assert {r.kind for r in db.query(ScanRun).all()} == {"sast", "sca", "secret"}


def test_the_report_cannot_name_its_own_scanner(client, integration, db):
    """A report that could would file findings as bandit — and on the next run
    a real bandit scan would close them, because resolve is scoped by tool."""
    token = integration["token"]
    lying = json.loads(sarif())
    lying["runs"][0]["tool"]["driver"]["name"] = "gitleaks"

    post(client, "/ci/results", token, scan_type="sast", payload=json.dumps(lying))

    assert db.query(Finding).one().source == "bandit"


def test_a_secret_report_in_sarif_is_refused(client, integration, db):
    """Gitleaks can emit SARIF, and its SARIF carries the matched line in
    `snippet` — which the SARIF reader copies into evidence. The workflow also
    passes --redact, but a workflow is a file somebody can edit."""
    sarif_secret = json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{
                "ruleId": "github-pat",
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app/config.py"},
                    "region": {"startLine": 24,
                               "snippet": {"text": f'TOKEN = "{RAW_SECRET}"'}},
                }}],
            }],
        }],
    })

    post(client, "/ci/results", integration["token"],
         scan_type="secret", payload=sarif_secret)

    run = db.query(ScanRun).filter(ScanRun.kind == "secret").one()

    assert run.status == "failed"
    assert "SARIF" in run.error
    assert db.query(Finding).count() == 0


def test_an_unredacted_secret_report_still_stores_nothing(client, integration, db):
    """Second line of defence. The workflow redacts; if it did not, the parser
    does — and the value reaches no column, no log and no response."""
    token = integration["token"]

    response = post(client, "/ci/results", token, scan_type="secret", payload=GITLEAKS_RAW)

    assert RAW_SECRET not in response.text

    for finding in db.query(Finding).all():
        assert RAW_SECRET not in json.dumps({
            "e": finding.evidence, "t": finding.title,
            "d": finding.description, "x": finding.details,
        })

    from app.models import AuditLog

    for entry in db.query(AuditLog).all():
        assert RAW_SECRET not in (entry.detail or "")

    client.become(integration["owner"])
    assert RAW_SECRET not in client.get("/findings").text


def test_a_scanner_that_could_not_run_is_recorded_as_such(client, integration, db):
    """Not as an empty, clean-looking result. An empty report from a scanner
    that never started reads exactly like a repository with nothing wrong."""
    post(client, "/ci/results", integration["token"],
         scan_type="secret", succeeded=False, payload="")

    run = db.query(ScanRun).filter(ScanRun.kind == "secret").one()

    assert run.status == "scanner_unavailable"
    assert db.query(Finding).count() == 0


def test_a_scanner_only_resolves_its_own_findings(client, integration, db):
    """SAST must not close an SCA finding by not mentioning it. The scope
    isolation already lives in _resolve_stale; this is the CI path proving it."""
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=sarif())
    post(client, "/ci/results", token, scan_type="sca", payload=PIP_AUDIT)
    assert db.query(Finding).count() == 2

    # A later run where bandit finds nothing at all.
    empty = json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Bandit"}}, "results": []}]})
    post(client, "/ci/results", token, external_run_id="9913-1",
         scan_type="sast", payload=empty)

    sca = db.query(Finding).filter(Finding.source == "pip-audit").one()

    assert sca.status == "open"


def test_a_fixed_finding_reopens_when_it_comes_back(client, integration, db):
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=sarif())
    # Gone: same file, so the directory is still covered.
    gone = json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Bandit"}},
        "results": [json.loads(sarif(rule="B105", line=9))["runs"][0]["results"][0]],
    }]})
    post(client, "/ci/results", token, external_run_id="9914-1",
         scan_type="sast", payload=gone)

    first = db.query(Finding).filter(Finding.source_ref == "B608").one()
    assert first.status == "fixed"

    post(client, "/ci/results", token, external_run_id="9915-1",
         scan_type="sast", payload=sarif())
    db.refresh(first)

    assert first.status == "open"
    assert first.due_date


# --- the gate ----------------------------------------------------------------


def test_a_missing_required_scan_is_incomplete_not_a_pass(client, integration):
    """The answer that makes the other two mean anything. A gate reporting
    PASSED when the secret scanner never ran is a green light for a check that
    did not happen."""
    token = integration["token"]

    body = post(client, "/ci/results", token, scan_type="sast", payload=sarif()).json()

    assert body["security_gate"] == GATE_INCOMPLETE
    assert set(body["missing_scans"]) == {"sca", "secret"}

    post(client, "/ci/results", token, scan_type="sca", payload=PIP_AUDIT)
    body = post(client, "/ci/results", token, scan_type="secret", payload=GITLEAKS).json()

    assert body["security_gate"] == GATE_PASSED


def test_a_scanner_that_did_not_run_keeps_the_gate_incomplete(client, integration):
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=sarif())
    post(client, "/ci/results", token, scan_type="sca", payload=PIP_AUDIT)
    body = post(client, "/ci/results", token,
                scan_type="secret", succeeded=False, payload="").json()

    assert body["security_gate"] == GATE_INCOMPLETE
    assert "SECRET" in body["gate_reason"]


def test_an_open_critical_finding_fails_the_gate(client, integration):
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=CRITICAL_SARIF)
    post(client, "/ci/results", token, scan_type="sca", payload=PIP_AUDIT)
    body = post(client, "/ci/results", token, scan_type="secret", payload=GITLEAKS).json()

    assert body["security_gate"] == GATE_FAILED
    assert body["blocking"] == 1
    assert "kritik" in body["gate_reason"]


def test_an_accepted_risk_does_not_fail_the_gate(client, integration, db):
    """Someone argued for it with a second factor and an expiry. A gate that
    overrules that is a gate people switch off, and a gate that is off is not
    a stricter policy — it is no policy."""
    from datetime import date, timedelta

    token = integration["token"]
    post(client, "/ci/results", token, scan_type="sast", payload=CRITICAL_SARIF)

    client.become(integration["owner"], amr=["pwd", "mfa"])
    finding = client.get("/findings").json()[0]
    accepted = client.put(f"/findings/{finding['id']}", json={
        **{k: finding[k] for k in ("title", "description", "asset", "severity")},
        "status": "accepted_risk",
        "accepted_reason": "Bu kod yolu üretimde çağrılmıyor, kaldırılıyor.",
        "accepted_until": str(date.today() + timedelta(days=30)),
    })
    assert accepted.status_code == 200, accepted.text
    client.logout()

    post(client, "/ci/results", token, external_run_id="9920-1",
         scan_type="sast", payload=CRITICAL_SARIF)
    post(client, "/ci/results", token, external_run_id="9920-1",
         scan_type="sca", payload=PIP_AUDIT)
    body = post(client, "/ci/results", token, external_run_id="9920-1",
                scan_type="secret", payload=GITLEAKS).json()

    assert body["blocking"] == 0
    assert body["security_gate"] == GATE_PASSED


def test_the_gate_can_be_read_back_but_the_findings_cannot(client, integration):
    token = integration["token"]
    post(client, "/ci/results", token, scan_type="sast", payload=sarif())

    read = client.get(
        f"/ci/gate?repository={REPO}&external_run_id={RUN}",
        headers={"X-SecureTask-Token": token},
    )

    assert read.status_code == 200
    assert read.json()["security_gate"] == GATE_INCOMPLETE
    # Nothing about what was found.
    assert "title" not in read.text and "asset" not in read.text

    other = client.get(
        f"/ci/gate?repository=someone/else&external_run_id={RUN}",
        headers={"X-SecureTask-Token": token},
    )
    assert other.status_code == 403


# --- the contract the interface depends on -----------------------------------


def test_registering_returns_the_token_in_the_body(client, db):
    """The endpoint the "Jeton üret" button calls, with the values a person
    actually types.

    Pinned as a contract because the interface has exactly one chance to read
    this token: there is no second call that can fetch it, so a response the
    caller cannot read is a token that is gone.
    """
    from app import scanner

    client.login_as("alice")
    original = dict(scanner.DAST_TARGETS)
    scanner.DAST_TARGETS.clear()
    scanner.DAST_TARGETS["securetask-test"] = "http://127.0.0.1:8010"

    try:
        response = client.post("/ci/integrations", json={
            "repository": "Sevvalgungorr/SecureTask",
            "project": "securetask",
            "dast_target": "securetask-test",
        })
    finally:
        scanner.DAST_TARGETS.clear()
        scanner.DAST_TARGETS.update(original)

    assert response.status_code == 201, response.text

    body = response.json()

    assert body["repository"] == "Sevvalgungorr/SecureTask"
    assert body["project"] == "securetask"
    assert body["dast_target"] == "securetask-test"
    assert body["token"].startswith(ci.TOKEN_PREFIX)
    # And the row holds the digest, not the value.
    assert db.query(CiIntegration).one().token_hash == ci.hash_token(body["token"])


def test_the_client_reads_a_body_from_any_successful_response(client):
    """A regression guard for a real bug, in the layer that had it.

    `api()` used to return the parsed body only for HTTP 200 and `null` for
    every other success. That was invisible until the first endpoint answering
    201 arrived — registering a repository — and the caller then read `.token`
    off `null`. The frontend has no test runner, so the guard is here: the
    pattern that confused a status code with the presence of a body must not
    come back.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "app" / "static" / "app.js").read_text(
        encoding="utf-8"
    )

    assert "res.status === 200 ? res.json() : null" not in source
    # And it still declines to invent a body where there is none.
    assert "res.status === 204" in source
