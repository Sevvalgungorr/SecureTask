"""The release half: deployment, post-deploy scanning, and refusing to round up.

A deployment succeeding says the artefact runs. A security gate passing says
the source looked clean before it was built. Neither says the running system
was checked — and the failure this half exists to prevent is the one where all
three get collapsed into a green tick.

The other thing tested here is what is *not* built. SecureTask does not deploy.
There is no host, no key, no artefact and no command anywhere in this path, and
a few of these tests exist only to say so in a way that fails if it stops being
true.
"""
import json
import time

import pytest

from app import config, scanner
import app.main as main_module
from app.models import (
    RELEASE_INCOMPLETE,
    RELEASE_NOT_READY,
    RELEASE_READY,
    PipelineRun,
    ScanRun,
)
from tests.test_ci import (
    CRITICAL_SARIF,
    GITLEAKS,
    PIP_AUDIT,
    REPO,
    RUN,
    ctx,
    post,
    sarif,
)

NUCLEI_CLEAN = ""
NUCLEI_CRITICAL = json.dumps({
    "template-id": "exposed-admin-panel",
    "host": "staging.example.test",
    "matched-at": "http://staging.example.test/admin",
    "info": {"name": "Kimlik doğrulaması olmayan yönetim paneli",
             "severity": "critical", "description": "..."},
})


@pytest.fixture()
def integration(client, db, monkeypatch):
    """A repository registered with a DAST target that exists on the server."""
    monkeypatch.setattr(
        scanner, "DAST_TARGETS", {"securetask-staging": "http://staging.example.test"}
    )
    monkeypatch.setattr(
        config, "DAST_TARGETS", {"securetask-staging": "http://staging.example.test"}
    )
    owner = client.login_as("alice")
    created = client.post("/ci/integrations", json={
        "repository": REPO, "project": "securetask",
        "dast_target": "securetask-staging",
    })
    assert created.status_code == 201, created.text
    body = created.json()
    body["owner"] = owner
    client.logout()
    return body


@pytest.fixture()
def nuclei(monkeypatch):
    """A stand-in for the DAST scanner. Records the call."""
    state = {"output": NUCLEI_CLEAN, "raise": None, "calls": 0, "argv": []}

    def fake_run(project, scanner_key="nuclei"):
        state["calls"] += 1
        state["project"] = project
        if state["raise"]:
            raise state["raise"]
        return scanner.ScanResult(scanner_key, project, state["output"], 0.2)

    monkeypatch.setattr(main_module.scanner, "run", fake_run)
    return state


def pass_the_gate(client, token, run_id=RUN):
    """Report all three required scans, cleanly."""
    post(client, "/ci/results", token, external_run_id=run_id,
         scan_type="sast", payload=sarif())
    post(client, "/ci/results", token, external_run_id=run_id,
         scan_type="sca", payload=PIP_AUDIT)
    return post(client, "/ci/results", token, external_run_id=run_id,
                scan_type="secret", payload=GITLEAKS).json()


def wait_dast(db, tries=150):
    """Wait for the scan AND for the pipeline to have been told about it.

    The scan thread sets its own row and then recomputes the pipeline, so a
    wait that stops at the first is a race: the release status would still be
    whatever it was when the scan was queued. Waiting for the pipeline to agree
    is waiting for the thing the test is actually about.
    """
    final = ("completed", "failed", "scanner_unavailable")

    for _ in range(tries):
        row = (
            db.query(ScanRun)
            .filter(ScanRun.kind == scanner.DAST)
            .order_by(ScanRun.id.desc())
            .first()
        )

        if row is not None:
            db.refresh(row)

            if row.status in final and row.pipeline_id:
                parent = (
                    db.query(PipelineRun)
                    .filter(PipelineRun.id == row.pipeline_id)
                    .one()
                )
                db.refresh(parent)

                if parent.dast_status == row.status:
                    return row

        time.sleep(0.05)

    raise AssertionError("DAST bitmedi")


def pipeline(db, run_id=RUN):
    row = db.query(PipelineRun).filter(PipelineRun.external_run_id == run_id).one()
    db.refresh(row)
    return row


# --- deployment is a report, not an instruction ------------------------------


def test_a_deployment_is_recorded_through_its_three_states(client, integration, db):
    token = integration["token"]
    pass_the_gate(client, token)

    for state in ("started", "succeeded"):
        body = post(client, "/ci/deployments", token, state=state).json()
        assert body["release_status"] in (RELEASE_INCOMPLETE, RELEASE_READY)

    row = pipeline(db)

    assert row.deployment_status == "succeeded"
    assert row.environment == "staging"
    assert row.deployed_at is not None


def test_a_failed_deployment_is_not_ready_whatever_the_gate_said(
    client, integration, db
):
    token = integration["token"]
    assert pass_the_gate(client, token)["security_gate"] == "passed"

    body = post(client, "/ci/deployments", token, state="failed").json()

    assert body["release_status"] == RELEASE_NOT_READY
    assert "dağıtım" in body["release_reason"].lower()


def test_nothing_in_the_deployment_path_starts_a_process(client, integration, db, monkeypatch):
    """The clearest way to say "this application does not deploy": if anything
    in this path ran a command, this fails."""
    import subprocess

    def refuse(*args, **kwargs):
        raise AssertionError("bir süreç başlatıldı")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)

    token = integration["token"]
    pass_the_gate(client, token)

    assert post(client, "/ci/deployments", token, state="started").status_code == 200
    assert post(client, "/ci/deployments", token, state="succeeded").status_code == 200


def test_the_deployment_model_carries_nothing_to_deploy_with(client):
    """No host, no credential, no artefact, no command. Absent by design rather
    than validated: a field that exists is a field somebody will fill."""
    from app.schemas import CiDeployment

    fields = set(CiDeployment.model_fields)

    assert not fields & {
        "host", "url", "target", "ssh_key", "credential", "token", "command",
        "script", "artifact", "image", "kubeconfig", "region",
    }


def test_production_is_not_an_environment_a_machine_can_name(client, integration):
    """Shipping to production is a decision someone writes deliberately, not
    one a pipeline picks from a list."""
    token = integration["token"]
    pass_the_gate(client, token)

    response = client.post(
        "/ci/deployments",
        json=ctx(state="succeeded", environment="production"),
        headers={"X-SecureTask-Token": token},
    )

    assert response.status_code == 422


# --- post-deployment DAST ----------------------------------------------------


def test_the_pipeline_cannot_send_a_url(client, integration, nuclei, db):
    """The address is not in the request and cannot be. The integration names a
    registered target; the URL is resolved from DAST_TARGETS on the server."""
    from app.schemas import CiDastRequest

    assert not set(CiDastRequest.model_fields) & {"url", "host", "target", "address"}

    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")

    # Even smuggled in, an extra field is not read: pydantic drops it and the
    # scanner is still called with the registered target name.
    client.post(
        "/ci/dast",
        json={**ctx(), "url": "http://169.254.169.254/latest/meta-data/"},
        headers={"X-SecureTask-Token": token},
    )
    wait_dast(db)

    assert nuclei["project"] == "securetask-staging"


def test_dast_is_refused_before_a_successful_deployment(client, integration, nuclei):
    """Scanning a staging system that was not updated produces a result about
    the previous release, and attaching it to this commit would be a false
    statement about this commit."""
    token = integration["token"]
    pass_the_gate(client, token)

    refused = client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})

    assert refused.status_code == 409
    assert nuclei["calls"] == 0

    post(client, "/ci/deployments", token, state="failed")
    assert client.post("/ci/dast", json=ctx(),
                       headers={"X-SecureTask-Token": token}).status_code == 409
    assert nuclei["calls"] == 0


def test_an_integration_without_a_registered_target_cannot_scan(
    client, db, monkeypatch, nuclei
):
    monkeypatch.setattr(scanner, "DAST_TARGETS", {"other": "http://other.test"})
    client.login_as("alice")
    created = client.post("/ci/integrations", json={"repository": REPO}).json()
    client.logout()
    token = created["token"]

    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")

    response = client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})

    assert response.status_code == 409
    assert nuclei["calls"] == 0


def test_a_dast_target_must_exist_when_the_integration_is_registered(
    client, monkeypatch
):
    monkeypatch.setattr(scanner, "DAST_TARGETS", {"known": "http://known.test"})
    client.login_as("alice")

    refused = client.post("/ci/integrations", json={
        "repository": "someone/other", "dast_target": "http://evil.test",
    })

    assert refused.status_code == 422


# --- release status ----------------------------------------------------------


def test_a_failed_gate_is_never_ready(client, integration, db):
    token = integration["token"]

    post(client, "/ci/results", token, scan_type="sast", payload=CRITICAL_SARIF)
    post(client, "/ci/results", token, scan_type="sca", payload=PIP_AUDIT)
    body = post(client, "/ci/results", token, scan_type="secret", payload=GITLEAKS).json()

    assert body["security_gate"] == "failed"
    assert body["release_status"] == RELEASE_NOT_READY

    # And a successful deployment does not upgrade it.
    body = post(client, "/ci/deployments", token, state="succeeded").json()
    assert body["release_status"] == RELEASE_NOT_READY


def test_an_incomplete_gate_is_incomplete_not_not_ready(client, integration):
    """Not knowing is a different answer from knowing it is bad, and reporting
    the harsher one teaches people to ignore it."""
    token = integration["token"]

    body = post(client, "/ci/results", token, scan_type="sast", payload=sarif()).json()

    assert body["release_status"] == RELEASE_INCOMPLETE


def test_a_missing_dast_leaves_the_release_incomplete(client, integration):
    token = integration["token"]
    pass_the_gate(client, token)
    body = post(client, "/ci/deployments", token, state="succeeded").json()

    assert body["release_status"] == RELEASE_INCOMPLETE
    assert "DAST" in body["release_reason"]


def test_an_uninstalled_scanner_is_incomplete_never_a_pass(
    client, integration, nuclei, db
):
    """The whole point of the third state. A missing scanner is not a clean
    result, and showing one would be inventing a check that never ran."""
    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")
    nuclei["raise"] = scanner.ScannerMissing("Nuclei bu makinede kurulu değil.")

    client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})
    wait_dast(db)
    row = pipeline(db)

    assert row.dast_status == "scanner_unavailable"
    assert row.release_status == RELEASE_INCOMPLETE
    assert "kurulu değil" in row.release_reason


def test_a_critical_dast_finding_makes_the_release_not_ready(
    client, integration, nuclei, db
):
    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")
    nuclei["output"] = NUCLEI_CRITICAL

    client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})
    wait_dast(db)
    row = pipeline(db)

    assert row.dast_status == "completed"
    assert row.release_status == RELEASE_NOT_READY
    assert "DAST" in row.release_reason


def test_everything_passing_is_the_only_way_to_ready(client, integration, nuclei, db):
    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")

    client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})
    wait_dast(db)
    row = pipeline(db)

    assert row.security_gate == "passed"
    assert row.deployment_status == "succeeded"
    assert row.dast_status == "completed"
    assert row.release_status == RELEASE_READY


def test_dast_findings_are_ordinary_findings(client, integration, nuclei, db):
    """No separate store for the post-deployment half either."""
    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")
    nuclei["output"] = NUCLEI_CRITICAL

    client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})
    wait_dast(db)

    client.become(integration["owner"])
    found = [f for f in client.get("/findings").json() if f["source"] == "nuclei"]

    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["due_date"]


def test_asking_for_dast_twice_does_not_scan_twice(client, integration, nuclei, db):
    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")

    client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})
    wait_dast(db)
    client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})

    assert nuclei["calls"] == 1
    assert db.query(ScanRun).filter(ScanRun.kind == scanner.DAST).count() == 1


# --- what a person sees ------------------------------------------------------


def test_a_pipeline_is_visible_to_its_owner_and_nobody_else(
    client, integration, nuclei, db
):
    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")

    client.become(integration["owner"])
    listed = client.get("/pipelines").json()

    assert len(listed) == 1
    assert listed[0]["repository"] == REPO
    assert {s["kind"] for s in listed[0]["scans"]} == {"sast", "sca", "secret"}

    detail = client.get(f"/pipelines/{listed[0]['id']}")
    assert detail.status_code == 200

    client.login_as("bob")
    assert client.get("/pipelines").json() == []
    assert client.get(f"/pipelines/{listed[0]['id']}").status_code == 404


def test_the_audit_log_records_the_pipeline_without_the_token(
    client, integration, nuclei, db
):
    from app.models import AuditLog

    token = integration["token"]
    pass_the_gate(client, token)
    post(client, "/ci/deployments", token, state="succeeded")
    client.post("/ci/dast", json=ctx(), headers={"X-SecureTask-Token": token})
    wait_dast(db)

    actions = {e.action for e in db.query(AuditLog).all()}

    assert "pipeline_started" in actions
    assert "ci_completed" in actions
    assert "deploy_succeeded" in actions
    assert "dast_completed" in actions
    assert actions & {"gate_passed", "gate_incomplete", "gate_failed"}

    for entry in db.query(AuditLog).all():
        assert token not in (entry.detail or "")
