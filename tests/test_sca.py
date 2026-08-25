"""Auditing the dependencies, and what that must not turn into.

The application's own code is one attack surface. The code it installs is the
other, and usually the larger one — so this reads the manifest and asks what is
known about each pinned version.

The dangerous version of this feature is the obvious one: resolve the
dependency graph, which downloads source distributions and runs `setup.py` from
every package in the tree. An audit that executes what it is auditing is not an
audit. Most of what is tested here is that refusal, and the fact that a clean
re-scan can close a finding *because the package was checked*, not because it
stopped being mentioned.
"""
import json
from datetime import date, timedelta

import pytest

from app import config, scanner
import app.main as main_module
from app.models import Finding, ScanRun


def audit_json(*deps) -> str:
    """A pip-audit report. Each dep is (name, version, [(id, [fixes], [aliases])])."""
    return json.dumps({
        "dependencies": [
            {
                "name": name,
                "version": version,
                "vulns": [
                    {
                        "id": vid,
                        "fix_versions": fixes,
                        "aliases": aliases,
                        "description": "Bir açık.",
                    }
                    for vid, fixes, aliases in vulns
                ],
            }
            for name, version, vulns in deps
        ],
        "fixes": [],
    })


REPORT = audit_json(
    ("requests", "2.19.1", [("PYSEC-2018-28", ["2.20.0"], ["CVE-2018-18074"])]),
    ("sqlalchemy", "2.0.51", []),
)


@pytest.fixture()
def project(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text(
        "# a comment\n"
        "requests==2.19.1\n"
        "sqlalchemy==2.0.51\n"
        "Authlib>=1.6\n"          # not pinned: cannot be audited without resolving
        "-r other.txt\n"          # an option line, not a requirement
        "\n"
    )
    monkeypatch.setattr(config, "SCAN_PROJECTS", {"demo": str(tmp_path)})
    monkeypatch.setattr(scanner, "SCAN_PROJECTS", {"demo": str(tmp_path)})
    return tmp_path


@pytest.fixture()
def auditor(monkeypatch, project):
    """A stand-in for pip-audit. Records the call, returns what it is told."""
    state = {"report": REPORT, "raise": None, "calls": 0, "note": ""}

    def fake_run(proj, scanner_key="pip-audit"):
        state["calls"] += 1
        state["project"] = proj
        if state["raise"]:
            raise state["raise"]
        return scanner.ScanResult(scanner_key, proj, state["report"], 0.1, state["note"])

    monkeypatch.setattr(main_module.scanner, "run", fake_run)
    return state


def _wait(client, scan_id, tries=60):
    import time

    for _ in range(tries):
        body = client.get(f"/scan/{scan_id}").json()
        if body["status"] in ("completed", "failed", "scanner_unavailable"):
            return body
        time.sleep(0.05)

    raise AssertionError("tarama bitmedi")


def _scan(client, project="demo"):
    started = client.post(f"/scan?project={project}&scanner_key=pip-audit")
    assert started.status_code == 200, started.text
    return _wait(client, started.json()["id"])


# --- what may be audited -----------------------------------------------------


def test_only_a_registered_project_can_be_audited(client, auditor):
    """The request names a project. There is no path in it to traverse, which
    is a stronger position than validating one."""
    client.login_as("alice")

    for attack in ("../../etc", "/etc", "demo/../..", "unknown", "~/.ssh"):
        response = client.post(f"/scan?project={attack}&scanner_key=pip-audit")
        assert response.status_code == 404

    assert auditor["calls"] == 0


def test_there_is_no_way_to_name_a_manifest(client, project):
    """The filenames are a fixed tuple in the module, not a parameter.

    A `path` or `requirements_file` field would be an arbitrary file read with
    a feature's name on it — the endpoint would happily audit /etc/passwd's
    "dependencies" and report what it could not parse.
    """
    import inspect

    signature = inspect.signature(main_module.start_scan)

    assert set(signature.parameters) == {
        "project", "scanner_key", "team_id", "user", "db",
    }
    assert scanner.MANIFESTS == ("requirements.txt", "requirements-dev.txt")


def test_the_audit_does_not_resolve_the_dependency_graph(project):
    """The two flags that keep this from executing the code it audits.

    Without `--no-deps` pip-audit resolves transitive dependencies, and
    resolution downloads and builds source distributions — which runs
    `setup.py` from every package in the tree.
    """
    args = scanner.SCANNERS["pip-audit"]["args"]("/tmp/manifest.txt")

    assert isinstance(args, list)
    assert all(isinstance(a, str) for a in args)
    assert "--no-deps" in args
    assert "--disable-pip" in args
    # And it never offers to change anything in the project it is auditing.
    assert "--fix" not in args


def test_only_pinned_requirements_are_audited_and_the_rest_are_counted(project):
    """`>=` cannot be audited without resolving it, and resolving is refused.

    So it is skipped — and *said*, because "no vulnerabilities" read against a
    list the operator thinks is longer than it is, is worse than an error.
    """
    text, count, dropped = scanner._pinned_manifest(project)

    assert count == 2
    assert dropped == 1                       # Authlib>=1.6
    assert "requests==2.19.1" in text
    assert "Authlib" not in text
    # Comments and pip's own option lines are not requirements and are not
    # counted as skipped ones.
    assert "other.txt" not in text


def test_a_project_with_nothing_pinned_is_refused_not_reported_as_clean(
    tmp_path, monkeypatch
):
    (tmp_path / "requirements.txt").write_text("Authlib>=1.6\n")
    monkeypatch.setattr(scanner, "SCAN_PROJECTS", {"loose": str(tmp_path)})

    with pytest.raises(scanner.ScanRefused):
        scanner.run("loose", "pip-audit")


def test_the_run_says_how_much_it_skipped(client, auditor):
    client.login_as("alice")
    auditor["note"] = "1 bağımlılık satırı sabit sürüm belirtmediği için denetlenmedi"

    body = _scan(client)

    assert body["status"] == "completed"
    assert "denetlenmedi" in body["note"]


# --- scanner availability ----------------------------------------------------


def test_a_missing_scanner_is_its_own_outcome_not_a_failure(client, auditor):
    """"pip-audit is not installed" is fixable in a minute. Filing it as a
    failure sends the operator looking for a broken scan instead."""
    client.login_as("alice")
    auditor["raise"] = scanner.ScannerMissing("pip-audit bu makinede kurulu değil.")

    body = _scan(client)

    assert body["status"] == "scanner_unavailable"
    assert "kurulu değil" in body["error"]
    # And nothing was invented to fill the page.
    assert body["total"] == 0
    assert client.get("/findings").json() == []


def test_a_scanner_that_ran_and_broke_is_still_a_failure(client, auditor):
    client.login_as("alice")
    auditor["raise"] = scanner.ScanFailed("pip-audit hata verdi (2): boom")

    assert _scan(client)["status"] == "failed"


# --- findings ----------------------------------------------------------------


def test_a_vulnerability_becomes_an_ordinary_finding(client, auditor):
    """No second store. It goes through the same importer, so it gets an SLA,
    a risk cell, an audit line and everything else for free."""
    client.login_as("alice")

    body = _scan(client)
    assert body["created"] == 1

    finding = client.get("/findings").json()[0]

    assert finding["source"] == "pip-audit"
    assert finding["asset"] == "requests"          # the package is the asset
    assert finding["source_ref"] == "PYSEC-2018-28"
    assert "CVE-2018-18074" in finding["title"]
    assert finding["due_date"]                     # an SLA, like anything else


def test_the_detail_carries_what_the_scanner_actually_said(client, auditor):
    client.login_as("alice")
    _scan(client)

    details = client.get("/findings").json()[0]["details"]

    assert details["package"] == "requests"
    assert details["installed_version"] == "2.19.1"
    assert details["fixed_versions"] == ["2.20.0"]
    assert details["cve"] == "CVE-2018-18074"


def test_the_severity_is_marked_as_ours_because_pip_audit_has_none(client, auditor):
    """pip-audit reports no severity — the JSON has no field for it, on either
    service. Presenting a default as the scanner's rating would be inventing
    the one number the whole remediation window hangs off."""
    client.login_as("alice")
    _scan(client)

    finding = client.get("/findings").json()[0]

    assert finding["details"]["severity_source"] == "securetask-default"
    assert "SecureTask varsayılanı" in finding["description"]


# --- the lifecycle -----------------------------------------------------------


def test_the_same_vulnerability_does_not_pile_up(client, auditor):
    client.login_as("alice")

    first = _scan(client)
    second = _scan(client)

    assert first["created"] == 1
    assert second["created"] == 0
    assert second["unchanged"] == 1
    assert len(client.get("/findings").json()) == 1


def test_a_patched_dependency_closes_because_the_package_was_checked(client, auditor):
    """The point of reading pip-audit's coverage rather than guessing it.

    After the upgrade the package has no vulnerabilities, so it produces no
    results — and a heuristic that infers "what was examined" from the results
    would see nothing and close nothing. pip-audit lists every package it
    looked at, including the clean ones, so this closes correctly.
    """
    client.login_as("alice")
    _scan(client)

    auditor["report"] = audit_json(
        ("requests", "2.32.0", []),               # upgraded, and now clean
        ("sqlalchemy", "2.0.51", []),
    )
    body = _scan(client)

    assert body["resolved"] == 1
    assert client.get("/findings").json()[0]["status"] == "fixed"


def test_a_vulnerability_that_comes_back_reopens_with_a_fresh_window(client, auditor):
    """Someone downgrades, or a pin is reverted. The evidence says it is not
    fixed, so the finding is not fixed — and it gets a new deadline rather than
    landing already overdue."""
    client.login_as("alice")
    _scan(client)

    auditor["report"] = audit_json(("requests", "2.32.0", []), ("sqlalchemy", "2.0.51", []))
    _scan(client)
    assert client.get("/findings").json()[0]["status"] == "fixed"

    auditor["report"] = REPORT
    body = _scan(client)

    assert body["reopened"] == 1
    finding = client.get("/findings").json()[0]
    assert finding["status"] == "open"
    assert finding["due_date"]


def test_an_accepted_risk_survives_a_clean_re_scan(client, auditor):
    """Someone argued for living with it, with a second factor and an expiry.
    A scanner no longer mentioning the package is not an argument against
    that, and a re-scan must not quietly undo the decision."""
    client.login_as("alice", amr=["pwd", "mfa"])
    _scan(client)

    finding = client.get("/findings").json()[0]
    accepted = client.put(f"/findings/{finding['id']}", json={
        **{k: finding[k] for k in ("title", "description", "asset", "severity")},
        "status": "accepted_risk",
        "accepted_reason": "Bu paketin o kod yolu kullanılmıyor, sürüm sabit.",
        "accepted_until": str(date.today() + timedelta(days=60)),
    })
    assert accepted.status_code == 200, accepted.text

    auditor["report"] = audit_json(("requests", "2.32.0", []), ("sqlalchemy", "2.0.51", []))
    body = _scan(client)

    assert body["resolved"] == 0
    assert client.get("/findings").json()[0]["status"] == "accepted_risk"


# --- who sees what -----------------------------------------------------------


def test_another_account_sees_neither_the_run_nor_the_finding(client, auditor, db):
    client.login_as("alice")
    started = client.post("/scan?project=demo&scanner_key=pip-audit").json()
    _wait(client, started["id"])

    client.login_as("bob")

    assert client.get(f"/scan/{started['id']}").status_code == 404
    assert client.get("/scan").json() == []
    assert client.get("/findings").json() == []
    # The rows exist; they are alice's.
    assert db.query(ScanRun).count() == 1
    assert db.query(Finding).count() == 1
