"""Running an analyser here, and the things that must not follow from it.

This is the only place the application starts a process, so most of what
matters is what it refuses: a directory nobody registered, a command line
assembled from input, a second run racing the first.

The analyser itself is stubbed. What needs proving is the boundary and the
bookkeeping — that a scan's results go through the *existing* importer with the
existing rules, and that a failed run leaves a row saying so.
"""
import json

import pytest

from app import config, scanner
import app.main as main_module
from app.models import Finding, ScanRun

SARIF = json.dumps({
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Bandit"}},
        "results": [{
            "ruleId": "B608",
            "level": "warning",
            "message": {"text": "Possible SQL injection"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/reports.py"},
                "region": {"startLine": 24, "snippet": {"text": "query = f'...'"}},
            }}],
        }],
    }],
})


@pytest.fixture()
def project(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "reports.py").write_text("x = 1\n")
    monkeypatch.setattr(config, "SCAN_PROJECTS", {"demo": str(tmp_path)})
    monkeypatch.setattr(scanner, "SCAN_PROJECTS", {"demo": str(tmp_path)})
    return tmp_path


@pytest.fixture()
def analyser(monkeypatch, project):
    """A stand-in for bandit. Records the call, returns what it is told."""
    state = {"sarif": SARIF, "raise": None, "calls": 0}

    def fake_run(proj, scanner_key="bandit"):
        state["calls"] += 1
        state["project"] = proj
        if state["raise"]:
            raise state["raise"]
        return scanner.ScanResult(scanner_key, proj, state["sarif"], 0.1)

    monkeypatch.setattr(main_module.scanner, "run", fake_run)
    return state


def _wait(client, scan_id, tries=60):
    """The scan runs on its own thread; poll until it settles."""
    import time

    for _ in range(tries):
        body = client.get(f"/scan/{scan_id}").json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.05)

    raise AssertionError("tarama bitmedi")


# --- what may be scanned -----------------------------------------------------


def test_only_a_registered_project_can_be_scanned(client, analyser):
    """The request names a project. There is no path in it to traverse, which
    is a stronger position than validating one."""
    client.login_as("alice")

    for attack in ("../../etc", "/etc", "demo/../..", "unknown"):
        assert client.post(f"/scan?project={attack}").status_code == 404

    assert analyser["calls"] == 0


def test_nothing_is_scannable_when_nothing_is_registered(client, monkeypatch):
    monkeypatch.setattr(scanner, "SCAN_PROJECTS", {})

    with pytest.raises(scanner.ScanRefused):
        scanner.run("demo")


def test_an_unknown_scanner_is_refused(client, project):
    with pytest.raises(scanner.ScanRefused):
        scanner.run("demo", "definitely-not-a-scanner")


def test_the_command_is_a_list_never_a_string(client, project):
    """No shell means quoting and metacharacters are not concepts that apply.
    A string here would reintroduce every one of them."""
    args = scanner.SCANNERS["bandit"]["args"](project)

    assert isinstance(args, list)
    assert all(isinstance(a, str) for a in args)
    # And the path handed to the analyser is relative, so the server's
    # filesystem layout does not end up in every finding's asset name.
    assert "-r" in args and args[args.index("-r") + 1] == "."


def test_a_missing_analyser_says_so_rather_than_failing_obscurely(client, project, monkeypatch):
    monkeypatch.setattr(scanner, "find_binary", lambda name: None)

    with pytest.raises(scanner.ScanRefused) as exc:
        scanner.run("demo")

    assert "kurulu değil" in str(exc.value)


# --- results go through the existing importer --------------------------------


def test_results_become_ordinary_findings(client, analyser):
    """No second finding store. Whatever a scan produces is subject to the same
    rules as an uploaded report, because the rules are about what a report may
    do to a decision — not about who wrote it."""
    client.login_as("alice")
    scan = client.post("/scan?project=demo").json()

    body = _wait(client, scan["id"])

    assert body["status"] == "completed"
    assert body["created"] == 1
    finding = client.get("/findings").json()[0]
    assert finding["source"] == "bandit"
    assert finding["source_ref"] == "B608"
    assert finding["asset"] == "app/reports.py"
    # And it arrives with everything an uploaded finding has, so the code
    # viewer, the AI analysis and the SLA all work on it unchanged.
    assert finding["evidence"] and finding["due_date"]


def test_a_second_scan_does_not_duplicate(client, analyser):
    """Existing deduplication, not a new one: same owner, same file, same rule."""
    client.login_as("alice")
    _wait(client, client.post("/scan?project=demo").json()["id"])
    second = _wait(client, client.post("/scan?project=demo").json()["id"])

    assert second["created"] == 0
    assert second["unchanged"] == 1
    assert len(client.get("/findings").json()) == 1


def test_a_scan_cannot_overwrite_an_accepted_risk(client, analyser):
    """The rule the importers already hold. A scan run from inside the
    application is still a scan."""
    from datetime import date, timedelta

    client.login_as("alice", amr=["otp"])
    _wait(client, client.post("/scan?project=demo").json()["id"])
    finding = client.get("/findings").json()[0]
    client.put(f"/findings/{finding['id']}", json={
        **{k: finding[k] for k in
           ("title", "description", "asset", "severity", "team_id", "due_date")},
        "status": "accepted_risk",
        "accepted_reason": "Sağlayıcı yaması çıkana kadar sınırlandırıldı",
        "accepted_until": str(date.today() + timedelta(days=30)),
    })

    _wait(client, client.post("/scan?project=demo").json()["id"])

    assert client.get(f"/findings/{finding['id']}").json()["status"] == "accepted_risk"


# --- when it goes wrong ------------------------------------------------------


def test_a_failed_scan_leaves_a_row_saying_why(client, analyser):
    """A scan that leaves no trace is indistinguishable from one that was never
    started, and "I ran it and nothing happened" then has no answer."""
    client.login_as("alice")
    analyser["raise"] = scanner.ScanFailed("Bandit hata verdi (2): no such option")

    body = _wait(client, client.post("/scan?project=demo").json()["id"])

    assert body["status"] == "failed"
    assert "no such option" in body["error"]
    assert client.get("/findings").json() == []


def test_a_second_run_is_refused_while_one_is_going(client, analyser, monkeypatch):
    """Two analysers writing findings for one tree race the deduplication, and
    the second tells nobody anything the first will not."""
    import threading

    gate = threading.Event()

    def slow(proj, scanner_key="bandit"):
        gate.wait(timeout=5)
        return scanner.ScanResult(scanner_key, proj, SARIF, 0.1)

    monkeypatch.setattr(main_module.scanner, "run", slow)
    client.login_as("alice")
    first = client.post("/scan?project=demo").json()

    assert client.post("/scan?project=demo").status_code == 409

    gate.set()
    _wait(client, first["id"])


# --- who sees what -----------------------------------------------------------


def test_scans_are_scoped_to_who_ran_them(client, analyser):
    client.login_as("alice")
    scan = client.post("/scan?project=demo").json()
    _wait(client, scan["id"])
    client.logout()
    client.login_as("mallory")

    assert client.get("/scan").json() == []
    assert client.get(f"/scan/{scan['id']}").status_code == 404


def test_starting_a_scan_is_recorded(client, analyser):
    client.login_as("alice")
    scan = client.post("/scan?project=demo").json()

    entry = next(e for e in client.get("/audit/me").json() if e["action"] == "scanned")
    assert "demo" in entry["detail"] and "bandit" in entry["detail"]

    # Waited for on purpose: the scan runs on a daemon thread with its own
    # session, and the next test's fixture drops the schema. Leaving it in
    # flight means a thread writing to tables that no longer exist — which is
    # exactly the warning this test produced before the wait was added.
    _wait(client, scan["id"])


# --- NEW / EXISTING / RESOLVED ------------------------------------------------


def _sarif(*rules):
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Bandit"}},
            "results": [{
                "ruleId": rule,
                "level": "warning",
                "message": {"text": f"finding {rule}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f"app/{rule.lower()}.py"},
                    "region": {"startLine": 3, "snippet": {"text": "x = 1"}},
                }}],
            } for rule in rules],
        }],
    })


def test_a_rescan_splits_into_new_existing_and_resolved(client, analyser):
    """First run finds A, B, C; second finds B, C, D. D is new, B and C carry
    on, and A is closed because this scan covered the tree it lives in and did
    not report it."""
    client.login_as("alice")
    analyser["sarif"] = _sarif("B101", "B102", "B103")
    first = _wait(client, client.post("/scan?project=demo").json()["id"])

    assert (first["created"], first["unchanged"], first["resolved"]) == (3, 0, 0)

    analyser["sarif"] = _sarif("B102", "B103", "B104")
    second = _wait(client, client.post("/scan?project=demo").json()["id"])

    assert second["created"] == 1        # B104
    assert second["unchanged"] == 2      # B102, B103
    assert second["resolved"] == 1       # B101

    by_rule = {f["source_ref"]: f for f in client.get("/findings").json()}
    assert by_rule["B101"]["status"] == "fixed"
    assert by_rule["B102"]["status"] == "open"
    assert by_rule["B104"]["status"] == "open"


def test_resolving_does_not_touch_an_accepted_risk(client, analyser):
    """Someone argued for it, with a second factor and an expiry. A scanner not
    mentioning the file this time is not an argument against that."""
    from datetime import date, timedelta

    client.login_as("alice", amr=["otp"])
    analyser["sarif"] = _sarif("B101")
    _wait(client, client.post("/scan?project=demo").json()["id"])
    finding = client.get("/findings").json()[0]
    client.put(f"/findings/{finding['id']}", json={
        **{k: finding[k] for k in
           ("title", "description", "asset", "severity", "team_id", "due_date")},
        "status": "accepted_risk",
        "accepted_reason": "Sağlayıcı yaması çıkana kadar sınırlandırıldı",
        "accepted_until": str(date.today() + timedelta(days=30)),
    })

    analyser["sarif"] = _sarif("B102")
    run = _wait(client, client.post("/scan?project=demo").json()["id"])

    assert run["resolved"] == 0
    assert client.get(f"/findings/{finding['id']}").json()["status"] == "accepted_risk"


def test_only_the_tree_the_scan_covered_is_resolved(client, analyser, monkeypatch):
    """A bandit report uploaded from an unrelated repository must not be closed
    by a scan that never looked at it."""
    client.login_as("alice")
    client.post(
        "/import/sarif",
        content=json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Bandit"}},
                "results": [{
                    "ruleId": "B999",
                    "level": "warning",
                    "message": {"text": "elsewhere"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "otherrepo/thing.py"},
                        "region": {"startLine": 1, "snippet": {"text": "y = 2"}},
                    }}],
                }],
            }],
        }),
        headers={"content-type": "application/json"},
    )

    analyser["sarif"] = _sarif("B101")
    run = _wait(client, client.post("/scan?project=demo").json()["id"])

    assert run["resolved"] == 0
    outside = next(f for f in client.get("/findings").json() if f["source_ref"] == "B999")
    assert outside["status"] == "open"


def test_a_run_records_how_long_it_took(client, analyser):
    client.login_as("alice")

    run = _wait(client, client.post("/scan?project=demo").json()["id"])

    assert run["duration"] is not None and run["duration"] >= 0


def test_the_options_endpoint_reports_what_is_configured(client, analyser):
    """The dropdowns are empty when this says they should be, and never
    because a failure was swallowed."""
    client.login_as("alice")

    body = client.get("/scan/options").json()

    assert [p["name"] for p in body["projects"]] == ["demo"]
    assert body["projects"][0]["available"] is True
    # Not "the only scanner": DAST added a second one. What this test is about
    # is that the static analyser is offered and correctly labelled.
    bandit = next(s for s in body["scanners"] if s["key"] == "bandit")
    assert bandit["kind"] == "sast" and bandit["installed"] is True


def test_options_are_honest_when_nothing_is_configured(client, monkeypatch):
    monkeypatch.setattr(scanner, "SCAN_PROJECTS", {})
    client.login_as("alice")

    assert client.get("/scan/options").json()["projects"] == []
