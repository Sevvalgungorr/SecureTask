"""Finding credentials in source, and never holding one.

Every other scanner in this application reports *about* code. This one reports
code, and the code is a live credential — so the interesting question is not
whether it finds things. It is whether a real secret can be recovered from
anything this application produces afterwards: a row, a log line, an audit
entry, an API response, a model prompt, a screenshot of the code viewer.

The answer has to be no by construction rather than by care, and there are two
reasons it is:

1. **Gitleaks redacts before it writes.** The `--redact` flag replaces the
   value inside the scanner, so what arrives on stdout has never contained it.
2. **The parser masks what is left, and refuses a line it could not clean.**

Everything below the parser — the database, the audit log, the AI prompt, the
code viewer — is safe because it is never given the value, not because each of
them remembers to be careful. These tests take the paranoid position anyway and
push a *raw, un-redacted* report through the whole thing, then go looking for
the secret in every layer. That is the report a future gitleaks version, a
misconfigured flag, or an uploaded file could produce.
"""
import json

import pytest

from app import ai, config, importers, scanner
import app.main as main_module
from app.models import AuditLog, Finding, ScanRun

# A credential shaped like the real thing, and never a real one. If any
# assertion below finds this string somewhere it should not be, the feature is
# broken in the only way that matters.
RAW = "ghp_R7cQm2Vx9LpTz4Nb8KdWfY3JhS1AeG6UoP0i"

# What gitleaks writes when it is asked to redact — the value replaced inside
# the scanner, before the report exists.
REDACTED = json.dumps([{
    "RuleID": "github-pat",
    "Description": "Detected a GitHub Personal Access Token, ...",
    "StartLine": 24,
    "EndLine": 24,
    "Match": 'GITHUB_TOKEN = "REDACTED"',
    "Secret": "REDACTED",
    "File": "app/config.py",
    "Fingerprint": "app/config.py:github-pat:24",
}])

# The same finding with the flag off: the report a misconfiguration would
# produce. Nothing downstream may leak it either.
UNREDACTED = json.dumps([{
    "RuleID": "github-pat",
    "Description": "Detected a GitHub Personal Access Token, ...",
    "StartLine": 24,
    "EndLine": 24,
    "Match": f'GITHUB_TOKEN = "{RAW}"',
    "Secret": RAW,
    "File": "app/config.py",
    "Fingerprint": "app/config.py:github-pat:24",
}])


@pytest.fixture()
def project(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "config.py").write_text(f'GITHUB_TOKEN = "{RAW}"\n')
    monkeypatch.setattr(config, "SCAN_PROJECTS", {"demo": str(tmp_path)})
    monkeypatch.setattr(scanner, "SCAN_PROJECTS", {"demo": str(tmp_path)})
    return tmp_path


@pytest.fixture()
def leaks(monkeypatch, project):
    """A stand-in for gitleaks. Records the call, returns what it is told."""
    state = {"report": UNREDACTED, "raise": None, "calls": 0}

    def fake_run(proj, scanner_key="gitleaks"):
        state["calls"] += 1
        state["project"] = proj
        if state["raise"]:
            raise state["raise"]
        return scanner.ScanResult(scanner_key, proj, state["report"], 0.1)

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
    started = client.post(f"/scan?project={project}&scanner_key=gitleaks")
    assert started.status_code == 200, started.text
    return _wait(client, started.json()["id"])


# --- what may be scanned -----------------------------------------------------


def test_only_a_registered_project_can_be_scanned(client, leaks):
    client.login_as("alice")

    for attack in ("../../etc", "/etc", "demo/../..", "unknown", "~/.ssh"):
        assert client.post(f"/scan?project={attack}&scanner_key=gitleaks").status_code == 404

    assert leaks["calls"] == 0


def test_the_scanner_is_told_to_redact_and_never_to_traverse(project):
    """The single most important flag in the scanner table.

    Without `--redact` gitleaks writes the credential into its report, and this
    application would be holding a live secret in a pipe, a parser, a row and a
    screenshot. With it, the value is replaced inside gitleaks and never
    crosses into this process at all.
    """
    args = scanner.SCANNERS["gitleaks"]["args"](project)

    assert isinstance(args, list)
    assert all(isinstance(a, str) for a in args)
    assert "--redact" in args
    # The directory is "." with cwd set to the project, so the server's
    # filesystem layout never lands in a finding's asset name.
    assert args[0] == "dir" and args[1] == "."
    # JSON, not SARIF: gitleaks' SARIF puts the match in `snippet`, and the
    # SARIF reader copies snippets straight into evidence.
    assert "sarif" not in args


def test_a_missing_scanner_is_its_own_outcome_and_invents_nothing(client, leaks):
    client.login_as("alice")
    leaks["raise"] = scanner.ScannerMissing("Gitleaks bu makinede kurulu değil.")

    body = _scan(client)

    assert body["status"] == "scanner_unavailable"
    assert "kurulu değil" in body["error"]
    assert body["total"] == 0
    assert client.get("/findings").json() == []


# --- the parser, which is where the guarantee is made ------------------------


def test_the_parser_removes_the_secret_from_the_line(client):
    results, skipped = importers.parse_gitleaks(UNREDACTED)

    assert len(results) == 1 and skipped == 0
    assert RAW not in results[0].evidence
    assert results[0].evidence == 'GITHUB_TOKEN = "ghp_************"'


def test_a_line_that_cannot_be_cleaned_is_dropped_entirely(client):
    """A partially-masked line is worse than no line. If the value survives the
    substitution for any reason, this is the last place that could tell."""
    weird = json.dumps([{
        "RuleID": "github-pat",
        "StartLine": 24,
        # The scanner disagrees with itself: the match does not contain what it
        # says the secret is, so the substitution cannot be trusted.
        "Match": f'TOKEN = "{RAW}"',
        "Secret": "something-else-entirely",
        "File": "app/config.py",
    }])

    results, _ = importers.parse_gitleaks(weird)

    assert len(results) == 1
    assert results[0].evidence == ""
    assert RAW not in json.dumps(results[0].details)


def test_the_details_have_no_field_for_a_secret(client):
    results, _ = importers.parse_gitleaks(UNREDACTED)
    details = results[0].details

    assert details["rule"] == "github-pat"
    assert details["secret_type"] == "GitHub Personal Access Token"
    assert details["line"] == 24
    # Not "empty" — absent. There is no key here for a value, and no code that
    # would add one.
    assert "secret" not in details
    assert "match" not in details
    assert RAW not in json.dumps(details)


def test_a_short_value_is_masked_whole(client):
    """Showing four characters of a six-character secret is not a hint."""
    assert importers.mask_secret("abc123") == "*" * 12
    assert importers.mask_secret("") == "*" * 12
    assert importers.mask_secret(RAW).startswith("ghp_")
    assert RAW not in importers.mask_secret(RAW)


# --- the whole pipeline, hunted for leaks ------------------------------------


def test_the_raw_secret_is_not_in_the_database(client, leaks, db):
    client.login_as("alice")
    _scan(client)

    for finding in db.query(Finding).all():
        assert RAW not in (finding.evidence or "")
        assert RAW not in (finding.title or "")
        assert RAW not in (finding.description or "")
        assert RAW not in json.dumps(finding.details or {})

    for run in db.query(ScanRun).all():
        assert RAW not in (run.error or "")
        assert RAW not in (run.note or "")


def test_the_raw_secret_is_not_in_any_api_response(client, leaks):
    """The paranoid version: serialise everything a caller can reach and grep
    the bytes. A field added later that carries it fails here."""
    client.login_as("alice")
    body = _scan(client)
    finding_id = client.get("/findings").json()[0]["id"]

    reachable = [
        client.get("/findings").text,
        client.get(f"/findings/{finding_id}").text,
        client.get("/scan").text,
        client.get(f"/scan/{body['id']}").text,
        client.get("/audit").text,
        client.get("/findings/stats").text,
    ]

    for payload in reachable:
        assert RAW not in payload


def test_the_raw_secret_is_not_in_the_audit_trail(client, leaks, db):
    """The audit log is the one place designed to keep everything forever."""
    client.login_as("alice")
    _scan(client)

    for entry in db.query(AuditLog).all():
        assert RAW not in (entry.detail or "")
        assert RAW not in (entry.action or "")


def test_the_model_is_not_sent_the_secret(client, leaks, db, monkeypatch):
    """AI analysis reads the finding, and the finding is already masked — but
    this asserts it rather than assuming it, because the prompt is built from
    fields somebody could add to later."""
    client.login_as("alice")
    _scan(client)

    finding = db.query(Finding).first()
    prompt = ai._analysis_prompt(finding, include_code=True)

    assert RAW not in prompt
    assert "ghp_************" in prompt or "REDACTED" in prompt


def test_the_code_viewer_is_refused_the_file(client, leaks, monkeypatch, project):
    """The leak this feature would otherwise have.

    The finding is masked; the file on disk is not. The code viewer's fallback
    reads the working tree when the reported snippet cannot place the flagged
    line — and answering that here would hand back the exact line, through an
    endpoint the interface calls on its own.
    """
    monkeypatch.setattr(main_module, "SOURCE_ROOT", str(project), raising=False)
    client.login_as("alice")
    _scan(client)

    finding_id = client.get("/findings").json()[0]["id"]
    response = client.get(f"/findings/{finding_id}/source")

    assert response.status_code == 404
    assert RAW not in response.text
    assert "maskelenmiş" in response.json()["detail"]


def test_a_normal_finding_can_still_read_its_source(client, project, monkeypatch, db):
    """The refusal above is specific. Breaking the code viewer for every SAST
    finding would be a regression dressed up as a control."""
    from app import source as source_module

    monkeypatch.setattr(source_module, "SOURCE_ROOT", str(project))
    client.login_as("alice")

    created = client.post("/findings", json={
        "title": "Hardcoded", "asset": "app/config.py", "severity": "low",
    }).json()
    finding = db.query(Finding).filter(Finding.id == created["id"]).one()
    # A bandit-shaped finding: the report's snippet matches the file, and the
    # flagged line sits outside the block it brought.
    finding.source = "bandit"
    finding.evidence = f'GITHUB_TOKEN = "{RAW}"'
    finding.evidence_start = 1
    finding.evidence_line = 1
    db.commit()

    assert client.get(f"/findings/{created['id']}/source").status_code == 200


# --- the lifecycle -----------------------------------------------------------


def test_a_secret_becomes_an_ordinary_finding(client, leaks):
    client.login_as("alice")

    body = _scan(client)
    finding = client.get("/findings").json()[0]

    assert body["created"] == 1
    assert finding["source"] == "gitleaks"
    assert finding["asset"] == "app/config.py"
    assert finding["source_ref"] == "github-pat:24"
    assert finding["title"] == "GitHub Personal Access Token"
    assert finding["due_date"]


def test_the_same_secret_does_not_pile_up(client, leaks):
    client.login_as("alice")

    first = _scan(client)
    second = _scan(client)

    assert first["created"] == 1
    assert second["created"] == 0
    assert second["unchanged"] == 1
    assert len(client.get("/findings").json()) == 1


def test_a_removed_secret_closes_and_a_returning_one_reopens(client, leaks):
    client.login_as("alice")
    _scan(client)

    # A second credential in the same directory, so the directory is still
    # covered when the first one is removed.
    two = json.loads(UNREDACTED)
    two.append({**two[0], "RuleID": "aws-access-key", "StartLine": 31,
                "Description": "Detected an AWS Access Key, ...",
                "File": "app/settings.py"})
    leaks["report"] = json.dumps(two)
    _scan(client)
    assert len(client.get("/findings").json()) == 2

    # The GitHub token is removed and rotated.
    leaks["report"] = json.dumps([two[1]])
    body = _scan(client)
    assert body["resolved"] == 1

    closed = [f for f in client.get("/findings").json() if f["source_ref"] == "github-pat:24"]
    assert closed[0]["status"] == "fixed"

    # It comes back — a revert, a merge that undid the fix.
    leaks["report"] = json.dumps(two)
    assert _scan(client)["reopened"] == 1


# --- who sees what -----------------------------------------------------------


def test_another_account_sees_neither_the_run_nor_the_finding(client, leaks, db):
    client.login_as("alice")
    started = client.post("/scan?project=demo&scanner_key=gitleaks").json()
    _wait(client, started["id"])

    client.login_as("bob")

    assert client.get(f"/scan/{started['id']}").status_code == 404
    assert client.get("/scan").json() == []
    assert client.get("/findings").json() == []
    assert db.query(ScanRun).count() == 1
    assert db.query(Finding).count() == 1


def test_another_account_cannot_reach_the_source_endpoint_either(client, leaks, db):
    client.login_as("alice")
    _scan(client)
    finding_id = db.query(Finding).first().id

    client.login_as("bob")

    assert client.get(f"/findings/{finding_id}/source").status_code == 404
