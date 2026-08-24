"""Scanning a running system, and the line that keeps it from being a weapon.

Static analysis reads files. Dynamic analysis sends live traffic at something,
so the question "what may it point at" is the whole feature. Everything here is
about that boundary, and about the two scan kinds not resolving each other's
findings.

Nuclei itself is stubbed. What needs proving is which target it would be given
and what happens to the results — not that a Go binary works.
"""
import json

import pytest

from app import config, scanner
import app.main as main_module

TARGET_URL = "http://securetask-test.internal:8000"

NUCLEI = "\n".join(json.dumps(entry) for entry in [
    {
        "template-id": "http-missing-security-headers",
        "host": TARGET_URL,
        "matched-at": TARGET_URL + "/",
        "info": {"name": "HSTS başlığı eksik", "severity": "medium"},
    },
    {
        "template-id": "http-server-header",
        "host": TARGET_URL,
        "matched-at": TARGET_URL + "/",
        "info": {"name": "Sunucu banner'ı sürüm sızdırıyor", "severity": "low"},
    },
])


@pytest.fixture()
def targets(monkeypatch):
    registry = {"securetask-test": TARGET_URL}
    monkeypatch.setattr(config, "DAST_TARGETS", registry)
    monkeypatch.setattr(scanner, "DAST_TARGETS", registry)
    return registry


@pytest.fixture()
def nuclei(monkeypatch, targets):
    state = {"out": NUCLEI, "raise": None, "given": None, "calls": 0}

    def fake_run(name, scanner_key="nuclei"):
        state["calls"] += 1
        state["given"] = name
        if state["raise"]:
            raise state["raise"]
        return scanner.ScanResult(scanner_key, name, state["out"], 0.1)

    monkeypatch.setattr(main_module.scanner, "run", fake_run)
    return state


def _wait(client, scan_id, tries=60):
    import time

    for _ in range(tries):
        body = client.get(f"/scan/{scan_id}").json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.05)

    raise AssertionError("tarama bitmedi")


def _start(client, target="securetask-test"):
    return client.post(f"/scan?project={target}&scanner_key=nuclei")


# --- what it may be pointed at -----------------------------------------------


def test_only_a_registered_target_can_be_scanned(client, nuclei):
    """A URL in a request is the shape of an SSRF. There is no URL in a
    request here — only a name this server resolves itself."""
    client.login_as("alice")

    for attack in (
        "https://example.com",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8000",
        "securetask-test/../other",
        "unknown-target",
    ):
        assert _start(client, attack).status_code == 404

    assert nuclei["calls"] == 0


def test_the_url_is_resolved_from_configuration_not_the_request(client, nuclei):
    client.login_as("alice")

    _wait(client, _start(client).json()["id"])

    # The runner is handed the *name*; scanner.run resolves it against the
    # registry. Nothing the caller sent reaches the command.
    assert nuclei["given"] == "securetask-test"
    assert scanner._dast_target("securetask-test") == TARGET_URL


def test_an_unregistered_name_resolves_to_nothing(client, targets):
    for name in ("https://example.com", "../etc", "", "nope"):
        with pytest.raises(scanner.ScanRefused):
            scanner._dast_target(name)


def test_nothing_is_scannable_when_no_target_is_configured(client, monkeypatch):
    monkeypatch.setattr(scanner, "DAST_TARGETS", {})

    with pytest.raises(scanner.ScanRefused):
        scanner._dast_target("securetask-test")


def test_only_http_targets_are_accepted_from_configuration(client):
    """A scanner handed file:// or gopher:// is a different kind of tool."""
    parsed = config._targets(
        "ok=https://staging.test;bad=file:///etc/passwd;also=gopher://x;empty="
    )

    assert parsed == {"ok": "https://staging.test"}


# --- how it is run -----------------------------------------------------------


def test_the_command_is_a_list_and_restricts_the_scan(client, targets):
    """Each flag is a restriction. `-no-interactsh` is the one people miss:
    nuclei otherwise uses a *public* out-of-band server, telling a third party
    what is being scanned."""
    args = scanner.SCANNERS["nuclei"]["args"](TARGET_URL)

    assert isinstance(args, list) and all(isinstance(a, str) for a in args)
    assert "-no-interactsh" in args
    assert "-disable-redirects" in args
    assert "-disable-update-check" in args
    assert "-rate-limit" in args and "-concurrency" in args
    excluded = args[args.index("-exclude-tags") + 1]
    for tag in ("intrusive", "dos", "brute-force"):
        assert tag in excluded


def test_a_missing_nuclei_says_so(client, targets, monkeypatch):
    monkeypatch.setattr(scanner, "find_binary", lambda name: None)

    with pytest.raises(scanner.ScanRefused) as exc:
        scanner.run("securetask-test", "nuclei")

    assert "kurulu değil" in str(exc.value)


def test_a_clean_target_is_a_successful_scan(client, nuclei):
    """nuclei prints nothing when it finds nothing. That is a result, not a
    failure — treating it as one would mean the scanner only 'worked' on a
    broken system."""
    client.login_as("alice")
    nuclei["out"] = ""

    body = _wait(client, _start(client).json()["id"])

    assert body["status"] == "completed"
    assert body["total"] == 0


def test_a_failed_scan_is_recorded(client, nuclei):
    client.login_as("alice")
    nuclei["raise"] = scanner.ScanFailed("Tarama 900 saniyede bitmedi.")

    body = _wait(client, _start(client).json()["id"])

    assert body["status"] == "failed"
    assert "900" in body["error"]
    assert client.get("/findings").json() == []


# --- results go through the existing importer --------------------------------


def test_results_become_ordinary_findings(client, nuclei):
    client.login_as("alice")

    body = _wait(client, _start(client).json()["id"])

    assert body["kind"] == "dast"
    assert body["created"] == 2
    findings = client.get("/findings").json()
    assert {f["source"] for f in findings} == {"nuclei"}
    # Grouped by host, as the existing nuclei reader has always done.
    assert {f["asset"] for f in findings} == {"securetask-test.internal:8000"}
    # And no code: a network finding has no source line, so the viewer offers
    # nothing rather than inventing a file.
    assert all(f["evidence"] is None for f in findings)


def test_a_second_scan_does_not_duplicate(client, nuclei):
    client.login_as("alice")
    _wait(client, _start(client).json()["id"])

    second = _wait(client, _start(client).json()["id"])

    assert second["created"] == 0
    assert second["unchanged"] == 2
    assert len(client.get("/findings").json()) == 2


def test_a_rescan_splits_new_existing_and_resolved(client, nuclei):
    client.login_as("alice")
    _wait(client, _start(client).json()["id"])

    nuclei["out"] = "\n".join(json.dumps(e) for e in [
        {
            "template-id": "http-server-header",
            "host": TARGET_URL,
            "info": {"name": "Sunucu banner'ı", "severity": "low"},
        },
        {
            "template-id": "tls-version",
            "host": TARGET_URL,
            "info": {"name": "Eski TLS sürümü", "severity": "high"},
        },
    ])
    second = _wait(client, _start(client).json()["id"])

    assert second["created"] == 1        # tls-version
    assert second["unchanged"] == 1      # http-server-header
    assert second["resolved"] == 1       # http-missing-security-headers

    by_rule = {f["source_ref"]: f for f in client.get("/findings").json()}
    assert by_rule["http-missing-security-headers"]["status"] == "fixed"
    assert by_rule["tls-version"]["status"] == "open"


# --- the two kinds do not resolve each other ---------------------------------


@pytest.fixture()
def sast(monkeypatch, tmp_path):
    (tmp_path / "app").mkdir()
    monkeypatch.setattr(scanner, "SCAN_PROJECTS", {"demo": str(tmp_path)})
    monkeypatch.setattr(config, "SCAN_PROJECTS", {"demo": str(tmp_path)})

    sarif = json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Bandit"}},
            "results": [{
                "ruleId": "B608",
                "level": "warning",
                "message": {"text": "Possible SQL injection"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app/reports.py"},
                    "region": {"startLine": 1, "snippet": {"text": "x = 1"}},
                }}],
            }],
        }],
    })
    return sarif


def test_a_dast_rescan_never_resolves_a_sast_finding(client, nuclei, sast, monkeypatch):
    """The scopes are separated by the scanner that produced the finding, so a
    web scan cannot close something found by reading code — and vice versa."""
    client.login_as("alice")

    def dispatch(name, scanner_key="bandit"):
        if scanner_key == "nuclei":
            return scanner.ScanResult(scanner_key, name, nuclei["out"], 0.1)
        return scanner.ScanResult(scanner_key, name, sast, 0.1)

    monkeypatch.setattr(main_module.scanner, "run", dispatch)

    _wait(client, client.post("/scan?project=demo").json()["id"])          # SAST
    _wait(client, _start(client).json()["id"])                             # DAST

    # Now a DAST rescan that reports nothing at all.
    nuclei["out"] = ""
    run = _wait(client, _start(client).json()["id"])

    code_finding = next(
        f for f in client.get("/findings").json() if f["source"] == "bandit"
    )
    assert code_finding["status"] == "open"
    assert run["resolved"] == 0   # nothing of its own was covered either


def test_a_sast_rescan_never_resolves_a_dast_finding(client, nuclei, sast, monkeypatch):
    client.login_as("alice")

    def dispatch(name, scanner_key="bandit"):
        if scanner_key == "nuclei":
            return scanner.ScanResult(scanner_key, name, nuclei["out"], 0.1)
        return scanner.ScanResult(scanner_key, name, sast, 0.1)

    monkeypatch.setattr(main_module.scanner, "run", dispatch)
    _wait(client, _start(client).json()["id"])                             # DAST
    _wait(client, client.post("/scan?project=demo").json()["id"])          # SAST
    _wait(client, client.post("/scan?project=demo").json()["id"])          # SAST again

    web = [f for f in client.get("/findings").json() if f["source"] == "nuclei"]
    assert web and all(f["status"] == "open" for f in web)


# --- who sees what -----------------------------------------------------------


def test_a_dast_run_is_scoped_to_who_started_it(client, nuclei):
    client.login_as("alice")
    scan = _start(client).json()
    _wait(client, scan["id"])
    client.logout()
    client.login_as("mallory")

    assert client.get("/scan").json() == []
    assert client.get(f"/scan/{scan['id']}").status_code == 404
    assert client.get("/findings").json() == []


def test_the_options_endpoint_lists_targets_and_kinds(client, nuclei):
    client.login_as("alice")

    body = client.get("/scan/options").json()

    assert [t["name"] for t in body["targets"]] == ["securetask-test"]
    kinds = {s["key"]: s["kind"] for s in body["scanners"]}
    assert kinds["bandit"] == "sast" and kinds["nuclei"] == "dast"
