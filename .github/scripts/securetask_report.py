#!/usr/bin/env python3
"""Report a pipeline's security results to SecureTask.

Small on purpose. Everything that decides anything — which scanner a report is
attributed to, whether the gate passes, which URL a DAST scan reaches — lives on
the server. This script carries bytes and reads back an answer.

Two secrets, both from the environment, neither ever printed:

    SECURETASK_API_URL    where the installation is
    SECURETASK_CI_TOKEN   what this repository is allowed to report

The token is sent in a header and is never written to stdout, which matters
because a workflow's log is readable by anyone who can read the repository and
GitHub only masks values it was told are secrets.
"""
# So the script also runs on an older interpreter than the workflow pins —
# somebody will run it by hand to debug a pipeline, and "unsupported operand
# type(s) for |" is a confusing first thing to meet.
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30


def env(name: str, required: bool = True) -> str:
    value = (os.environ.get(name) or "").strip()

    if required and not value:
        # The name, never the value.
        print(f"::error::{name} tanımlı değil.", file=sys.stderr)
        sys.exit(1)

    return value


def configured() -> bool:
    """Is there a SecureTask to report to?

    Two ways there is not, and neither is a broken build:

    * nobody has set the secrets up yet — the workflow is in the repository
      before the integration is;
    * the run came from a fork, and GitHub does not give forks a repository's
      secrets, on purpose.

    In both cases the scans still ran and their results are still in the job's
    log. Failing here would turn "the integration is not connected" into a red
    tick on every pull request, and a red tick people learn to ignore is worse
    than no tick.
    """
    return bool(
        (os.environ.get("SECURETASK_API_URL") or "").strip()
        and (os.environ.get("SECURETASK_CI_TOKEN") or "").strip()
    )


def context() -> dict:
    """What identifies this run, from GitHub's own environment.

    `repository` is sent because the server matches it against the
    registration — it is a claim to be checked, not a value to be trusted, and
    a mismatch is a refusal.
    """
    event = {}
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if event_path and os.path.isfile(event_path):
        try:
            with open(event_path, encoding="utf-8") as handle:
                event = json.load(handle)
        except (OSError, json.JSONDecodeError):
            event = {}

    pull_request = (event.get("pull_request") or {}).get("number")
    sha = env("GITHUB_SHA", required=False)

    # For a pull_request event GITHUB_SHA is the merge commit, which is not a
    # commit anyone can check out. The head sha is the one a person looks for.
    if pull_request:
        sha = ((event.get("pull_request") or {}).get("head") or {}).get("sha") or sha

    repository = env("GITHUB_REPOSITORY")
    server = env("GITHUB_SERVER_URL", required=False) or "https://github.com"
    run_id = env("GITHUB_RUN_ID", required=False)

    return {
        "repository": repository,
        "external_run_id": env("RUN_ID"),
        "branch": (env("GITHUB_HEAD_REF", required=False)
                   or env("GITHUB_REF_NAME", required=False)),
        "commit_sha": sha,
        "pull_request": pull_request,
        "external_url": f"{server}/{repository}/actions/runs/{run_id}" if run_id else "",
    }


def call(method: str, path: str, body: dict | None = None) -> dict:
    base = env("SECURETASK_API_URL").rstrip("/")
    token = env("SECURETASK_CI_TOKEN")

    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(base + path, data=data, method=method)
    request.add_header("X-SecureTask-Token", token)

    if data is not None:
        request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        # The path and the status, never the header that was sent.
        print(f"::error::SecureTask {exc.code} — {detail}", file=sys.stderr)
        raise SystemExit(1) from exc
    except urllib.error.URLError as exc:
        print(f"::error::SecureTask'a ulaşılamadı: {exc.reason}", file=sys.stderr)
        raise SystemExit(1) from exc


def read_report(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def summarise(body: dict) -> None:
    """Print the verdict where a person reading the run will see it."""
    print(f"Security Gate: {body.get('security_gate', '?')}")

    if body.get("gate_reason"):
        print(f"  {body['gate_reason']}")

    print(f"Release Security: {body.get('release_status', '?')}")

    if body.get("release_reason"):
        print(f"  {body['release_reason']}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")

    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(
                f"### SecureTask\n\n"
                f"- **Security Gate:** `{body.get('security_gate', '?')}` — "
                f"{body.get('gate_reason', '')}\n"
                f"- **Release Security:** `{body.get('release_status', '?')}` — "
                f"{body.get('release_reason', '')}\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-type", choices=("sast", "sca", "secret"))
    parser.add_argument("--report")
    parser.add_argument("--succeeded", default="true")
    parser.add_argument("--deployment", choices=("started", "succeeded", "failed"))
    parser.add_argument("--dast", action="store_true")
    parser.add_argument("--gate", action="store_true")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    if not configured():
        print(
            "::notice::SECURETASK_API_URL / SECURETASK_CI_TOKEN tanımlı değil — "
            "sonuç gönderilmedi. Depoyu SecureTask'ta DevSecOps → 'Depo bağla' "
            "ile kaydedip jetonu GitHub Secrets'a ekle."
        )
        return 0

    ctx = context()

    if args.scan_type:
        succeeded = args.succeeded.strip().lower() == "true"
        payload = read_report(args.report) if (succeeded and args.report) else ""

        if succeeded and not payload.strip():
            # An empty report from a scanner that did not run reads exactly
            # like a repository with nothing wrong in it. Say which it was.
            succeeded = False

        call("POST", "/ci/results", {
            **ctx,
            "scan_type": args.scan_type,
            "succeeded": succeeded,
            "error": "" if succeeded else f"{args.scan_type} CI'da tamamlanamadı.",
            "payload": payload,
        })
        print(f"{args.scan_type.upper()}: bildirildi "
              f"({'tamamlandı' if succeeded else 'çalıştırılamadı'})")
        return 0

    if args.deployment:
        call("POST", "/ci/deployments", {**ctx, "state": args.deployment,
                                         "environment": "staging"})
        print(f"Dağıtım bildirildi: {args.deployment}")
        return 0

    if args.dast:
        body = call("POST", "/ci/dast", {**ctx, "environment": "staging"})
        print(f"DAST istendi. Release Security: {body.get('release_status', '?')}")
        return 0

    if args.gate or args.release:
        query = (
            f"/ci/gate?repository={urllib.parse.quote(ctx['repository'])}"
            f"&external_run_id={urllib.parse.quote(ctx['external_run_id'])}"
        )
        body = call("GET", query)
        summarise(body)

        if args.gate:
            # The gate is enforced here, in the pipeline, rather than by
            # SecureTask blocking a merge. This is the seam where a required
            # status check would later plug in.
            if body.get("security_gate") == "failed":
                print("::error::Security Gate geçilemedi.", file=sys.stderr)
                return 1

            if body.get("security_gate") == "incomplete":
                # A warning, not a failure, in this first version: a scanner
                # that could not be installed should not stop everyone's work
                # before the team has decided that it should.
                print("::warning::Security Gate tamamlanamadı — "
                      "zorunlu taramalardan biri çalışmadı.")

        return 0

    parser.error("bir eylem seç")
    return 2


if __name__ == "__main__":
    sys.exit(main())
