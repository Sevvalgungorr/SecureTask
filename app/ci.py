"""The pipeline's side of the fence: machine credentials, and what they buy.

Everything else in this application is used by a person holding a session from
an identity provider. This is the one door a *program* comes through, unattended,
from a machine nobody in the team controls — so it is worth being explicit about
what is different.

**A CI token is not a login.** It cannot read findings, cannot change a status,
cannot accept a risk and cannot see another repository. It can report what a
scanner found for the one repository it is registered against, say that a
deployment happened, and ask what the gate concluded. Everything a person does
still needs a person.

**The token is never stored.** Only its SHA-256 is, and verification is a
lookup by that hash — so there is no stored secret to compare against, nothing
to leak from a backup, and no way to show a token again after it is issued. The
one moment the plaintext exists is the response that creates it.

**The repository name in a request is not trusted.** It is matched against the
registration, and the tenant comes from the registration. Without that, any
valid token could name any repository and file findings into somebody else's
list — which is the whole of the multi-tenant boundary, decided in one lookup.

**Nothing here deploys anything.** A deployment event is a *report* that an
external system already did something. There is no host, no key and no command
in this module, because the moment there is, this application is a thing worth
attacking to get at somebody's infrastructure.
"""
import hashlib
import hmac
import secrets

from app.models import (
    DEPLOY_FAILED,
    DEPLOY_SUCCEEDED,
    GATE_BLOCKS_AT,
    GATE_FAILED,
    GATE_INCOMPLETE,
    GATE_PASSED,
    RELEASE_INCOMPLETE,
    RELEASE_NOT_READY,
    RELEASE_READY,
    REQUIRED_SCANS,
)

# Long enough that guessing is not a strategy, and prefixed so a leaked one is
# recognisable for what it is. Secret-scanning tools find credentials by their
# shape; a token that looks like random text is one nobody's scanner will spot
# in a log or a commit.
TOKEN_PREFIX = "st_ci_"
TOKEN_BYTES = 32

# Which scan types a pipeline may report, and which reader handles each. The
# keys are also what `ScanRun.kind` records, so a CI-reported run and a locally
# started one are the same kind of row.
SCAN_TYPES = ("sast", "sca", "secret")

# Which tool each scan type is expected to come from. The scanner name is taken
# from here rather than from the request: a report that could name its own tool
# could file findings as "bandit" and have them close a bandit scan's findings.
SCANNER_FOR = {
    "sast": "bandit",
    "sca": "pip-audit",
    "secret": "gitleaks",
}


def issue_token() -> tuple[str, str]:
    """A new token and the hash to store. The plaintext is returned once."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    """SHA-256, and no salt on purpose.

    A salt defends a low-entropy secret against a precomputed table. This one
    is 32 random bytes, so there is no table to build — and a per-row salt
    would mean verification could not be a single indexed lookup, which is the
    property that keeps this from becoming a scan over every integration.
    """
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def looks_like_token(value: str) -> bool:
    """Cheap shape check, so a malformed header does not reach the database."""
    return bool(value) and value.startswith(TOKEN_PREFIX) and len(value) > len(TOKEN_PREFIX) + 20


def same_repository(claimed: str, registered: str) -> bool:
    """Compare the repository a request names against the one it may use.

    Constant-time, and case-insensitive because providers are: GitHub treats
    `Sevvalgungorr/SecureTask` and `sevvalgungorr/securetask` as one repository,
    and a mismatch here would be a refusal nobody could explain.
    """
    return hmac.compare_digest(
        (claimed or "").strip().lower(), (registered or "").strip().lower()
    )


def gate_for(runs: list) -> tuple[str, str]:
    """The security gate, from the scan runs a pipeline has so far.

    Three answers, and the third is the one that makes the other two mean
    anything:

    * **INCOMPLETE** — a required scan did not run, or ran and broke, or its
      scanner is not installed. Nothing is known, so nothing is claimed. A gate
      that reports "passed" when the secret scanner never ran is worse than no
      gate: it is a green light for a check that did not happen.
    * **FAILED** — every required scan finished, and something critical is open.
    * **PASSED** — every required scan finished and nothing critical is open.

    Only critical blocks. A gate that fails on everything is a gate somebody
    turns off, and a gate that is off is not a stricter policy than a narrow
    one — it is no policy.
    """
    by_kind = {}

    for run in runs:
        # Latest wins if a kind somehow has two: the newer statement about the
        # same code is the one to judge on.
        current = by_kind.get(run.kind)
        if current is None or run.id > current.id:
            by_kind[run.kind] = run

    missing = [kind for kind in REQUIRED_SCANS if kind not in by_kind]

    if missing:
        return GATE_INCOMPLETE, (
            "Zorunlu tarama tamamlanmadı: " + ", ".join(k.upper() for k in missing)
        )

    broken = [
        run for kind, run in by_kind.items()
        if kind in REQUIRED_SCANS and run.status != "completed"
    ]

    if broken:
        worst = broken[0]
        # "Scanner not installed" and "the scan crashed" are both INCOMPLETE,
        # but they are not the same sentence to read at 2am.
        why = (
            f"{worst.scanner} bu makinede kurulu değil"
            if worst.status == "scanner_unavailable"
            else f"{worst.scanner} taraması {worst.status}"
        )
        return GATE_INCOMPLETE, f"{worst.kind.upper()} tamamlanamadı — {why}."

    blocking = sum(run.blocking or 0 for kind, run in by_kind.items() if kind in REQUIRED_SCANS)

    if blocking:
        return GATE_FAILED, (
            f"{blocking} açık kritik bulgu var. "
            "Risk kabul edilmiş olanlar sayılmadı."
        )

    return GATE_PASSED, "Zorunlu taramaların hepsi tamamlandı, açık kritik bulgu yok."


def release_for(pipeline, dast_run) -> tuple[str, str]:
    """Whether what was deployed is safe to release, which is a third question.

    A deployment succeeding says the artefact runs. The gate passing says the
    source looked clean before it was built. Neither says the running system
    was checked — so this is computed from all three, and refuses to round up.

    The ordering matters: a definite failure anywhere is NOT READY, and only
    what is genuinely unknown is INCOMPLETE. Reporting "incomplete" for a
    pipeline whose gate failed would bury a real answer under a soft one.
    """
    if pipeline.security_gate == GATE_FAILED:
        return RELEASE_NOT_READY, "Security Gate geçilemedi."

    if pipeline.deployment_status == DEPLOY_FAILED:
        return RELEASE_NOT_READY, "Staging dağıtımı başarısız oldu."

    if dast_run is not None and dast_run.status == "completed" and (dast_run.blocking or 0):
        return RELEASE_NOT_READY, (
            f"DAST {dast_run.blocking} açık kritik bulgu buldu."
        )

    if pipeline.security_gate != GATE_PASSED:
        return RELEASE_INCOMPLETE, pipeline.gate_reason or "Security Gate tamamlanmadı."

    if pipeline.deployment_status != DEPLOY_SUCCEEDED:
        return RELEASE_INCOMPLETE, "Staging dağıtımı henüz tamamlanmadı."

    if dast_run is None:
        return RELEASE_INCOMPLETE, "Dağıtım sonrası DAST çalıştırılmadı."

    if dast_run.status == "scanner_unavailable":
        # The honest answer, and the one the specification asks for by name.
        # A missing scanner is not a clean result.
        return RELEASE_INCOMPLETE, "DAST tarayıcısı bu makinede kurulu değil."

    if dast_run.status != "completed":
        return RELEASE_INCOMPLETE, f"DAST taraması {dast_run.status}."

    return RELEASE_READY, (
        "Security Gate geçildi, staging dağıtımı başarılı, DAST temiz."
    )
