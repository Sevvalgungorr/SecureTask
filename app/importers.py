"""Reading scanner output into findings.

Only public, documented output formats are parsed here. A scanner reports what
it saw; it does not get to decide what the team already concluded about it, so
the ingest rules in main.py treat existing findings as the human's territory.
"""
import json
from dataclasses import dataclass
from urllib.parse import urlparse

# One import may not create an unbounded amount of work. A scan of a large
# estate legitimately produces thousands of rows, but accepting them in a single
# request turns an authenticated user into a cheap way to fill the database.
MAX_RESULTS = 1000

# nuclei rates findings on its own scale. `info` results are not vulnerabilities
# (version banners, technology detection); they enter as low rather than being
# dropped, because they are still inventory. `unknown` is treated the same way:
# an unrated result is not evidence of low risk, but guessing higher would drown
# the real findings.
NUCLEI_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
    "unknown": "low",
}


@dataclass(frozen=True)
class ScanResult:
    """One result from a scanner, normalised to this application's vocabulary."""

    source_ref: str
    title: str
    asset: str
    severity: str
    description: str
    # Optional: the lines the report carried with it. A network scan has none.
    evidence: str = ""
    evidence_start: int | None = None
    evidence_line: int | None = None


# A snippet is quoted source code from someone's repository. Long enough to
# show the line in context, short enough that a report cannot use this as a
# way to store a file.
MAX_EVIDENCE = 4000


def _asset_of(entry: dict) -> str:
    """The host a result belongs to.

    nuclei reports `host` as a URL as often as a bare hostname, and findings
    have to group by host — otherwise the same missing header on ten paths of
    one site becomes ten findings.
    """
    raw = (entry.get("host") or entry.get("matched-at") or entry.get("matched_at") or "").strip()

    if not raw:
        return ""

    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.netloc or raw)[:255]

    # A bare host:port, or a matched-at without a scheme — keep the authority.
    return raw.split("/", 1)[0][:255]


def _entries(raw: str) -> list:
    """Accept both shapes nuclei writes: a JSON array, or one object per line."""
    text = raw.strip()

    if not text:
        return []

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        pass
    else:
        return loaded if isinstance(loaded, list) else [loaded]

    entries = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            # A single unreadable line must not lose the rest of the scan; it is
            # counted as skipped by the caller.
            entries.append(None)

    return entries


def parse_nuclei(raw: str) -> tuple[list[ScanResult], int]:
    """Return the usable results and how many entries were unusable."""
    results: list[ScanResult] = []
    skipped = 0

    for entry in _entries(raw)[:MAX_RESULTS]:
        if not isinstance(entry, dict):
            skipped += 1
            continue

        template_id = str(entry.get("template-id") or entry.get("template_id") or "").strip()
        asset = _asset_of(entry)

        # Without both, a result cannot be matched against a later scan, which
        # is the whole point of importing rather than typing.
        if not template_id or not asset:
            skipped += 1
            continue

        info = entry.get("info") if isinstance(entry.get("info"), dict) else {}
        severity = NUCLEI_SEVERITY.get(
            str(info.get("severity") or "unknown").lower(), "low"
        )
        title = str(info.get("name") or template_id).strip()[:200]

        matched = str(entry.get("matched-at") or entry.get("matched_at") or "").strip()
        description = " · ".join(
            part for part in (str(info.get("description") or "").strip(), matched) if part
        )

        results.append(
            ScanResult(
                source_ref=template_id[:255],
                title=title,
                asset=asset,
                severity=severity,
                description=description[:2000],
            )
        )

    return results, skipped


# --- SARIF: the format code scanners agree on ------------------------------
#
# Semgrep, Bandit, CodeQL, gitleaks and GitHub's own scanning all emit SARIF,
# so reading one format covers the whole category. Nothing here runs a scanner:
# the report is produced wherever the code already lives — a developer's
# machine or their CI — and only the findings are sent. Cloning someone's
# repository to scan it would mean executing untrusted code and holding their
# source, which is a liability this application has no reason to take on.

# SARIF's own severity vocabulary. `none` covers informational rules, which are
# kept rather than dropped for the same reason nuclei's `info` results are.
SARIF_LEVEL = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}

# GitHub's convention: a CVSS-like number carried on the rule. When present it
# is more precise than the coarse level, so it wins.
def _severity_from_score(score: str) -> str | None:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None

    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"

    return "low"


def _rule_index(run: dict) -> dict:
    """Rules are declared once per run and referenced by id from each result."""
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = {}

    for rule in driver.get("rules") or []:
        if isinstance(rule, dict) and rule.get("id"):
            rules[str(rule["id"])] = rule

    return rules


def _location_of(result: dict) -> tuple[str, str]:
    """The file a finding sits in, and the line, as far as SARIF states them."""
    locations = result.get("locations") or []

    if not locations or not isinstance(locations[0], dict):
        return "", ""

    physical = locations[0].get("physicalLocation") or {}
    uri = str((physical.get("artifactLocation") or {}).get("uri") or "").strip()
    line = (physical.get("region") or {}).get("startLine")

    return uri.lstrip("/")[:255], (f"satır {line}" if line else "")


def _evidence_of(result: dict) -> tuple[str, int | None, int | None]:
    """The quoted source the report brought, if it brought any.

    `contextRegion` is preferred over `region`: a rule that fires on one line
    is easier to judge with the lines around it, and the scanner already
    decided how much context is fair to include.
    """
    locations = result.get("locations") or []

    if not locations or not isinstance(locations[0], dict):
        return "", None, None

    physical = locations[0].get("physicalLocation") or {}
    region = physical.get("region") or {}
    context = physical.get("contextRegion") or {}
    block = context if context.get("snippet") else region

    text = str((block.get("snippet") or {}).get("text") or "")

    if not text.strip():
        return "", None, None

    def _int(value):
        return value if isinstance(value, int) and value > 0 else None

    return text[:MAX_EVIDENCE], _int(block.get("startLine")), _int(region.get("startLine"))


def parse_sarif(raw: str) -> tuple[list[ScanResult], int, str]:
    """Return the usable results, how many were unusable, and the tool's name.

    A file is a finding's asset here, the way a host is for a network scan:
    it is the thing the problem lives on, so the same rule firing on the same
    file across two scans is one finding rather than two.
    """
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return [], 0, ""

    if not isinstance(document, dict):
        return [], 0, ""

    results: list[ScanResult] = []
    skipped = 0
    tool = ""

    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            skipped += 1
            continue

        driver = (run.get("tool") or {}).get("driver") or {}
        tool = tool or str(driver.get("name") or "").strip().lower()[:30]
        rules = _rule_index(run)

        for entry in run.get("results") or []:
            if len(results) >= MAX_RESULTS:
                break

            if not isinstance(entry, dict):
                skipped += 1
                continue

            rule_id = str(entry.get("ruleId") or "").strip()
            asset, line = _location_of(entry)

            # Without both there is nothing to match a later scan against,
            # which is the whole point of importing rather than typing.
            if not rule_id or not asset:
                skipped += 1
                continue

            rule = rules.get(rule_id, {})
            properties = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
            severity = (
                _severity_from_score(properties.get("security-severity"))
                or SARIF_LEVEL.get(str(entry.get("level") or "").lower())
                or SARIF_LEVEL.get(str(rule.get("defaultConfiguration", {}).get("level") or "").lower())
                or "medium"
            )

            message = str((entry.get("message") or {}).get("text") or "").strip()
            short = str((rule.get("shortDescription") or {}).get("text") or "").strip()
            title = (short or message or rule_id)[:200]

            evidence, ev_start, ev_line = _evidence_of(entry)

            results.append(
                ScanResult(
                    source_ref=rule_id[:255],
                    title=title,
                    asset=asset,
                    severity=severity,
                    description=" · ".join(p for p in (message, line) if p)[:2000],
                    evidence=evidence,
                    evidence_start=ev_start,
                    evidence_line=ev_line,
                )
            )

    return results, skipped, (tool or "sarif")
