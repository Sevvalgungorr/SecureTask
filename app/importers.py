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
    # What this particular scanner reported that has no field of its own — the
    # package and fixed version, the rule and the type of credential. Never a
    # secret value: for the one scanner that sees secrets, this dict is built
    # from fields that are not the secret, and the check is in parse_gitleaks.
    details: dict | None = None


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


# --- SCA: what the dependencies drag in ------------------------------------
#
# The application's own code is one attack surface; the code it installs is
# another, and usually the larger one. pip-audit reads a manifest and asks a
# vulnerability service what is known about each pinned version. It does not
# install anything and it does not run anything — see app/scanner.py for the
# flags that keep it that way.

# pip-audit reports no severity. Not "sometimes"; the JSON schema has no field
# for it, on either the PyPI or the OSV service — only the advisory id, the
# versions that fix it, the aliases and the prose. So this is SecureTask's
# default for an unrated dependency vulnerability, not a rating anyone's
# scanner produced, and the finding says so in as many words. Inventing a
# severity per CVE would be inventing the one number the whole SLA hangs off.
SCA_SEVERITY = "medium"

SCA_UNRATED = (
    "pip-audit derecelendirme vermiyor; bu kritiklik SecureTask varsayılanı, "
    "tarayıcının değerlendirmesi değil."
)


def _preferred_alias(aliases: list) -> str:
    """A CVE if there is one — that is the identifier people search for."""
    names = [str(a).strip() for a in aliases if isinstance(a, (str, int))]

    for name in names:
        if name.upper().startswith("CVE-"):
            return name

    return names[0] if names else ""


def parse_pip_audit(raw: str) -> tuple[list[ScanResult], int, set[str]]:
    """Return the results, how many entries were unusable, and what was audited.

    The third value is the point of doing this here rather than in the generic
    importer. pip-audit lists **every** dependency it examined, including the
    ones with nothing wrong — so a re-scan knows exactly which packages were
    looked at, and a vulnerability that has since been patched can be closed
    because the package was checked and came back clean. Guessing that from the
    findings alone is not possible: a package with no vulnerabilities produces
    no results to infer coverage from.
    """
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return [], 0, set()

    if not isinstance(document, dict):
        return [], 0, set()

    results: list[ScanResult] = []
    skipped = 0
    audited: set[str] = set()

    for dep in document.get("dependencies") or []:
        if not isinstance(dep, dict):
            skipped += 1
            continue

        package = str(dep.get("name") or "").strip()
        version = str(dep.get("version") or "").strip()

        if not package:
            skipped += 1
            continue

        # Examined, whether or not anything was found. This is the coverage.
        audited.add(package.lower())

        for vuln in dep.get("vulns") or []:
            if len(results) >= MAX_RESULTS:
                break

            if not isinstance(vuln, dict):
                skipped += 1
                continue

            vuln_id = str(vuln.get("id") or "").strip()

            if not vuln_id:
                skipped += 1
                continue

            aliases = vuln.get("aliases") if isinstance(vuln.get("aliases"), list) else []
            fixes = [
                str(f).strip()
                for f in (vuln.get("fix_versions") or [])
                if isinstance(f, (str, int))
            ]
            cve = _preferred_alias(aliases)
            label = cve or vuln_id

            fix_text = (
                f"Düzeltilen sürüm: {', '.join(fixes)}" if fixes
                else "Yayımlanmış bir düzeltme sürümü bildirilmedi."
            )
            description = " · ".join(
                part for part in (
                    str(vuln.get("description") or "").strip(),
                    f"Kurulu sürüm: {version}" if version else "",
                    fix_text,
                    SCA_UNRATED,
                ) if part
            )

            results.append(
                ScanResult(
                    # The advisory id, not the CVE: it is what pip-audit keys
                    # on, so it is stable across runs. The CVE is what a person
                    # searches for, so it is in the title and the detail.
                    source_ref=vuln_id[:255],
                    title=f"{package} {version} · {label}"[:200],
                    # The package is the asset. A dependency vulnerability
                    # lives on the dependency, the way a code finding lives on
                    # a file — so the same CVE in the same package is one
                    # finding across re-scans rather than a new one each time.
                    asset=package[:255],
                    severity=SCA_SEVERITY,
                    description=description[:2000],
                    details={
                        "kind": "sca",
                        "package": package,
                        "installed_version": version,
                        "vulnerability_id": vuln_id,
                        "cve": cve,
                        "fixed_versions": fixes,
                        "aliases": [str(a) for a in aliases][:10],
                        # So the interface can say where the rating came from
                        # instead of presenting it as the scanner's.
                        "severity_source": "securetask-default",
                    },
                )
            )

    return results, skipped, audited


# --- Secret scanning: the one scanner whose output is itself dangerous ------
#
# Everything else here reports *about* code. This one reports code, and the
# code is a live credential. Gitleaks emits the matched line and the secret it
# found as separate fields, which is what makes it safe to use: the secret can
# be removed from the line before anything else in this application sees it.
#
# That removal happens HERE, in the parser, and not later. There is no layer
# below this that has the raw value, so there is no persistence, log, audit
# entry, API response, AI prompt or code viewer that could leak one — not
# because each of them is careful, but because none of them is ever given it.
#
# Deliberately not SARIF, which gitleaks can also emit: its SARIF `snippet`
# carries the raw secret, and the SARIF reader above copies snippets straight
# into `evidence`. Reading the richer format would have been less code and a
# credential in the database.

# Gitleaks does not rate its rules either. A working credential committed to a
# repository is not a medium; this is SecureTask's policy and the finding says
# so, the same way the SCA default does.
SECRET_SEVERITY = "high"

SECRET_UNRATED = (
    "Gitleaks derecelendirme vermiyor; bu kritiklik SecureTask varsayılanı."
)

# How much of a masked value is shown. Enough to recognise which credential is
# meant — "AKIA…" says AWS, "ghp_…" says GitHub — and not enough to use.
MASK_PREFIX = 4
# A fixed number of asterisks, so the mask does not disclose the length of the
# secret it replaced.
MASK_BODY = "*" * 12


def mask_secret(secret: str) -> str:
    """The stand-in a secret is replaced by, everywhere it would have appeared."""
    value = (secret or "").strip()

    if not value:
        return MASK_BODY

    # Short values are all prefix. Showing four characters of a six-character
    # value is not a hint, it is most of the secret.
    if len(value) < 12:
        return MASK_BODY

    return value[:MASK_PREFIX] + MASK_BODY


def _masked_line(match: str, secret: str) -> str:
    """The matched line with the secret taken out of it, or nothing.

    Returns "" rather than a partially-masked line if the value survives the
    substitution for any reason. A line that still contains the credential is
    worse than no line at all, and this is the last place that could tell.
    """
    if not match or not secret:
        return ""

    # The scanner has to agree with itself. If the value it named is not in the
    # line it reported, the substitution below would be a no-op and this would
    # return the line untouched — with whatever is actually in it. Checking
    # only that `secret` is gone afterwards does not catch that: it is already
    # gone, because it was never there.
    if secret not in match:
        return ""

    masked = match.replace(secret, mask_secret(secret))

    # The check that makes the rest of the application's guarantees true.
    if secret in masked:
        return ""

    return masked.strip()[:MAX_EVIDENCE]


# Past this, the description is a sentence rather than a name. "Generic API
# Key" is a title; "Discovered a potential authorization token provided in a
# curl command header" is prose, and prose in a title makes every row in the
# list the same height as a paragraph.
MAX_SECRET_TYPE = 48

_LEAD = (
    "Detected a ", "Detected an ", "Detected ",
    "Discovered a ", "Discovered an ", "Discovered ",
    "Identified a ", "Identified an ", "Identified ",
    "Uncovered a ", "Uncovered an ", "Uncovered ",
    "Found a ", "Found an ", "Found ",
)


def _secret_type(description: str, rule_id: str) -> str:
    """A readable name for what was found.

    Gitleaks' own prose where it is short enough to be a name, and the rule id
    made readable where it is not. Truncating the sentence instead would
    produce "Discovered a potential authorization token provided in a…", which
    is a name nobody can scan a list by.
    """
    text = str(description or "").split(",")[0].split(".")[0].strip()

    for prefix in _LEAD:
        if text.lower().startswith(prefix.lower()):
            text = text[len(prefix):]
            break

    if text and len(text) <= MAX_SECRET_TYPE:
        return text

    # "curl-auth-header" → "Curl Auth Header". The rule id is what gitleaks
    # keys on, so it is the most precise short name available.
    pretty = " ".join(word.capitalize() for word in rule_id.replace("_", "-").split("-"))

    return (pretty or rule_id).strip()[:120]


def parse_gitleaks(raw: str) -> tuple[list[ScanResult], int]:
    """Read gitleaks' JSON report, leaving every secret behind.

    `Secret` and `Match` are read and neither is returned. What comes out is
    the file, the line, the rule, the kind of credential, and a masked preview
    of the line — which is what someone needs to go and remove it.
    """
    try:
        entries = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return [], 0

    if entries is None:
        return [], 0

    if not isinstance(entries, list):
        return [], 0

    results: list[ScanResult] = []
    skipped = 0

    for entry in entries[:MAX_RESULTS]:
        if not isinstance(entry, dict):
            skipped += 1
            continue

        rule_id = str(entry.get("RuleID") or entry.get("ruleID") or "").strip()
        path = str(entry.get("File") or entry.get("file") or "").strip().lstrip("/")
        line = entry.get("StartLine") or entry.get("startLine")
        line = line if isinstance(line, int) and line > 0 else None

        if not rule_id or not path:
            skipped += 1
            continue

        secret_type = _secret_type(entry.get("Description"), rule_id)
        # Read here, never returned. Both are raw.
        preview = _masked_line(
            str(entry.get("Match") or ""), str(entry.get("Secret") or "")
        )

        # rule + file + line, which is gitleaks' own fingerprint minus the
        # part that would need the secret. Two different keys in one file are
        # two findings; the same key found again is the same finding.
        source_ref = f"{rule_id}:{line}" if line else rule_id

        results.append(
            ScanResult(
                source_ref=source_ref[:255],
                title=secret_type[:200],
                asset=path[:255],
                severity=SECRET_SEVERITY,
                # Gitleaks' own prose about the rule, not a restatement of the
                # title — the file, line and rule are already their own fields
                # and repeating them here makes every row a paragraph tall.
                description=" · ".join(
                    part for part in (
                        str(entry.get("Description") or "").strip(),
                        SECRET_UNRATED,
                    ) if part
                )[:2000],
                # The masked line, in the field the code viewer already reads.
                # It is one line, so the flagged line is inside the block and
                # the viewer never asks the server to open the file — which is
                # also refused for this kind of finding, in main.py.
                evidence=preview,
                evidence_start=line if preview else None,
                evidence_line=line if preview else None,
                details={
                    "kind": "secret",
                    "rule": rule_id,
                    "secret_type": secret_type,
                    "file": path,
                    "line": line,
                    "severity_source": "securetask-default",
                    # Deliberately absent: there is no "secret" key here, and
                    # no code anywhere that would put one in.
                },
            )
        )

    return results, skipped
