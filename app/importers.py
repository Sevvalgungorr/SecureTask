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
