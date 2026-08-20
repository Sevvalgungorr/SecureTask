"""The security knowledge a finding is analysed against, and how it is found.

A model asked to rate a finding answers from whatever it absorbed in training.
That is fine for the shape of an answer and unreliable for the details — which
CWE this is, what actually fixes it, whether the OWASP category is A03 or A01.
Those are facts with sources, so they are looked up and handed over rather than
recalled.

**The knowledge is data, not code.** It lives in `app/knowledge/*.json` so it
can grow, be reviewed as content, and be diffed like content. Hundreds of
security paragraphs scattered through modules as string literals would be
unreadable and unmaintainable, and nobody would ever correct one.

**Retrieval is lexical, deliberately.** Embeddings and a vector store would be
the right answer for a large or open-ended corpus; this corpus is a few dozen
curated entries keyed by identifiers the scanners already emit. A rule id like
`B608` maps to CWE-89 exactly, and nothing an embedding does improves on
"exact". Adding a vector database here would buy nothing but a dependency and
the word "RAG". The seam is `retrieve()`: it takes a finding and returns
ranked chunks, so a different implementation can replace the scoring without
anything above it noticing.

**What comes back is reference material, not instruction.** It is fenced in the
prompt the same way the finding is, and for the same reason: today the corpus
is ours, but internal guides are meant to be added later, and text that arrives
from somewhere else must never be able to give the model orders.
"""
import json
import re
from dataclasses import dataclass
from pathlib import Path

_DIR = Path(__file__).parent / "knowledge"

# Bumped when the corpus changes in a way that would change an analysis. Stored
# with each analysis so a reader can tell which body of knowledge produced it,
# and so a future cache can tell a stale answer from a current one.
KB_VERSION = "2026-08-20.1"

# How many chunks reach the prompt. Small on purpose: the whole corpus would
# bury the finding, and a model given ten loosely related passages writes about
# the passages instead of the code in front of it.
MAX_CHUNKS = 3

# Below this, a chunk is not related enough to be worth the context. Returning
# nothing is a valid answer — better than handing over an entry about weak
# random numbers because it happened to share the word "value".
MIN_SCORE = 2.0

# En iyi eşleşmenin bu oranının altındaki parçalar atılıyor. Kesin bir kural
# kimliği eşleştiğinde skor 10'un üzerine çıkıyor; 3 puanlık bir kelime
# çakışması o cevabın yanında durmayı hak etmiyor.
RELATIVE_CUTOFF = 0.45


@dataclass(frozen=True)
class Chunk:
    """One retrieved passage, with the provenance to cite it."""

    source: str          # "CWE" | "OWASP"
    id: str              # "CWE-89" | "A03"
    title: str
    text: str
    reference: str
    score: float

    @property
    def key(self) -> str:
        return f"{self.source}:{self.id}"


def _load() -> list[dict]:
    entries = []

    for path in sorted(_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A corpus file that will not parse is a deployment problem, not a
            # reason to take the analysis feature down with it.
            continue

        for entry in data.get("entries", []):
            entries.append({**entry, "source": data.get("source", path.stem.upper())})

    return entries


# Read once. The corpus is a handful of files that ship with the application
# and do not change while it runs.
_ENTRIES = _load()


def _terms(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) > 2}


def _identifiers(text: str) -> set[str]:
    """CWE ids and OWASP category codes appearing literally in the text."""
    found = {m.upper() for m in re.findall(r"cwe[-_ ]?(\d+)", text or "", re.I)}
    ids = {f"CWE-{n}" for n in found}
    ids |= {m.upper() for m in re.findall(r"\bA0?([1-9]|10)\b(?=\s*[:.]|\s+\w)", text or "")}
    return ids


def _query_of(finding) -> tuple[str, set[str]]:
    """What this finding is about, as text and as identifiers.

    Every field here is one the finding already has. Notably absent is the CWE
    from a previous analysis: retrieval runs *before* the model, so the CWE it
    will produce cannot be an input to finding the knowledge that produces it.
    The scanner's rule id fills that gap — `B608` is an exact statement that
    this is SQL injection, made by the tool that read the code.
    """
    parts = [
        getattr(finding, "title", "") or "",
        getattr(finding, "description", "") or "",
        getattr(finding, "source_ref", "") or "",
        getattr(finding, "asset", "") or "",
    ]
    text = " ".join(parts)
    return text, _identifiers(text)


def _score(entry: dict, terms: set[str], ids: set[str], rule: str) -> float:
    score = 0.0

    # An exact rule id from the scanner is the strongest signal available: the
    # tool that read the code said which weakness this is.
    rules = [r.lower() for r in entry.get("rules", [])]
    rule_l = (rule or "").lower()

    if rule_l and rule_l in rules:
        score += 10.0
    elif rule_l and any(r in rule_l or rule_l in r for r in rules if r):
        score += 6.0

    # An identifier written in the finding text itself.
    if entry.get("id", "").upper() in ids:
        score += 8.0

    # Keyword overlap. Multi-word keywords count for more because they are
    # much less likely to match by accident than a single common word.
    for keyword in entry.get("keywords", []):
        k = keyword.lower()
        if " " in k:
            if k in " ".join(sorted(terms)) or all(w in terms for w in k.split()):
                score += 2.5
        elif k in terms:
            score += 1.5

    return score


def retrieve(finding, limit: int = MAX_CHUNKS) -> list[Chunk]:
    """The most relevant passages for this finding, or an empty list.

    Empty is a normal outcome. A finding this corpus has nothing useful to say
    about should be analysed without it rather than with something adjacent —
    irrelevant context does not merely fail to help, it pulls the answer toward
    whatever it happens to describe.
    """
    text, ids = _query_of(finding)
    terms = _terms(text)
    rule = getattr(finding, "source_ref", "") or ""

    scored = []

    for entry in _ENTRIES:
        score = _score(entry, terms, ids, rule)

        if score >= MIN_SCORE:
            scored.append((score, entry))

    scored.sort(key=lambda pair: (-pair[0], pair[1].get("id", "")))

    # Mutlak eşik tek başına yetmiyor. "injection" gibi bir kelime birden çok
    # sınıfta geçiyor, ve bir SQL enjeksiyonu bulgusuna log enjeksiyonu
    # pasajını da vermek analizi oraya çekiyor. En iyi eşleşmenin çok altında
    # kalan bir parça, ilgili değil — yalnızca aynı kelimeyi paylaşıyor.
    if scored:
        floor = max(MIN_SCORE, scored[0][0] * RELATIVE_CUTOFF)
        scored = [pair for pair in scored if pair[0] >= floor]
    chunks = [
        Chunk(
            source=entry["source"],
            id=entry.get("id", ""),
            title=entry.get("title", ""),
            text=entry.get("text", ""),
            reference=entry.get("reference", ""),
            score=score,
        )
        for score, entry in scored[:limit]
    ]

    # A CWE entry names its OWASP category; pulling that in gives the model the
    # class as well as the specific weakness, which is what the OWASP field in
    # the answer is asking for. Only ever added alongside a CWE that was
    # actually retrieved — never on its own guess.
    owasp_ids = {
        entry.get("owasp")
        for _, entry in scored[:limit]
        if entry.get("source") == "CWE" and entry.get("owasp")
    }
    have = {c.id for c in chunks}

    for entry in _ENTRIES:
        if entry.get("source") == "OWASP" and entry.get("id") in owasp_ids - have:
            chunks.append(Chunk(
                source=entry["source"], id=entry["id"], title=entry.get("title", ""),
                text=entry.get("text", ""), reference=entry.get("reference", ""),
                score=0.0,
            ))

    return chunks


def by_key(key: str) -> Chunk | None:
    """Look a stored citation back up in the current corpus.

    Analyses store identifiers, not text: the passage lives in one place, so
    correcting it corrects every analysis that cited it. An identifier that no
    longer exists returns None and is simply dropped — a citation is only shown
    while the thing it points at is still there.
    """
    source, _, ident = (key or "").partition(":")

    for entry in _ENTRIES:
        if entry.get("source") == source and entry.get("id") == ident:
            return Chunk(
                source=source, id=ident, title=entry.get("title", ""),
                text=entry.get("text", ""), reference=entry.get("reference", ""),
                score=0.0,
            )

    return None
