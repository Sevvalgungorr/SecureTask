"""Retrieval: what reaches the model, and what must not be invented.

The value of this layer is entirely in being right about *which* passage. A
retriever that returns something for every finding looks like it works and
quietly makes every analysis worse, because a model handed an unrelated
passage writes about the passage.

So most of this is about not retrieving.
"""
import pytest

from app import knowledge


class FakeFinding:
    """Only the fields retrieval is allowed to read."""

    def __init__(self, title="", description="", source_ref="", asset=""):
        self.title = title
        self.description = description
        self.source_ref = source_ref
        self.asset = asset


def keys(chunks):
    return [c.key for c in chunks]


# --- finding the right thing -------------------------------------------------


def test_a_scanner_rule_id_finds_its_weakness(client):
    """B608 is bandit saying "this is SQL injection". An exact rule id is the
    strongest signal available, because the tool that said it read the code."""
    chunks = knowledge.retrieve(FakeFinding(
        title="Possible SQL injection vector through string-based query construction",
        source_ref="B608",
    ))

    assert "CWE:CWE-89" in keys(chunks)


def test_a_cwe_written_in_the_finding_is_used(client):
    chunks = knowledge.retrieve(FakeFinding(
        title="Deserialization issue", description="See CWE-502 for background."
    ))

    assert "CWE:CWE-502" in keys(chunks)


def test_the_owasp_category_comes_with_the_weakness(client):
    """The answer has an OWASP field, so the class travels with the specific
    weakness — but only ever a category a retrieved CWE actually names."""
    chunks = knowledge.retrieve(FakeFinding(title="SQL injection", source_ref="B608"))

    assert "OWASP:A03" in keys(chunks)


def test_hardcoded_credentials_are_recognised(client):
    chunks = knowledge.retrieve(FakeFinding(
        title="Possible hardcoded password: 'google-secret'", source_ref="B106",
    ))

    assert any(k.startswith("CWE:CWE-798") or k.startswith("CWE:CWE-312") for k in keys(chunks))


# --- and not the wrong thing -------------------------------------------------


def test_an_unrelated_finding_retrieves_nothing(client):
    """Returning nothing is a valid answer. Handing over an adjacent passage
    does not merely fail to help — it pulls the analysis toward whatever that
    passage happens to describe."""
    chunks = knowledge.retrieve(FakeFinding(
        title="Toplantı notlarını güncelle", description="Cuma sunumu için."
    ))

    assert chunks == []


def test_a_single_common_word_is_not_enough(client):
    """"value" appears in several entries. One weak term must not drag one in."""
    chunks = knowledge.retrieve(FakeFinding(title="Update the default value"))

    assert chunks == []


def test_sql_injection_does_not_pull_in_weak_crypto(client):
    chunks = knowledge.retrieve(FakeFinding(title="SQL injection", source_ref="B608"))

    assert "CWE:CWE-327" not in keys(chunks)
    assert "CWE:CWE-330" not in keys(chunks)


def test_only_a_few_chunks_ever_travel(client):
    """The whole corpus would bury the finding it is supposed to be about."""
    chunks = knowledge.retrieve(FakeFinding(
        title="sql injection command shell xss password certificate random pickle path",
        source_ref="B608",
    ))

    assert len(chunks) <= knowledge.MAX_CHUNKS + 1   # + the CWE's own OWASP class


def test_the_best_match_comes_first(client):
    chunks = knowledge.retrieve(FakeFinding(
        title="Possible SQL injection", source_ref="B608",
    ))

    assert chunks[0].key == "CWE:CWE-89"


# --- citations point at something real ---------------------------------------


def test_a_citation_resolves_to_the_passage_it_names(client):
    chunk = knowledge.by_key("CWE:CWE-89")

    assert chunk is not None
    assert chunk.title == "SQL Injection"
    assert chunk.reference.startswith("https://cwe.mitre.org/")


def test_an_identifier_that_no_longer_exists_resolves_to_nothing(client):
    """Passages live in one place so a correction reaches every analysis that
    cited one. The other side of that: an analysis citing something since
    removed shows no citation rather than a dangling one."""
    assert knowledge.by_key("CWE:CWE-99999") is None
    assert knowledge.by_key("MADE-UP:X") is None
    assert knowledge.by_key("") is None


def test_every_entry_carries_the_provenance_to_cite_it(client):
    """A passage without an identifier, a title and a reference is not a source
    — it is an unattributed claim, which is the thing this exists to avoid."""
    for entry in knowledge._ENTRIES:
        assert entry.get("id"), entry
        assert entry.get("title"), entry
        assert entry.get("text"), entry
        assert entry.get("reference", "").startswith("https://"), entry
