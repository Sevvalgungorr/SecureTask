"""Reading source from disk, and the four things that must stop it.

This endpoint exists because a scanner's snippet cannot always place the line
it flagged. It is also the most dangerous thing in the application, because the
path it opens comes out of an uploaded SARIF — whoever writes the report writes
the path. Without these checks it is arbitrary file read with a feature's name
on it.

So most of this file is about refusing.
"""
import pytest

from app import config, source

FILE = "app/reports.py"
SNIPPET = (
    "def count_rows(db, table):\n"
    '    query = f"SELECT count(*) FROM {table}"\n'
    "    return db.execute(text(query)).scalar_one()\n"
)


@pytest.fixture()
def tree(tmp_path, monkeypatch):
    """A working tree with one real file in it."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "reports.py").write_text(
        "\n".join(
            [f"# line {n}" for n in range(1, 23)]
            + SNIPPET.rstrip("\n").split("\n")
            + [f"# line {n}" for n in range(26, 40)]
        )
    )
    # Things that must never be readable through this, sitting where a crafted
    # report would point.
    (tmp_path / ".env").write_text("SESSION_SECRET=hunter2\n")
    (tmp_path / "app" / "key.pem").write_text("-----BEGIN PRIVATE KEY-----\n")
    monkeypatch.setattr(config, "SOURCE_ROOT", str(tmp_path))
    monkeypatch.setattr(source, "SOURCE_ROOT", str(tmp_path))
    monkeypatch.setattr(source, "SOURCE_CONTEXT_LINES", 5)
    return tmp_path


# --- the gate that decides which file may be opened -------------------------


def test_a_traversing_path_is_refused(tree):
    """The path is written by whoever wrote the scan report."""
    for attack in (
        "../../../etc/passwd",
        "app/../../etc/passwd",
        "app/../.env",
        "....//....//etc/passwd",
    ):
        with pytest.raises(source.SourceUnavailable):
            source.safe_path(attack)


def test_an_absolute_path_is_refused(tree):
    for attack in ("/etc/passwd", "//etc/passwd", "C:/Windows/win.ini", "\\\\host\\share"):
        with pytest.raises(source.SourceUnavailable):
            source.safe_path(attack)


def test_a_symlink_out_of_the_tree_is_refused(tree):
    """Containment is checked *after* resolution, so a link that points out of
    the tree lands outside the root and fails there."""
    (tree / "app" / "escape.py").symlink_to("/etc/passwd")

    with pytest.raises(source.SourceUnavailable):
        source.safe_path("app/escape.py")


def test_only_source_extensions_are_opened(tree):
    """An allowlist, because a denylist would have to think of .env, .pem,
    .sqlite and whatever is invented next."""
    for path in (".env", "app/key.pem"):
        with pytest.raises(source.SourceUnavailable):
            source.safe_path(path)

    assert source.safe_path(FILE).name == "reports.py"


def test_nothing_is_readable_when_no_root_is_configured(tree, monkeypatch):
    """Unset means the feature does not exist — the right default for something
    that opens files."""
    monkeypatch.setattr(source, "SOURCE_ROOT", "")

    with pytest.raises(source.SourceUnavailable):
        source.safe_path(FILE)


# --- the gate that decides whether the file is evidence ---------------------


def test_a_window_is_returned_when_the_file_matches_the_report(tree):
    """23–25 is what the report carried; 24 is the flagged line. The window
    comes back centred on it, from the file."""
    window = source.window_for(FILE, 24, SNIPPET, 23)

    assert window["line"] == 24
    assert window["start_line"] == 19
    assert len(window["lines"]) == 11
    assert window["lines"][5] == '    query = f"SELECT count(*) FROM {table}"'


def test_a_line_outside_the_snippet_is_still_placed(tree):
    """The whole point: bandit can flag a line the snippet does not contain.
    The snippet still proves the file is the right version, and the window is
    then taken around the flagged line rather than around the snippet."""
    window = source.window_for(FILE, 30, SNIPPET, 23)

    assert window["line"] == 30
    assert window["start_line"] == 25
    assert window["lines"][5] == "# line 30"


def test_a_changed_file_returns_nothing(tree):
    """A file on disk is not evidence by itself. If the tree has moved on,
    line 24 is a different statement now, and highlighting it would be a
    confident lie — so the snippet is used as a checksum."""
    (tree / "app" / "reports.py").write_text("# everything changed\n" * 40)

    with pytest.raises(source.SourceUnavailable):
        source.window_for(FILE, 24, SNIPPET, 23)


def test_a_line_past_the_end_of_the_file_returns_nothing(tree):
    with pytest.raises(source.SourceUnavailable):
        source.window_for(FILE, 9999, SNIPPET, 23)


def test_no_snippet_means_no_proof_and_no_source(tree):
    """Without the report's own lines there is nothing to check the file
    against, so there is no way to know it is the version that was scanned."""
    with pytest.raises(source.SourceUnavailable):
        source.window_for(FILE, 24, "", 23)


def test_trailing_whitespace_does_not_break_the_match(tree):
    """Scanners differ on whether they keep the line ending. Nothing else is
    forgiven."""
    assert source.window_for(FILE, 24, SNIPPET.replace("\n", "  \n"), 23)


# --- through the endpoint ----------------------------------------------------


def _payload(**fields):
    payload = {
        "title": "String birleştirmeyle SQL sorgusu",
        "description": None,
        "asset": FILE,
        "severity": "medium",
        "status": "open",
        "due_date": None,
        "accepted_reason": None,
        "accepted_until": None,
    }
    payload.update(fields)
    return payload


def _finding_with_evidence(client, db, asset=FILE, line=24, start=23, snippet=SNIPPET):
    from app.models import Finding

    finding_id = client.post("/findings", json=_payload(asset=asset)).json()["id"]
    row = db.query(Finding).filter(Finding.id == finding_id).one()
    row.evidence, row.evidence_start, row.evidence_line = snippet, start, line
    db.commit()
    return finding_id


def test_the_endpoint_serves_the_window(client, tree):
    client.login_as("alice")
    finding_id = _finding_with_evidence(client, client.db)

    body = client.get(f"/findings/{finding_id}/source").json()

    assert body["line"] == 24
    assert body["path"] == FILE
    assert len(body["lines"]) == 11


def test_the_endpoint_names_no_path_of_its_own(client, tree):
    """The caller supplies an id. The path is the finding's, and the finding is
    already scoped to who may see it."""
    client.login_as("alice")
    finding_id = _finding_with_evidence(client, client.db, asset="../../.env")

    assert client.get(f"/findings/{finding_id}/source").status_code == 404


def test_someone_elses_finding_reads_nothing(client, tree):
    client.login_as("alice")
    finding_id = _finding_with_evidence(client, client.db)
    client.logout()
    client.login_as("mallory")

    assert client.get(f"/findings/{finding_id}/source").status_code == 404


def test_every_refusal_looks_the_same(client, tree, monkeypatch):
    """Missing, forbidden, out of tree and stale all answer 404 with one
    message. Telling them apart would make this a way to map the filesystem."""
    client.login_as("alice")
    seen = set()

    for asset in (FILE, "../../.env", "app/key.pem", "app/nope.py"):
        finding_id = _finding_with_evidence(client, client.db, asset=asset)
        if asset != FILE:
            res = client.get(f"/findings/{finding_id}/source")
            seen.add((res.status_code, res.json()["detail"]))

    assert len(seen) == 1

    # And with the tree gone, the readable one answers exactly the same way.
    monkeypatch.setattr(source, "SOURCE_ROOT", "")
    finding_id = _finding_with_evidence(client, client.db)
    res = client.get(f"/findings/{finding_id}/source")

    assert (res.status_code, res.json()["detail"]) in seen
