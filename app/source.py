"""Reading a window of source from a working tree, when there is one.

A scanner reports a file and a line. The snippet it ships is sometimes enough
to show that line in context and sometimes not: bandit reports a multi-line
call with `region` at the call's first line and `contextRegion` around the
offending argument, and the two do not nest — so the line to highlight can sit
outside the block that came with the report.

The fix is to read the file. That is also the dangerous part, because the path
comes out of an uploaded SARIF: whoever writes the report writes the path. A
naive implementation is arbitrary file read with a feature's name on it, and
`../../.env` would be answered politely.

Four gates, and the last one is the one that matters most:

1. **A root, configured here and nowhere else.** Unset means the feature does
   not exist. Nothing in a request can name or influence it.
2. **Containment after resolution.** The candidate is resolved — following
   symlinks — and must still sit inside the resolved root. `..`, absolute
   paths, and a symlink pointing out of the tree all fail the same check.
3. **An extension allowlist.** Source files, and only those. A denylist would
   have to think of `.env`, `.pem`, `.key`, `.sqlite`, and whatever is invented
   next; an allowlist only has to be right about what source code looks like.
4. **Proof that the file is the code the scanner read.** A file on disk is not
   evidence of anything by itself — the tree may have moved on, and line 176 of
   today's file may be a different statement. So the snippet that came with the
   report is used as a checksum: if the file's lines at the reported offsets do
   not match it byte for byte, this is not the version that was scanned and
   nothing is returned. That is what keeps the highlight honest rather than
   plausible.
"""
from pathlib import Path

from app.config import SOURCE_CONTEXT_LINES, SOURCE_ROOT

# Source files, and only source files. The window returned is small, but the
# check that decides *which* file may be opened has to be the strict one.
ALLOWED_SUFFIXES = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rb",
    ".php", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".swift", ".scala",
    ".sh", ".bash", ".sql", ".html", ".css", ".scss", ".vue", ".tf", ".yml",
    ".yaml", ".toml", ".gradle", ".groovy", ".pl", ".lua", ".m", ".mm",
})

# A source file is text. Past this the thing being opened is not what this
# feature is for, and reading it would only be a way to spend memory.
MAX_BYTES = 2_000_000


class SourceUnavailable(Exception):
    """No source could be returned, for a reason the caller need not act on.

    Deliberately one exception for every cause. "Outside the root", "wrong
    extension" and "does not exist" are the same answer to the caller — and
    distinguishing them in a response would turn this endpoint into a way to
    map the filesystem.
    """


def _resolved_root() -> Path:
    if not SOURCE_ROOT:
        raise SourceUnavailable("Kaynak kök dizini yapılandırılmamış.")

    root = Path(SOURCE_ROOT).expanduser().resolve()

    if not root.is_dir():
        raise SourceUnavailable("Kaynak kök dizini bulunamadı.")

    return root


def safe_path(relative: str) -> Path:
    """Resolve `relative` under the configured root, or refuse.

    Refusing is the normal outcome for anything surprising; the caller learns
    only that there is no source.
    """
    root = _resolved_root()
    candidate = (relative or "").strip()

    if not candidate:
        raise SourceUnavailable("Dosya yolu yok.")

    # An absolute path would escape the join outright, and a Windows-style
    # drive or UNC prefix does the same on the platforms that honour it.
    if candidate.startswith(("/", "\\")) or ":" in candidate[:3]:
        raise SourceUnavailable("Mutlak yol kabul edilmiyor.")

    # Some scanners prefix the URI scheme; the rest of the path is still
    # relative to the tree that was scanned.
    if candidate.startswith("file://"):
        candidate = candidate[len("file://"):].lstrip("/")

    # resolve() follows symlinks, so a link inside the tree that points out of
    # it lands outside the root and is caught by the containment check below —
    # which is why the check comes after resolution, not before.
    target = (root / candidate).resolve()

    if not target.is_relative_to(root):
        raise SourceUnavailable("Kök dizinin dışında.")

    if target.suffix.lower() not in ALLOWED_SUFFIXES:
        raise SourceUnavailable("Bu dosya türü okunmuyor.")

    if not target.is_file():
        raise SourceUnavailable("Dosya bulunamadı.")

    if target.stat().st_size > MAX_BYTES:
        raise SourceUnavailable("Dosya çok büyük.")

    return target


def _read_lines(path: Path) -> list[str]:
    # errors="replace" rather than failing: a file with one bad byte should
    # still show its other lines, and the replacement character is visible.
    text = path.read_text(encoding="utf-8", errors="replace")
    return text.split("\n")


def matches_report(lines: list[str], start_line: int, snippet: str) -> bool:
    """Is this file the version the scanner read?

    The snippet the report carried is the only evidence available, so it is
    used as a checksum: it has to appear at exactly the offsets the report gave
    it. Trailing whitespace is ignored because scanners differ on whether they
    keep the line ending; nothing else is.
    """
    if not snippet or not start_line or start_line < 1:
        return False

    expected = snippet.replace("\r\n", "\n").rstrip("\n").split("\n")
    actual = lines[start_line - 1: start_line - 1 + len(expected)]

    if len(actual) != len(expected):
        return False

    return all(a.rstrip() == b.rstrip() for a, b in zip(actual, expected))


def window_for(relative: str, line: int, snippet: str, snippet_start: int) -> dict:
    """A window of source centred on `line`, if the file can be trusted.

    Raises SourceUnavailable unless every gate passes — including the one that
    says this file is the code the scanner actually read.
    """
    if not line or line < 1:
        raise SourceUnavailable("Satır numarası yok.")

    path = safe_path(relative)
    lines = _read_lines(path)

    if line > len(lines):
        # The file is shorter than the reported line: whatever this is, it is
        # not the version that was scanned.
        raise SourceUnavailable("Satır dosyanın dışında.")

    if not matches_report(lines, snippet_start, snippet):
        raise SourceUnavailable("Dosya, raporun gördüğü sürümle eşleşmiyor.")

    start = max(1, line - SOURCE_CONTEXT_LINES)
    end = min(len(lines), line + SOURCE_CONTEXT_LINES)

    return {
        # Echoed from the finding, not from the request: the caller never names
        # a path, and this is the same value it already had.
        "path": relative,
        "start_line": start,
        "line": line,
        "lines": lines[start - 1:end],
    }
