"""Running an analyser over a registered project.

This is the one place in the application that starts a process, so it is worth
being precise about what it does and does not do.

**It does not run the code being analysed.** Bandit parses Python into an
abstract syntax tree and inspects the tree. Gitleaks reads files as text.
pip-audit reads a list of names and versions. Nothing under the project
directory is imported or executed, which is the difference between this and
cloning a repository to build it — the thing this application has always
refused. For the dependency audit that refusal has a specific name: see
`--no-deps` and `--disable-pip` below, without which the audit would build the
packages it is auditing.

**It does not take a path from anyone.** The caller names a project; the path
comes from `SCAN_PROJECTS` in configuration. There is no traversal to attempt
because there is no path in the request to traverse, which is a stronger
position than validating one. Unregistered names are refused, and the directory
is still resolved and checked, so a configuration entry pointing at a symlink
that moved cannot quietly escape.

**It does not build a command line.** The arguments are a list and there is no
shell, so quoting, metacharacters and word-splitting are not concepts that
apply here. A project name that happens to contain `; rm -rf /` is a name that
is not in the registry.

**It parses as little as possible.** Bandit emits SARIF, which this application
already read, and nuclei's JSONL was already understood — neither needed a
reader. The output goes into the same importer as an uploaded report, with the
same deduplication and the same rule that a scan may not overwrite a judgement.

The two newer scanners did need readers, and both for a reason:

* pip-audit, because its output carries **what it examined** as well as what it
  found. A package with no vulnerabilities produces no result, so a clean
  re-scan can only close a finding if the coverage is read rather than guessed.
* gitleaks, because its output carries **live credentials**. It is asked to
  redact them (`--redact`), so the value is replaced inside the scanner and
  never crosses into this process — and the reader masks again and refuses any
  line it could not clean. Its SARIF would have been less code and a secret in
  the database.
"""
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.config import (  # noqa: F401
    DAST_CONCURRENCY,
    DAST_RATE_LIMIT,
    DAST_TARGETS,
    DAST_TIMEOUT_SECONDS,
    SCA_TIMEOUT_SECONDS,
    SCAN_MAX_OUTPUT,
    SCAN_PROJECTS,
    SCAN_TIMEOUT_SECONDS,
)

# Four things a scan can be about, kept apart by name rather than by a boolean
# because the consequences differ:
#
#   sast    reads the code the team wrote
#   sca     reads the manifest of code the team installed
#   secret  reads the code looking for credentials that should not be in it
#   dast    sends live traffic at something that is running
#
# The first three open files. Only the last one touches another system.
SAST = "sast"
SCA = "sca"
SECRET = "secret"
DAST = "dast"

# Which analysers this installation knows how to run. One for now; the shape is
# here so a second is a table entry rather than a rewrite, and no further
# abstraction is invented before there is a second thing to abstract over.
#
# `args` receives the resolved project directory and must produce a complete
# argv — a list, never a string.
# Directories that are in a project tree but are not the project: installed
# dependencies, version control, build output, caches. Scanning them produces
# findings in code the team does not own and cannot fix, which buries the ones
# they can — and on this repository it also crashed bandit's SARIF writer
# outright ("list index out of range" on a file inside .venv).
VENDOR_DIRS = (
    ".venv", "venv", "env", ".git", "node_modules", ".tox", ".nox",
    "build", "dist", ".mypy_cache", ".pytest_cache", "__pycache__",
    "site-packages", ".eggs",
)

# The same exclusions, expressed the way gitleaks accepts them. Ships with the
# application rather than being read from the project: a scanned tree does not
# get to relax the configuration of the scanner pointed at it.
GITLEAKS_CONFIG = Path(__file__).parent / "scanners" / "gitleaks.toml"

# Dependency lists this application knows how to read, in the order they are
# looked for. A fixed tuple, not a pattern and not a request parameter: naming
# the file is naming a path, and there is no path in a request here.
MANIFESTS = ("requirements.txt", "requirements-dev.txt")

# `name==version`, optionally with extras and an environment marker. Anything
# else — a range, a URL, an editable install, an `-r` include — is not a pinned
# dependency and cannot be audited without resolving it, which is the one thing
# this scanner will not do.
PINNED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?==[^\s;#]+")

# What to type when a scanner is missing. Not every one of these is a Python
# package, and telling someone to `pip install gitleaks` sends them to a name
# that is not the tool.
INSTALL_HINT = {
    "bandit": "pip install bandit",
    "pip-audit": "pip install pip-audit",
    "gitleaks": "https://github.com/gitleaks/gitleaks — tek bir ikili dosya",
    "nuclei": "https://github.com/projectdiscovery/nuclei",
}


SCANNERS: dict[str, dict] = {
    "bandit": {
        "label": "Bandit",
        "binary": "bandit",
        # "." with cwd set to the project, not an absolute path: bandit writes
        # whatever it was given into the report, and an absolute one would put
        # the server's filesystem layout into every finding's asset name. It
        # would also stop these deduplicating against the same file from an
        # uploaded report, and leave the code viewer with a path it cannot
        # resolve under SOURCE_ROOT.
        "args": lambda target: [
            "-r", ".",
            "-f", "sarif",
            "--exclude", ",".join(f"./{d}" for d in VENDOR_DIRS),
            # Assert statements in tests are the overwhelming majority of what
            # bandit reports on a project with a test suite, and they are not
            # findings anyone acts on. Excluded so the list stays about the
            # application rather than about pytest.
            "--skip", "B101",
            "-q",
        ],
        # Bandit exits 1 when it *finds* something. That is a successful run
        # with results, not a failure — treating it as one would mean the
        # scanner only "worked" when the code was clean.
        "ok_returncodes": (0, 1),
        "kind": SAST,
    },
    "pip-audit": {
        "label": "pip-audit",
        "binary": "pip-audit",
        "kind": SCA,
        # `manifest` says: this scanner is given a dependency list rather than
        # a directory, and the list is built by _pinned_manifest() below.
        "manifest": True,
        # Three flags, and two of them are refusals.
        #
        # `--no-deps` stops pip-audit resolving the dependency graph, and
        # `--disable-pip` stops it using pip to do so. Left on, resolution
        # downloads and builds source distributions — which runs setup.py from
        # every package in the tree. An audit that executes the code it is
        # auditing is not an audit, and it is exactly the thing this
        # application has refused since it declined to clone repositories.
        #
        # What is left reads a list of names and versions and asks a
        # vulnerability service about them. Nothing is installed, imported or
        # executed; the packages themselves are never fetched.
        "args": lambda manifest: [
            "-r", str(manifest),
            "--no-deps",
            "--disable-pip",
            "-f", "json",
            "--progress-spinner", "off",
        ],
        # 1 means vulnerabilities were found. Same as bandit: a successful run
        # with results, not a failure.
        "ok_returncodes": (0, 1),
    },
    "gitleaks": {
        "label": "Gitleaks",
        "binary": "gitleaks",
        "kind": SECRET,
        # `--redact` is the single most important flag in this file.
        #
        # Without it, gitleaks writes the credential it found into its report,
        # and this application would then be holding a live secret in a
        # subprocess pipe, a parser, a database row and a screenshot. With it,
        # the value is replaced *inside gitleaks* before the report is written
        # — so the raw secret never crosses into this process at all.
        #
        # Everything else this application does about secret handling is a
        # second layer over that one. The parser masks again; the code viewer
        # is refused the file; the model is given the finding without it. But
        # the guarantee starts here, with the value not being sent.
        #
        # JSON rather than SARIF, deliberately: gitleaks' SARIF puts the match
        # in `snippet`, and the SARIF reader copies snippets into evidence.
        "args": lambda target: [
            "dir", ".",
            "--config", str(GITLEAKS_CONFIG),
            "--report-format", "json",
            # gitleaks writes its report to a file. Its logs go to stderr, so
            # stdout carries the report and nothing else.
            "--report-path", "/dev/stdout",
            "--no-banner",
            "--redact",
        ],
        # 1 means leaks were found.
        "ok_returncodes": (0, 1),
        # A project with no secrets in it is a successful scan with no results,
        # and the commonest outcome anyone should hope for.
        "empty_ok": True,
    },
    "nuclei": {
        "label": "Nuclei",
        "binary": "nuclei",
        "kind": DAST,
        # Every flag here is a restriction, and each one is load-bearing.
        #
        # `-no-interactsh` is the one people miss: by default nuclei uses a
        # **public** out-of-band server to detect blind vulnerabilities, which
        # means it tells a third party what it is scanning. On an internal
        # staging system that is a disclosure nobody asked for.
        #
        # `-duc` stops it phoning home for template updates mid-scan, so a run
        # is reproducible and makes no connection the operator did not expect.
        "args": lambda target: [
            "-target", str(target),
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-no-interactsh",
            "-disable-redirects",
            # Templates that change state or hammer the target. This is a
            # check, not a pentest — and the line between them is exactly here.
            "-exclude-tags", "intrusive,dos,fuzz,brute-force,sqli-error",
            "-rate-limit", str(DAST_RATE_LIMIT),
            "-concurrency", str(DAST_CONCURRENCY),
            "-timeout", "10",
            "-retries", "1",
        ],
        # nuclei exits 0 whether or not it found anything.
        "ok_returncodes": (0,),
        # Findings are what it printed, not whether it printed any: a clean
        # target is a successful scan with no results.
        "empty_ok": True,
    },
}


def of_kind(kind: str) -> frozenset:
    """The scanner names registered under one kind.

    Used to answer "is this finding a leaked credential" from the finding's
    `source` alone — which is a stored string and survives the scanner being
    reconfigured, unlike asking the table at read time for something else.
    """
    return frozenset(
        key for key, spec in SCANNERS.items() if spec.get("kind", SAST) == kind
    )


def targets() -> list[dict]:
    """Running applications this installation may scan.

    The URL is shown because an operator picking a target needs to know which
    system a name means. It is configuration, not a secret — and nothing in a
    request can name a different one.
    """
    return [
        {"name": name, "url": url}
        for name, url in sorted(DAST_TARGETS.items())
    ]


class ScanRefused(Exception):
    """The scan was not started, and the caller is told why in plain words."""


class ScannerMissing(ScanRefused):
    """The analyser is not installed on this machine.

    Its own class because it is its own outcome, not a kind of failure. "Run
    `pip install pip-audit`" is a sentence somebody can act on in a minute,
    and it deserves to be told apart from a scanner that ran and broke.
    """


class ScanFailed(Exception):
    """The scanner ran and did not produce a usable report."""


@dataclass(frozen=True)
class ScanResult:
    scanner: str
    project: str
    sarif: str
    duration: float
    # Something true about the run that is not an error. A dependency audit
    # that silently examined 20 of 24 requirements is worse than one that
    # refused: the operator reads "no vulnerabilities" and believes it.
    note: str = ""


def find_binary(name: str) -> str | None:
    """Locate an analyser, looking beside this interpreter first.

    A tool installed into the same virtual environment as the application sits
    next to `sys.executable` and is usually *not* on PATH — the venv is only on
    PATH for a shell that activated it, and a service started by a supervisor
    has no such shell. Checking there first is the difference between "Bandit
    is not installed" and "Bandit is installed and I could not see it", which
    is a confusing thing to tell someone who just installed it.
    """
    local = Path(sys.executable).parent / name

    if local.is_file():
        return str(local)

    return shutil.which(name)


def projects() -> list[dict]:
    """What may be scanned, for the interface to offer.

    Paths are included because an operator choosing between projects needs to
    know which directory each name means; they are configuration rather than
    secrets, and nothing here can be used to name a different one.
    """
    return [
        {"name": name, "path": path, "available": Path(path).expanduser().is_dir()}
        for name, path in sorted(SCAN_PROJECTS.items())
    ]


def scanners() -> list[dict]:
    return [
        {
            "key": key,
            "label": spec["label"],
            "kind": spec.get("kind", SAST),
            # Whether the binary is actually on this machine. Offering a
            # scanner that is not installed produces a failure the user cannot
            # act on; saying so up front produces one they can.
            "installed": find_binary(spec["binary"]) is not None,
        }
        for key, spec in sorted(SCANNERS.items())
    ]


def _target(project: str) -> Path:
    if not SCAN_PROJECTS:
        raise ScanRefused("Bu kurulumda taranabilir proje tanımlı değil.")

    raw = SCAN_PROJECTS.get(project)

    if not raw:
        # The name is not echoed back. It came from a request, and reflecting
        # unknown input into an error message is how error messages become a
        # way to probe what exists.
        raise ScanRefused("Böyle bir proje tanımlı değil.")

    path = Path(raw).expanduser().resolve()

    if not path.is_dir():
        raise ScanRefused("Projenin dizini bulunamadı.")

    return path


def _dast_target(name: str) -> str:
    """Resolve a target name to its configured URL, or refuse.

    The URL never comes from the request. A caller that could send one would be
    pointing this application's scanner at anything it can reach — the SSRF the
    monitor already refuses, with a louder voice.
    """
    if not DAST_TARGETS:
        raise ScanRefused("Bu kurulumda taranabilir hedef tanımlı değil.")

    url = DAST_TARGETS.get(name)

    if not url:
        # Not echoed back: reflecting unknown input into an error is how error
        # messages become a way to probe what exists.
        raise ScanRefused("Böyle bir hedef tanımlı değil.")

    return url


def _pinned_manifest(project: Path) -> tuple[str, int, int]:
    """A dependency list containing only what can be audited without resolving.

    Returns the text, how many requirements it holds, and how many lines were
    left out.

    pip-audit's `--no-deps` mode refuses a manifest outright if a single
    requirement is not pinned to an exact version, and a real project has at
    least one `>=`. Refusing the whole audit over that would mean the feature
    never runs; auditing the unpinned line would mean resolving it, which means
    downloading and building packages. So the pinned requirements are audited,
    and **how many were left out is reported** rather than quietly dropped —
    otherwise "no vulnerabilities" would be a claim about a list the operator
    thinks is longer than it is.

    Nothing here comes from a request. The directory came from the registry and
    the filenames are the fixed tuple above.
    """
    kept: list[str] = []
    skipped = 0

    for name in MANIFESTS:
        path = project / name

        if not path.is_file():
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        kept.append(f"# {name}")

        for line in text.splitlines():
            stripped = line.strip()

            # Blank lines, comments and pip's own option lines are not
            # requirements and are not counted as skipped ones.
            if not stripped or stripped.startswith(("#", "-", "--")):
                continue

            if PINNED.match(stripped):
                kept.append(stripped)
            else:
                skipped += 1

    # The header lines are not requirements.
    count = len([line for line in kept if not line.startswith("#")])

    return "\n".join(kept) + "\n", count, skipped


def run(project: str, scanner: str = "bandit") -> ScanResult:
    """Run the analyser and return its report. Raises rather than returning junk."""
    spec = SCANNERS.get(scanner)

    if spec is None:
        raise ScanRefused("Böyle bir tarayıcı tanımlı değil.")

    binary = find_binary(spec["binary"])

    if binary is None:
        raise ScannerMissing(
            f"{spec['label']} bu makinede kurulu değil. "
            f"Kurulum: {INSTALL_HINT.get(scanner, 'pip install ' + spec['binary'])}"
        )

    kind = spec.get("kind", SAST)
    # A project name resolves to a directory; a target name resolves to a URL.
    # Both come from configuration and neither is ever read from a request.
    target = _dast_target(project) if kind == DAST else _target(project)
    note = ""
    manifest = None

    if spec.get("manifest"):
        text, count, dropped = _pinned_manifest(target)

        if not count:
            raise ScanRefused(
                "Bu projede okunabilir bir bağımlılık listesi yok "
                "(requirements.txt içinde sabitlenmiş sürüm bulunamadı)."
            )

        if dropped:
            note = (
                f"{dropped} bağımlılık satırı sabit sürüm belirtmediği için "
                f"denetlenmedi; {count} satır denetlendi."
            )

        # Written by this process, in a directory this process owns, from lines
        # this process filtered. The scanned project is never handed the
        # scanner's own arguments.
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="securetask-sca-",
            encoding="utf-8", delete=False,
        )

        with handle:
            handle.write(text)

        manifest = Path(handle.name)

    # A list, and shell=False by omission. There is no command line to inject
    # into because there is no command line — the arguments are passed to the
    # operating system as they are.
    argv = [binary, *spec["args"](manifest if manifest else target)]
    timeout = (
        DAST_TIMEOUT_SECONDS if kind == DAST
        else SCA_TIMEOUT_SECONDS if kind == SCA
        else SCAN_TIMEOUT_SECONDS
    )

    try:
        completed = subprocess.run(          # noqa: S603 - argv list, no shell
            argv,
            capture_output=True,
            text=True,
            # The analyser has no reason to read stdin, and leaving it open is
            # how a process waits forever on a machine nobody is watching.
            stdin=subprocess.DEVNULL,
            # A URL is not a working directory. For a dynamic scan there is
            # nothing local to sit in.
            cwd=str(target) if kind != DAST else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanFailed(f"Tarama {timeout:.0f} saniyede bitmedi.") from exc
    except OSError as exc:
        raise ScanFailed("Tarayıcı çalıştırılamadı.") from exc
    finally:
        if manifest is not None:
            manifest.unlink(missing_ok=True)

    if completed.returncode not in spec["ok_returncodes"]:
        # The scanner's own stderr is the useful part — "no such option",
        # "syntax error in file" — but it is another program's output, so it is
        # trimmed and passed through as text rather than interpreted.
        detail = (completed.stderr or "").strip().splitlines()
        tail = detail[-1][:200] if detail else "çıktı yok"
        raise ScanFailed(f"{spec['label']} hata verdi ({completed.returncode}): {tail}")

    sarif = completed.stdout or ""

    if len(sarif) > SCAN_MAX_OUTPUT:
        raise ScanFailed("Tarama çıktısı beklenenden büyük; içe aktarılmadı.")

    if not sarif.strip() and not spec.get("empty_ok"):
        raise ScanFailed(f"{spec['label']} boş bir rapor döndürdü.")

    return ScanResult(
        scanner=scanner, project=project, sarif=sarif, duration=0.0, note=note,
    )
