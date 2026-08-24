"""Running a static analyser over a registered project.

This is the one place in the application that starts a process, so it is worth
being precise about what it does and does not do.

**It does not run the code being analysed.** Bandit parses Python into an
abstract syntax tree and inspects the tree. Nothing under the project directory
is imported or executed, which is the difference between this and cloning a
repository to build it — the thing this application has always refused.

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

**It does not parse anything new.** Bandit emits SARIF, which this application
already reads — the output goes into the same importer as an uploaded report,
with the same deduplication and the same rule that a scan may not overwrite a
judgement.
"""
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from app.config import (  # noqa: F401
    DAST_CONCURRENCY,
    DAST_RATE_LIMIT,
    DAST_TARGETS,
    DAST_TIMEOUT_SECONDS,
    SCAN_MAX_OUTPUT,
    SCAN_PROJECTS,
    SCAN_TIMEOUT_SECONDS,
)

# Static analysis reads files; dynamic analysis sends live traffic at something
# that is running. They are different enough in consequence that the code keeps
# them apart by name rather than by a boolean.
SAST = "sast"
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


class ScanFailed(Exception):
    """The scanner ran and did not produce a usable report."""


@dataclass(frozen=True)
class ScanResult:
    scanner: str
    project: str
    sarif: str
    duration: float


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


def run(project: str, scanner: str = "bandit") -> ScanResult:
    """Run the analyser and return its SARIF. Raises rather than returning junk."""
    spec = SCANNERS.get(scanner)

    if spec is None:
        raise ScanRefused("Böyle bir tarayıcı tanımlı değil.")

    binary = find_binary(spec["binary"])

    if binary is None:
        raise ScanRefused(
            f"{spec['label']} bu makinede kurulu değil. "
            f"Kurulum: pip install {spec['binary']}"
        )

    # A project name resolves to a directory; a target name resolves to a URL.
    # Both come from configuration and neither is ever read from a request.
    target = _dast_target(project) if spec.get("kind") == DAST else _target(project)
    # A list, and shell=False by omission. There is no command line to inject
    # into because there is no command line — the arguments are passed to the
    # operating system as they are.
    argv = [binary, *spec["args"](target)]
    timeout = DAST_TIMEOUT_SECONDS if spec.get("kind") == DAST else SCAN_TIMEOUT_SECONDS

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
            cwd=str(target) if spec.get("kind") != DAST else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanFailed(f"Tarama {timeout:.0f} saniyede bitmedi.") from exc
    except OSError as exc:
        raise ScanFailed("Tarayıcı çalıştırılamadı.") from exc

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

    return ScanResult(scanner=scanner, project=project, sarif=sarif, duration=0.0)
