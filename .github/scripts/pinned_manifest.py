#!/usr/bin/env python3
"""Write a dependency list containing only what can be audited without resolving.

pip-audit's `--no-deps` mode refuses a manifest outright if a single
requirement is not pinned to an exact version, and a real project has at least
one `>=`. Refusing the whole audit over that would mean the feature never runs;
auditing the unpinned line would mean resolving it, which means downloading and
building packages — running `setup.py` from every package in the tree.

So the pinned requirements are audited and **how many were left out is
printed**. Dropping them silently would have the operator read "no
vulnerabilities" against a list shorter than they think it is.

The same rule lives in `app/scanner.py: _pinned_manifest` for scans this
application starts itself. Two implementations, deliberately: this one runs on
a checkout where the application is not installed.
"""
import re

# `name==version`, optionally with extras and an environment marker. Anything
# else — a range, a URL, an editable install, an `-r` include — is not a pinned
# dependency and cannot be audited without resolving it.
PINNED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?==[^\s;#]+")

MANIFESTS = ("requirements.txt", "requirements-dev.txt")
OUT = "pinned.txt"


def main() -> int:
    kept: list[str] = []
    dropped = 0

    for name in MANIFESTS:
        try:
            with open(name, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError:
            continue

        for line in lines:
            stripped = line.strip()

            # Blank lines, comments and pip's own option lines are not
            # requirements and are not counted as skipped ones.
            if not stripped or stripped.startswith(("#", "-")):
                continue

            if PINNED.match(stripped):
                kept.append(stripped)
            else:
                dropped += 1

    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write("\n".join(kept) + "\n")

    print(
        f"::notice::{len(kept)} bağımlılık denetlenecek, {dropped} satır "
        f"sabit sürüm belirtmediği için atlandı."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
