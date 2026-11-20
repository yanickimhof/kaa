"""macOS specifics.

The Python interpreters installed by uv are only "linker signed" and carry no
identifier. macOS then hides the neighbour (ARP) table from them, which makes a
network scanner blind. Giving the interpreter a stable ad hoc identity fixes it.
Nothing is downloaded, no certificate is involved, and `uv python install
--reinstall` restores the original file.
"""

from __future__ import annotations

import os
import subprocess
import sys

IDENTIFIER = "app.kaa.python"


def interpreter() -> str:
    return os.path.realpath(sys.executable)


def identifier(path: str | None = None) -> str | None:
    """Code signing identifier of the interpreter, None if it cannot be read."""
    try:
        res = subprocess.run(["codesign", "-dv", path or interpreter()],
                             capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in (res.stderr + res.stdout).splitlines():
        if line.startswith("Identifier="):
            return line.split("=", 1)[1].strip()
    return None


def needs_identity(path: str | None = None) -> bool:
    return sys.platform == "darwin" and identifier(path) in ("-", "")


def ensure_identity(path: str | None = None) -> tuple[bool, str]:
    """Sign the interpreter ad hoc with a stable identifier if it has none."""
    if sys.platform != "darwin":
        return True, "not needed on this platform"
    path = path or interpreter()
    if not needs_identity(path):
        return True, "interpreter already has an identity"
    try:
        res = subprocess.run(["codesign", "--force", "--sign", "-", "--identifier",
                              IDENTIFIER, path], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"codesign failed: {exc}"
    if res.returncode != 0:
        return False, f"codesign failed: {(res.stderr or res.stdout).strip()}"
    return True, f"gave {path} the identity {IDENTIFIER} (restart Kaa to apply)"
