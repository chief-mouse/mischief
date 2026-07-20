"""Host data-directory defaults for mschf.

Resolution order for ``host_root()``:

1. ``MSCHF_HOME`` env var (when set) — returned as-is (absolute).
2. Dev-source mode: if ``pyproject.toml`` exists at the package's grandparent
   (repo checkout layout), use that directory — same as legacy HOST_ROOT.
3. Installed mode: per-user data dir (no new deps, do not create).

Pure stdlib; do not import other mschf modules (trust imports this).
"""

from __future__ import annotations

import os
import sys


def host_root() -> str:
    """Return the host data root for CA certs, trust store, identities, etc."""
    env = os.environ.get("MSCHF_HOME")
    if env:
        return os.path.abspath(env)

    # Dev / source checkout: package lives at <root>/src/mschf/
    package_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.abspath(os.path.join(package_dir, "..", ".."))
    if os.path.isfile(os.path.join(candidate, "pyproject.toml")):
        return candidate

    # Installed: per-user config/data directory (not created here).
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "mschf")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/mschf")
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "mschf")
    return os.path.expanduser("~/.config/mschf")
