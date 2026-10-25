# rules/engine/envshared.py
"""Read the repo-root shared env file by key. Never logs a value; the file is mode 600.

The default used to be the FILESYSTEM root, so a bare call silently read nothing
and every caller had to pass the path itself. It is now the repo root, three
directories up from this file (rules/engine/envshared.py -> repo root).

Since 2026-10-16 the shared file holds only what a real customer needs; Zybur's own
keys (main's Elastic write and validation keys among them) are in ``.env.internal``
beside it. A key the given file does not hold is looked up there, the same rule as
onboarding/lib/shared-env.js sharedEnvValue.
"""
import os

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ".env.shared",
)
INTERNAL_NAME = ".env.internal"

def _read_one(key, path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() != key:
                continue
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            return v or None
    return None

def read_shared_env(key, path=DEFAULT_PATH):
    return (_read_one(key, path)
            or _read_one(key, os.path.join(os.path.dirname(path), INTERNAL_NAME)))

def require_shared_env(key, path=DEFAULT_PATH):
    v = read_shared_env(key, path)
    if v is None:
        raise KeyError(f"{key} not found in {path} or the {INTERNAL_NAME} beside it")
    return v
