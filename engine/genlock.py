# rules/engine/genlock.py
"""Regenerate usecases/_ruleid.lock.json over the full non-draft registry.

`build_lock` is fail-loud: a use-case naming a rule that does not resolve in the
export raises RuleNameError here, naming the offender. Run after adding use-cases
or flipping a use-case's draft status.

Run:  python3 rules/engine/genlock.py
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ruleid import build_lock
from loader import load_usecases

UC = os.path.join(HERE, "..", "usecases")
EXPORT = os.path.join(HERE, "..", "rules_export.ndjson")
LOCK = os.path.join(UC, "_ruleid.lock.json")

def main():
    ucs = load_usecases(UC, EXPORT)          # include_draft=False by default
    lock = build_lock(ucs, EXPORT)           # fail-loud on an unresolved rule name
    with open(LOCK, "w") as f:
        json.dump(lock, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"registry: {len(ucs)} non-draft use-cases; lock: {len(lock)} rule mappings")
    return 0

if __name__ == "__main__":
    sys.exit(main())
