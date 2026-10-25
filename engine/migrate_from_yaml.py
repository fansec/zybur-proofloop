# rules/engine/migrate_from_yaml.py
"""One-shot: migrate rules/tests.yaml (61 tests) into the rules/usecases/ registry
and generate _ruleid.lock.json (fail-loud).

The p3a/p3b TEST_DEFS are NOT ingested here: their attack commands live inside
bespoke Python handler functions (run_p3*_test_NN), not the metadata dicts, so they
are not data-migratable. Those tests are ported alongside their plugins (Task 16).

Field mapping (tests.yaml -> use-case):
  num          -> slug id under <tactic>/
  rule         -> rules[0]  (resolves to rule_id via the lock)
  executor     -> a registered plugin name (psh/cmd -> caldera_command; DIRECT_* -> plugin)
  command      -> params.command                 (NOT dash-sanitized; it is a real command)
  cleanup      -> cleanup
  attack       -> description                     (dash-sanitized: Zybur-authored prose)
  group        -> tags[0]                         (enables --tag selection)
  expect[_reason] -> expect / reason
"""
import os, re, json, sys, yaml
from ruleid import build_lock

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS_YAML = os.path.join(HERE, "..", "tests.yaml")
EXPORT = os.path.join(HERE, "..", "rules_export.ndjson")
OUT_DIR = os.path.join(HERE, "..", "usecases")
LOCK = os.path.join(OUT_DIR, "_ruleid.lock.json")

_DASH = str.maketrans({"—": "-", "–": "-"})  # em/en dash -> hyphen

EXECUTOR_MAP = {
    "psh": "caldera_command",
    "cmd": "caldera_command",
    "DIRECT_WINRM": "winrm_command",
    "DIRECT_SMB": "smb_write",
    "DIRECT_SMB_RENAME": "smb_rename",
    "DIRECT_SMB_EXE": "smb_exe_transfer",
    "DIRECT_SMB_RANSOM_NOTE": "smb_ransom_note",
    "DIRECT_REMOTE_SERVICE": "remote_service",
    "DIRECT_REMOTE_SCHTASK": "remote_schtask",
    "DIRECT_RARE_SMB": "rare_smb",
}
# num-specific overrides for the bespoke DIRECT_WINRM tests (design 3 table)
WINRM_OVERRIDES = {33: "psremoting", 21: "rdp_keystroke", 45: "rdp_keystroke", 23: "hidden_user"}


def _slug(name):
    s = "".join(c.lower() if c.isalnum() else "-" for c in name)
    return re.sub(r"-+", "-", s).strip("-")[:60]


def _sanitize(s):
    return s.translate(_DASH) if isinstance(s, str) else s


def map_executor(legacy_executor, num):
    if legacy_executor == "DIRECT_WINRM" and num in WINRM_OVERRIDES:
        return WINRM_OVERRIDES[num]
    return EXECUTOR_MAP.get(legacy_executor, legacy_executor)


def map_test(t):
    """Map one legacy tests.yaml test dict to a new use-case dict."""
    tactic = t["tactic"]
    executor = map_executor(t["executor"], t["num"])
    shell = "cmd" if t["executor"] == "cmd" else "psh"
    uc = {
        "id": f"{tactic}/{_slug(t['rule'])}",
        "title": _sanitize(t["rule"]),
        "rules": [t["rule"]],
        "technique": t["technique_id"],
        "tactic": tactic,
        "executor": executor,
        "params": {"platform": "windows", "shell": shell, "command": t.get("command") or ""},
    }
    if t.get("severity"):
        uc["severity"] = t["severity"]
    if t.get("group"):
        uc["tags"] = [t["group"]]
    if t.get("attack"):
        uc["description"] = _sanitize(t["attack"])
    if t.get("cleanup"):
        uc["cleanup"] = t["cleanup"]
    if t.get("expect"):
        uc["expect"] = t["expect"]
    if t.get("expect_reason"):
        uc["reason"] = _sanitize(t["expect_reason"])
    return uc


# Emit each use-case with a stable key order for readable diffs.
_KEY_ORDER = ["id", "title", "rules", "technique", "tactic", "severity", "tags",
              "description", "executor", "expect", "reason", "params", "needs", "cleanup"]


def _ordered(uc):
    out = {k: uc[k] for k in _KEY_ORDER if k in uc}
    for k, v in uc.items():
        if k not in out:
            out[k] = v
    return out


def write_registry(tests, out_dir):
    seen, paths, ucs = {}, [], []
    for t in tests:
        uc = map_test(t)
        if uc["id"] in seen:  # keep ids unique (append num on collision)
            uc["id"] = f"{uc['id']}-{t['num']}"
        seen[uc["id"]] = t["num"]
        path = os.path.join(out_dir, uc["id"] + ".yaml")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            yaml.safe_dump(_ordered(uc), f, sort_keys=False, default_flow_style=False,
                           allow_unicode=True, width=1000000)
        paths.append(path)
        ucs.append(uc)
    return paths, ucs


def main():
    with open(TESTS_YAML) as f:
        data = yaml.safe_load(f)
    tests = data["tests"]
    paths, ucs = write_registry(tests, OUT_DIR)
    print(f"wrote {len(paths)} use-case files under {OUT_DIR}")
    lock = build_lock(ucs, EXPORT)  # fail-loud: RuleNameError lists every unresolved (id, name)
    with open(LOCK, "w") as f:
        json.dump(lock, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {LOCK} with {len(lock)} rule mappings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
