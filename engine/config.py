# rules/engine/config.py
"""One config for the engine. Resolved from the environment, then validation/.creds.

CHANGED 2026-07-27. This file used to carry the CALDERA API key and the lab
Administrator password as literal DEFAULTS. It is TRACKED IN GIT and no deny pattern matches
`config.py`, so any nightly analyst agent could read both with a plain Read while
the same values were being denied to it in .env.shared - the boundary had a hole
exactly the width of this file. The secrets now live in validation/.creds, which is
gitignored and denied at all three layers.

Since 2026-10-22 no lab fact has a default either: the server, the attacker address,
the domain controller's name and domain and the dedup pool come from the environment,
the creds file or the lab-hosts registry, and a missing one is named
(missing_lab_config, run.py --preflight), never guessed. The argument for a default
was that a wrong address selects nothing; that stopped being true on 2026-08-26, when
an address a previous literal named was taken by a different device, so a stale
default aims the attack path at someone else's machine. The two target addresses come
from the registry (labhosts.py: validation/lab-hosts.json, or LAB_HOSTS_FILE), which
calls itself the one place an attack range is named, and a registry that cannot be
read raises rather than guessing: an unreadable registry is a repo defect, not a lab
fact. What keeps a default is a label or a vendor id: the CALDERA group, the built-in
planner id, the account names.
"""
import os

import labhosts

# Secrets: no default. A missing one is an error at the point of use, not a silent
# fall back to a value in a tracked file.
_SECRET_KEYS = ("CALDERA_API_KEY", "WIN_PASS")
VALID_TARGETS = ("workstation", "domain_controller")


def _creds_paths():
    # An explicit file REPLACES the default places, it does not join them: a checkout
    # with no validation/ folder (the public export, a CI box) points the engine at
    # its own file, and a box that also has the default file must not leak its values
    # into a run that asked for another.
    override = os.environ.get("ZYBUR_CREDS_FILE")
    if override:
        return [override]
    here = os.path.dirname(os.path.abspath(__file__))
    return [
        os.path.join(here, "..", "..", "validation", ".creds"),
        "/validation/.creds",
    ]


def _read_creds(key):
    from envshared import read_shared_env
    for path in _creds_paths():
        v = read_shared_env(key, path)
        if v:
            return v
    return None


# REPLACE_ME is not a value: it is what a key looks like while it waits to be
# filled in. Mirrors onboarding/lib/env-file.js isPlaceholderValue.
_PLACEHOLDERS = ("REPLACE_ME", "")


def _usable(v):
    return v if (v and v.strip() not in _PLACEHOLDERS) else None


def _resolve(key, default=None):
    return _usable(os.environ.get(key)) or _usable(_read_creds(key)) or default


def _registry_ip(role):
    """The configured address for a lab role. LabHostsError propagates on purpose."""
    return labhosts.host_for_role(role)["ip"]


def load_config():
    here = os.path.dirname(os.path.abspath(__file__))
    return {
        "server":      _resolve("CALDERA_SERVER"),
        "api_key":     _resolve("CALDERA_API_KEY"),
        "group":       _resolve("CALDERA_GROUP",  "red"),
        "planner_id":  _resolve("CALDERA_PLANNER", "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"),
        # The address comes from validation/lab-hosts.json, not from a literal here.
        # It WAS a literal until 2026-09-06 and sat stale for about four weeks after
        # the 2026-07-29 move; onboarding/lab-host-exclusion.test.js fails if one
        # comes back. The registry entry carries the whole address history.
        "win_host":    _resolve("WIN_HOST",       _registry_ip("workstation")),
        "win_user":    _resolve("WIN_USER",       "Administrator"),
        "win_pass":    _resolve("WIN_PASS"),
        # DC1 is a separate execution target. These values stay distinct here and
        # are projected onto win_* only for a use-case that explicitly declares
        # target: domain_controller, so an absent target field remains incapable
        # of redirecting the existing workstation corpus.
        "dc_host":     _resolve("DC_HOST",        _registry_ip("domain_controller")),
        "dc_user":     _resolve("DC_USER",        "Administrator"),
        "dc_pass":     _resolve("DC_PASS"),
        "dc_domain":   _resolve("DC_DOMAIN"),
        "dc_fqdn":     _resolve("DC_FQDN"),
        "attacker_ip": _resolve("ATTACKER_IP"),
        # The dedup pool (dedup.py reads the same names through _resolve). Carried
        # here so missing_lab_config can name them like every other lab value.
        "dedup_subnet":   _resolve("DEDUP_SUBNET"),
        "dedup_gateway":  _resolve("DEDUP_GATEWAY"),
        "dedup_denylist": _resolve("DEDUP_DENYLIST"),
        "results_dir": os.environ.get("RESULTS_DIR", os.path.join(here, "..", "results")),
    }


def require_config():
    """load_config, but refuses to hand back a config with a missing credential.

    Callers that actually detonate use this; read-only paths (selection, lint,
    coverage) use load_config and never touch api_key or win_pass.
    """
    cfg = load_config()
    fields = {"CALDERA_API_KEY": "api_key", "WIN_PASS": "win_pass"}
    missing = [k for k in _SECRET_KEYS if not cfg[fields[k]]]
    if missing:
        raise SystemExit(
            "engine: %s not set. They live in validation/.creds (gitignored, mode 600); "
            "export them or restore that file. Refusing to fall back to a value in a "
            "tracked file." % ", ".join(missing))
    return cfg


def config_for_target(cfg, target="workstation"):
    """Project a named lab target onto the executor's stable win_* interface."""
    target = target or "workstation"
    if target not in VALID_TARGETS:
        raise ValueError(f"unknown use-case target {target!r}")
    out = dict(cfg)
    out["target"] = target
    if target == "domain_controller":
        out["win_host"] = cfg.get("dc_host")
        out["win_user"] = cfg.get("dc_user")
        out["win_pass"] = cfg.get("dc_pass")
    return out


def missing_for_target(cfg, target="workstation"):
    """Name missing target credentials without ever returning their values."""
    target = target or "workstation"
    if target == "domain_controller":
        needed = (("DC_HOST", "dc_host"), ("DC_USER", "dc_user"),
                  ("DC_PASS", "dc_pass"), ("DC_DOMAIN", "dc_domain"))
    elif target == "workstation":
        needed = (("WIN_HOST", "win_host"), ("WIN_USER", "win_user"),
                  ("WIN_PASS", "win_pass"))
    else:
        return [f"target:{target}"]
    return [env_name for env_name, field in needed if not cfg.get(field)]


# What each registered executor reads from the lab. One entry per executor in
# executors.registry (test_lab_config.py holds the two together), so a new executor
# cannot ship without saying which lab values it needs. The netns executors (SMB,
# remote, WMI) send through dedup.py's source-IP rotation, so the three DEDUP names
# are theirs; the WinRM executors never draw from the pool and do not need them.
_WIN = ("WIN_HOST", "WIN_USER", "WIN_PASS")
_DC = ("DC_HOST", "DC_USER", "DC_PASS", "DC_DOMAIN", "DC_FQDN")
_DEDUP = ("DEDUP_SUBNET", "DEDUP_GATEWAY", "DEDUP_DENYLIST")
_NETNS = ("ATTACKER_IP", *_WIN, *_DEDUP)
LAB_KEYS_BY_EXECUTOR = {
    "winrm_command":      _WIN,
    "windows_reversible": _WIN,
    "hidden_user":        _WIN,
    "rdp_keystroke":      _WIN,
    "psremoting":         _NETNS,
    "caldera_command":    ("CALDERA_SERVER", "CALDERA_API_KEY", *_WIN),
    "ad_directory":       _DC,
    "ad_network":         _DC,
    "ad_reversible":      _DC,
    "dcsync":             _DC,
    "dcsync_ephemeral":   _DC,
    "kerberos_asreq":     _DC,
    "smb_multipath":      _DC,
    "smb_exe_transfer":   _NETNS,
    "smb_ransom_note":    _NETNS,
    "smb_rename":         _NETNS,
    "smb_write":          ("ATTACKER_IP", *_WIN),
    "rare_smb":           ("ATTACKER_IP", *_WIN),
    "remote_schtask":     _NETNS,
    "remote_service":     _NETNS,
    "dcomexec":           _NETNS,
    "wmiexec":            _NETNS,
}

# Env name -> load_config() field. Explicit, because the field names are not a
# mechanical lower-casing (CALDERA_SERVER is "server", CALDERA_API_KEY "api_key").
_ENV_TO_FIELD = {
    "CALDERA_SERVER": "server", "CALDERA_API_KEY": "api_key",
    "WIN_HOST": "win_host", "WIN_USER": "win_user", "WIN_PASS": "win_pass",
    "DC_HOST": "dc_host", "DC_USER": "dc_user", "DC_PASS": "dc_pass",
    "DC_DOMAIN": "dc_domain", "DC_FQDN": "dc_fqdn",
    "ATTACKER_IP": "attacker_ip",
    "DEDUP_SUBNET": "dedup_subnet", "DEDUP_GATEWAY": "dedup_gateway",
    "DEDUP_DENYLIST": "dedup_denylist",
}


def missing_lab_config(cfg, executors):
    """The env names the given executors need whose config value is empty.

    Names only, sorted and de-duplicated, never a value: the answer is printed by
    run.py --preflight and has to be safe in any log.
    """
    names = set()
    for executor in executors:
        for env_name in LAB_KEYS_BY_EXECUTOR[executor]:
            if not cfg.get(_ENV_TO_FIELD[env_name]):
                names.add(env_name)
    return sorted(names)


_TEMPLATES = (
    ("{{SERVER}}", "server"), ("{{WIN_HOST}}", "win_host"), ("{{WIN_USER}}", "win_user"),
    ("{{WIN_PASS}}", "win_pass"), ("{{ATTACKER_IP}}", "attacker_ip"),
    # Not a secret and not a static cfg value: {{NONCE}} is the one per-RUN
    # placeholder, generated fresh by the executor for the single detonation
    # using it (rules/engine/executors/winrm_command.py, secrets.token_hex(4),
    # the same per-run-token convention every other executor already uses) and
    # merged into that one call's cfg dict rather than into load_config()'s
    # shared, process-wide cfg. Added 2026-10-19 (C-S5 chain-proof canary fix):
    # the canary use-case used cmd.exe's own %RANDOM% before this, a RUNTIME
    # expansion that WinRS's outer `cmd.exe /C` wrap (see cmdline.py) left
    # unexpanded on the outer process's own command line while an inner
    # cmd.exe expanded it for real - two process-creation events, two values,
    # one of them a nonce never actually written anywhere. Templating a
    # pre-generated literal in instead means there is nothing left to expand
    # differently.
    ("{{NONCE}}", "nonce"),
)

def subst(text, cfg):
    """Substitute {{TEMPLATE}} placeholders in a command/cleanup with runtime cfg values.

    Secrets (e.g. {{WIN_PASS}}) are injected only at runtime, never written to the
    tracked registry - the migrated use-case files keep the placeholders.
    """
    if not text:
        return text
    for tpl, key in _TEMPLATES:
        if tpl in text:
            # A key that is present and None is a lab value nobody configured (there
            # are no defaults since 2026-10-22). Writing "None" into an attack
            # command would aim it at nothing, silently; the executor's caller turns
            # this into an ERROR row that names the variable. An ABSENT key keeps its
            # old meaning, an empty string (a cfg that never carried the field).
            if key in cfg and cfg[key] is None:
                env_name = next((e for e, f in _ENV_TO_FIELD.items() if f == key), key)
                raise ValueError(f"{tpl} needs {env_name}, which is not set")
            text = text.replace(tpl, str(cfg.get(key, "")))
    return text
