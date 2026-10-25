# rules/engine/lint.py
"""The CI lint gate over the use-case registry.

Checks: schema valid; id == path; ids unique; executor is a registered plugin;
rules: names resolve and the _ruleid.lock.json is not stale (fail-loud); any
needs.dedup source IP is inside the safe pool (outside the .111 denylist); and,
best-effort, the technique is present in the rule's own threat[].

--no-resolve (2026-10-22) checks shape only, for a tree whose rule pack cannot answer
for its use-cases: the public export ships three made-up rules (fixtures/
rules_export.sample.ndjson) and no real pack, so no use-case's rule names resolve
there. It skips the name resolution and the threat[] check, and judges the lock by its
own shape (an object of {rule_id, rule_uuid}) and by its keys against the names the
detected use-cases carry, instead of rebuilding it from the pack. Everything else runs.
"""
import os, re, sys, json, argparse, yaml
import executors.plugins  # noqa: F401  (registers all executor plugins as a side-effect)
from schema import validate_usecase
from ruleid import load_enabled_rules, check_lock, resolve_rule_names, RuleNameError
from executors.registry import executor_names
from executors.ad_reversible import OPERATIONS as AD_REVERSIBLE_OPERATIONS
from executors.ad_directory import (
    OPERATIONS as AD_DIRECTORY_OPERATIONS,
    NIGHTLY_SAFE_OPERATIONS as AD_DIRECTORY_NIGHTLY_SAFE_OPERATIONS,
)
from executors.ad_network import (
    OPERATIONS as AD_NETWORK_OPERATIONS,
    NIGHTLY_SAFE_OPERATIONS as AD_NETWORK_NIGHTLY_SAFE_OPERATIONS,
)
from executors.windows_reversible import (
    OPERATIONS as WINDOWS_REVERSIBLE_OPERATIONS,
    NIGHTLY_SAFE_OPERATIONS as WINDOWS_REVERSIBLE_NIGHTLY_SAFE_OPERATIONS,
)
from executors.smb_multipath import (
    OPERATIONS as SMB_MULTIPATH_OPERATIONS,
    NIGHTLY_SAFE_OPERATIONS as SMB_MULTIPATH_NIGHTLY_SAFE_OPERATIONS,
)
from dedup import build_pool, DedupConfigError
from cmdline import MAX_RUN_PS_CMDLINE, run_ps_cmdline_len, run_cmd_cmdline_len
# Aliased: this module already has its own narrower local `safe_pool` (the
# "non-empty rotation" check below), used for something else entirely. Importing
# selector's safe_pool under its own name would silently shadow that local, so the
# evidence-field check below calls the aliased import, never the bare name.
from selector import safe_pool as selector_safe_pool


# `network: internet` is a statement the author must make, and this is how the lint knows when
# it is owed. A use-case reaches the internet when a string in its params (or its cleanup) holds
# an http(s) URL whose host is not a `{{...}}` template (the lab's own CALDERA address is one),
# or one of the public resolvers as a whole address. A private address in a URL still counts: the
# lint cannot tell a lab host from a public one, and the cost of a false yes is an --allow-internet
# the operator has to pass, while the cost of a false no is a download nobody agreed to.
_URL = re.compile(r"https?://([^\s/?#'\"`<>\\]+)", re.IGNORECASE)
_PUBLIC_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")
_RESOLVER = re.compile(r"(?<!\d)(?<!\d\.)(?:" + "|".join(re.escape(r) for r in _PUBLIC_RESOLVERS)
                       + r")(?!\d)(?!\.\d)")


def _strings(node):
    """Every string value under `node`, however deep."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _strings(v)


def reaches_internet(doc):
    """True when the use-case's params or cleanup name a URL or a public resolver (see above)."""
    if not isinstance(doc, dict):
        return False
    texts = list(_strings(doc.get("params")))
    if isinstance(doc.get("cleanup"), str):
        texts.append(doc["cleanup"])
    for text in texts:
        if any(not m.group(1).startswith("{{") for m in _URL.finditer(text)):
            return True
        if _RESOLVER.search(text):
            return True
    return False


# The verbs that make `leaves_no_artifact: true` a false statement. Deliberately a
# short list of things that PERSIST past the process, not a general write detector:
# a regex cannot decide whether a redirect lands on disk or on a named pipe (the
# privilege-escalation named-pipe use-case writes to \\.\pipe\, which persists for
# exactly as long as the process does), so guessing at redirects would fail the
# honest use-cases and still miss the dishonest ones. What is here is what the
# corpus actually uses to leave state behind, and every entry is a thing reconcile
# has a manifest kind for.
_PERSISTING_VERBS = (
    "reg add", "reg.exe add", "Set-ItemProperty", "New-ItemProperty",
    "schtasks /create", "schtasks.exe /create", "Register-ScheduledTask",
    "sc create", "sc.exe create", "New-Service",
    "bitsadmin /create", "Start-BitsTransfer",
    "net user", "New-LocalUser",
    "Set-Content", "Out-File", "Copy-Item", "New-Item",
    # Fetching is not persisting; fetching TO DISK is. `Invoke-WebRequest` alone
    # would flag the public-ip discovery use-case, which reads a response body and
    # writes nothing, so the download verbs are spelled with the flag that lands
    # the bytes on the filesystem.
    "-OutFile", "DownloadFile", "-urlcache", "curl -o", "wget -o", "Start-BitsTransfer",
)

# A cleanup declaration is not self-certifying. Only executors whose code owns a
# second-session cleanup plus a measured residual probe may use
# cleanup_managed_by. Additions belong with executor tests proving that contract.
MANAGED_CLEANUP_EXECUTORS = {
    "ad_reversible", "ad_directory", "ad_network", "dcsync_ephemeral",
    "kerberos_asreq", "windows_reversible", "smb_multipath",
}


def _persisting_verbs(doc):
    """Which persisting verbs a use-case's payload contains, lowercase-insensitively."""
    cmd = str(((doc.get("params") or {}).get("command")) or "")
    low = cmd.lower()
    return [v for v in _PERSISTING_VERBS if v.lower() in low]


def _parent_technique(tech):
    """T1059.003 -> T1059. A technique with no sub-technique suffix has no parent."""
    return tech.split(".")[0] if "." in tech else None


def _rule_threat_techniques(export_path):
    """rule name -> set(technique ids) from threat[], for the best-effort technique check."""
    out = {}
    with open(export_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if not d.get("enabled") or not d.get("name"):
                continue
            techs = set()
            for t in d.get("threat") or []:
                for tech in t.get("technique") or []:
                    if tech.get("id"):
                        techs.add(tech["id"])
                    for sub in tech.get("subtechnique") or []:
                        if sub.get("id"):
                            techs.add(sub["id"])
            out[d["name"]] = techs
    return out


def _lock_shape_errors(lock_path, detected):
    """--no-resolve's lock check: the shape, and the key set against the use-cases' own names."""
    try:
        with open(lock_path) as f:
            lock = json.load(f)
    except (OSError, ValueError) as e:
        return [f"{lock_path}: unreadable lock: {type(e).__name__}"]
    if not isinstance(lock, dict):
        return [f"{lock_path}: the lock is not a JSON object"]
    errs = []
    for name, entry in sorted(lock.items()):
        if (not isinstance(entry, dict) or set(entry) != {"rule_id", "rule_uuid"}
                or not isinstance(entry["rule_id"], str) or not entry["rule_id"]
                or not (entry["rule_uuid"] is None or isinstance(entry["rule_uuid"], str))):
            errs.append(f"{lock_path}: entry {name!r} is not {{rule_id: str, rule_uuid: str|null}}")
    named = {name for d in detected for name in (d.get("rules") or [])}
    for name in sorted(named - set(lock)):
        errs.append(f"{lock_path}: stale lock - {name!r} is named by a use-case and missing from the lock")
    for name in sorted(set(lock) - named):
        errs.append(f"{lock_path}: stale lock - {name!r} is in the lock and named by no detected use-case")
    return errs


def lint(usecases_dir, export_path, lock_path, resolve=True):
    errs = []
    enabled = load_enabled_rules(export_path)  # also fails loud early if the export is unreadable
    known_execs = executor_names()
    pool = None  # built on first use: only a use-case that pins source_ips needs it
    threat = _rule_threat_techniques(export_path) if resolve else {}
    seen_ids = {}
    docs = []
    for root, _, files in os.walk(usecases_dir):
        for fn in sorted(files):
            if not fn.endswith(".yaml") or fn.startswith("_"):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, usecases_dir)
            try:
                with open(full) as fh:
                    doc = yaml.safe_load(fh) or {}
            except yaml.YAMLError as e:
                errs.append(f"{rel}: YAML parse error: {e}")
                continue
            schema_errs = validate_usecase(doc, rel)
            errs.extend(f"{rel}: {e}" for e in schema_errs)
            # Said even for a file the schema also refuses: one run shows everything the lint can
            # see, and an unrelated schema error must not hide an undeclared egress.
            if reaches_internet(doc) and doc.get("network") != "internet":
                errs.append(f"{rel}: reaches the internet without network: internet")
            if schema_errs:
                continue
            docs.append(doc)
            if doc["id"] in seen_ids:
                errs.append(f"{rel}: duplicate id {doc['id']!r} (also {seen_ids[doc['id']]})")
            else:
                seen_ids[doc["id"]] = rel
            if doc["executor"] not in known_execs:
                errs.append(f"{rel}: unknown executor {doc['executor']!r} (known: {sorted(known_execs)})")
            if doc["executor"] == "ad_reversible":
                operation = (doc.get("params") or {}).get("operation")
                if operation not in AD_REVERSIBLE_OPERATIONS:
                    errs.append(f"{rel}: ad_reversible operation {operation!r} is not in the "
                                "executor's closed operation set")
                if doc.get("target", "workstation") != "domain_controller":
                    errs.append(f"{rel}: ad_reversible requires target: domain_controller")
            if doc["executor"] == "ad_directory":
                operation = (doc.get("params") or {}).get("operation")
                if operation not in AD_DIRECTORY_OPERATIONS:
                    errs.append(f"{rel}: ad_directory operation {operation!r} is not in the "
                                "executor's closed operation set")
                if doc.get("target", "workstation") != "domain_controller":
                    errs.append(f"{rel}: ad_directory requires target: domain_controller")
                if (doc.get("safety") == "safe"
                        and operation not in AD_DIRECTORY_NIGHTLY_SAFE_OPERATIONS):
                    errs.append(f"{rel}: ad_directory operation {operation!r} may not be "
                                "safety:safe or enter the unattended nightly pool")
            if doc["executor"] == "ad_network":
                operation = (doc.get("params") or {}).get("operation")
                if operation not in AD_NETWORK_OPERATIONS:
                    errs.append(f"{rel}: ad_network operation {operation!r} is not in the "
                                "executor's closed operation set")
                if doc.get("target", "workstation") != "domain_controller":
                    errs.append(f"{rel}: ad_network requires target: domain_controller")
                if (doc.get("safety") == "safe"
                        and operation not in AD_NETWORK_NIGHTLY_SAFE_OPERATIONS):
                    errs.append(f"{rel}: ad_network operation {operation!r} may not be "
                                "safety:safe or enter the unattended nightly pool")
            if doc["executor"] == "windows_reversible":
                operation = (doc.get("params") or {}).get("operation")
                if operation not in WINDOWS_REVERSIBLE_OPERATIONS:
                    errs.append(f"{rel}: windows_reversible operation {operation!r} is not in the "
                                "executor's closed operation set")
                if (doc.get("safety") == "safe"
                        and operation not in WINDOWS_REVERSIBLE_NIGHTLY_SAFE_OPERATIONS):
                    errs.append(f"{rel}: windows_reversible operation {operation!r} may not be "
                                "safety:safe or enter the unattended nightly pool")
            if doc["executor"] == "smb_multipath":
                operation = (doc.get("params") or {}).get("operation")
                if operation not in SMB_MULTIPATH_OPERATIONS:
                    errs.append(f"{rel}: smb_multipath operation {operation!r} is not in the "
                                "executor's closed operation set")
                if doc.get("target", "workstation") != "domain_controller":
                    errs.append(f"{rel}: smb_multipath requires target: domain_controller")
                if (doc.get("safety") == "safe"
                        and operation not in SMB_MULTIPATH_NIGHTLY_SAFE_OPERATIONS):
                    errs.append(f"{rel}: smb_multipath operation {operation!r} may not be "
                                "safety:safe or enter the unattended nightly pool")
            if (doc["executor"] == "kerberos_asreq"
                    and doc.get("target", "workstation") != "domain_controller"):
                errs.append(f"{rel}: kerberos_asreq requires target: domain_controller")
            if doc["executor"] == "winrm_command":
                # 2026-10-14: cmd.exe refuses a command string over 8191 characters and
                # the WinRM call still returns, so an over-long payload never runs and
                # its night reads as executed. The BITS payload (9,027) did exactly that.
                # Measured raw, before placeholder substitution: MAX_RUN_PS_CMDLINE
                # keeps headroom under the hard limit for that (rules/engine/cmdline.py).
                p = doc.get("params") or {}
                measure = run_ps_cmdline_len if p.get("shell") == "psh" else run_cmd_cmdline_len
                for label, text in (("command", p.get("command")), ("cleanup", doc.get("cleanup"))):
                    if isinstance(text, str) and text.strip() and measure(text) > MAX_RUN_PS_CMDLINE:
                        errs.append(f"{rel}: winrm_command {label} is {measure(text)} characters on the "
                                    f"cmd.exe command line, over {MAX_RUN_PS_CMDLINE}: it would never run")
            safety = doc.get("safety")
            cleanup = doc.get("cleanup")
            has_cleanup = isinstance(cleanup, str) and bool(cleanup.strip())
            no_artifact = bool(doc.get("leaves_no_artifact"))
            managed_by = doc.get("cleanup_managed_by")
            managed_cleanup = (managed_by == doc.get("executor")
                               and managed_by in MANAGED_CLEANUP_EXECUTORS)
            if managed_by and managed_by not in MANAGED_CLEANUP_EXECUTORS:
                errs.append(f"{rel}: cleanup_managed_by executor {managed_by!r} has no "
                            "lint-approved measured cleanup contract")
            if safety == "safe" and not (has_cleanup or no_artifact or managed_cleanup):
                errs.append(f"{rel}: safety:safe requires a non-empty cleanup, "
                            "leaves_no_artifact:true, or an approved cleanup_managed_by executor")
            if no_artifact:
                for verb in _persisting_verbs(doc):
                    errs.append(f"{rel}: leaves_no_artifact:true but the payload runs "
                                f"{verb!r}, which leaves something behind")
            if doc.get("destroys_evidence") and safety == "safe":
                errs.append(f"{rel}: destroys_evidence must not be safety:safe")
            # P-D1: evidence (real_behaviour|stand_in) is REQUIRED for every safe-pool
            # member (the exact 4-filter predicate in selector.safe_pool, called here
            # on a singleton list so the two places can never drift into two answers)
            # and merely recommended elsewhere, so an unproven corpus still lints.
            if doc.get("evidence") is None:
                # allow_internet=True: `network: internet` is an operator allowance at run time,
                # not a lower standard of proof, so an internet use-case the nightly can draw
                # still owes its evidence.
                if selector_safe_pool([doc], allow_internet=True):
                    errs.append(f"{rel}: pool use-case has no evidence "
                                "(real_behaviour|stand_in - see P-D1)")
                else:
                    errs.append(f"WARN {rel}: no evidence (real_behaviour|stand_in - see P-D1)")
            needs = doc.get("needs") or {}
            dedup_req = needs.get("dedup")
            if isinstance(dedup_req, dict):
                for ip in dedup_req.get("source_ips") or []:
                    if pool is None:
                        try:
                            pool = set(build_pool())
                        except DedupConfigError as e:
                            # The pool is configuration now; without it a pinned source
                            # ip cannot be judged, which is a finding, not a pass.
                            errs.append(f"{rel}: cannot check dedup source ip {ip}: {e}")
                            break
                    if ip not in pool:
                        errs.append(f"{rel}: dedup source ip {ip} not in the safe pool (denylisted or out of range)")
            # Name resolution for EVERY use-case regardless of expect: until
            # 2026-09-02 renaming a non-detected use-case's rule to "This Rule Does
            # Not Exist Anywhere" passed both this file and loader.py in silence.
            # The expect-aware rules live in ruleid.resolve_rule_names, shared with
            # the loader so the gate and the runtime cannot drift into two answers.
            if resolve:
                errs.extend(f"{rel}: {e}" for e in resolve_rule_names(doc, enabled))
            if resolve and doc.get("expect", "detected") == "detected":
                for name in doc.get("rules") or []:
                    tset = threat.get(name)
                    authored = [doc["technique"], *(doc.get("additional_techniques") or [])]
                    if tset and not any(
                            tech in tset or (_parent_technique(tech) in tset)
                            for tech in authored):
                        # A use-case naming a SUB-technique whose PARENT is in the
                        # rule's own threat[] is not a mismatch. A single behavior
                        # can also validate rules whose own ATT&CK mappings differ,
                        # so additional_techniques supplies those explicit mappings.
                        # best-effort (design 7): the test's technique describes the attack,
                        # the rule's threat[] describes the rule; a mismatch is a WARN, not fatal.
                        errs.append(f"WARN {rel}: technique {doc['technique']} not in threat[] of rule {name!r} {sorted(tset)}")
    # Registry-wide: at least one loop-safe use-case must exist, or the nightly
    # rotation has nothing to select and silently detonates nothing.
    safe_pool = [d for d in docs if d.get("safety") == "safe" and not d.get("destroys_evidence")]
    if docs and not safe_pool:
        errs.append("safe pool is empty - nothing is loop-safe to select")
    # rule_id lock: not stale, all names resolve (fail-loud). Drafts are excluded from
    # the lock, same as the loader/runtime view, so the check must exclude them too.
    detected = [d for d in docs
                if d.get("expect", "detected") == "detected" and d.get("status") != "draft"]
    if not os.path.exists(lock_path):
        errs.append(f"{lock_path}: missing lock file (run migrate/gen to create it)")
    elif not resolve:
        errs.extend(_lock_shape_errors(lock_path, detected))
    else:
        try:
            if not check_lock(lock_path, detected, export_path):
                errs.append(f"{lock_path}: stale lock - regenerate (does not match registry)")
        except RuleNameError as e:
            errs.append(f"rule_id resolution: {e}")
    return errs


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Lint the use-case registry")
    ap.add_argument("--usecases", default=os.path.join(here, "..", "usecases"))
    ap.add_argument("--export", default=os.path.join(here, "..", "rules_export.ndjson"))
    ap.add_argument("--lock", default=os.path.join(here, "..", "usecases", "_ruleid.lock.json"))
    ap.add_argument("--no-resolve", action="store_true",
                    help="shape only: do not resolve rule names against --export (see the module docstring)")
    args = ap.parse_args(argv)
    errs = lint(args.usecases, args.export, args.lock, resolve=not args.no_resolve)
    for e in errs:
        print(f"LINT: {e}")
    fatal = [e for e in errs if not e.startswith("WARN ")]
    # Said on the summary line itself, so a shape-only pass can never be read as a full one.
    mode = ", shape only (--no-resolve)" if args.no_resolve else ""
    print(f"lint: {len(fatal)} error(s), {len(errs) - len(fatal)} warning(s){mode}")
    return 1 if fatal else 0


if __name__ == "__main__":
    sys.exit(main())
