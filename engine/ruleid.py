# rules/engine/ruleid.py
"""Generate + check the name -> rule_id lockfile from rules_export.ndjson. Fail-loud."""
import json, os
from rulehash import rule_query_hash

class RuleNameError(Exception):
    pass

# Custom rules Zybur manages directly in Elastic (onboarding/lib/identity-setup.js
# RULE_BUILDERS) and binds like the prebuilt three (onboarding/lib/modules.js
# customRules), but which are never emitted into the committed pack: rules_export.
# ndjson is the Elastic prebuilt-rules export only, and rules-export-contract.test.js
# asserts the custom rule stays out of it (C-S1, 2026-10-16). A use-case can still
# target one of these by name - resolve_rule_names needs an answer either way, and
# "not in the pack" must not read as "not enabled". rule_id/interval/from here are
# copied from the canary rule's builder (identity-setup.js); a change there needs the same
# change here, same as any other rule's fields drift only together with its use-case.
#
# The cache-smuggling rule (ingest baseline plan 2026-10-22, F7 and section 20.3,
# 2026-10-23): the endpoint module's second custom rule, built from the baseline data by
# onboarding/lib/identity-rules.js buildCacheSmugglingRule, created on every tenant and
# on main, and bound like the canary rule (founder, 2026-10-23). The three
# steered use-cases of slice 5c (rules/usecases/execution/steered-*.yaml) target it.
# Since 2026-10-23 onboarding/lib/identity-rules.test.js holds every entry here to its
# builder's name, rule_id, interval and look-back.
MANAGED_RULES = {
    "Zybur Proofloop - Canary": {
        "rule_id": "zybur-proofloop-canary",
        "rule_uuid": None,
        "interval": "5m",
        "from_": "now-10m",
    },
    "Zybur - Execution From a Cache Folder": {
        "rule_id": "zybur-cache-smuggling",
        "rule_uuid": None,
        "interval": "5m",
        "from_": "now-9m",
    },
}

def load_enabled_rules(export_path):
    out = {}
    with open(export_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if not d.get("enabled") or not d.get("name") or not d.get("rule_id"):
                continue
            out[d["name"]] = {
                "rule_id": d["rule_id"],
                "rule_uuid": d.get("id"),
                "interval": d.get("interval"),
                "from_": d.get("from"),
                # What a proof is measured against (rulehash.py). MANAGED_RULES below
                # carry none: they are not in the export, so there is no query to hash.
                "query_hash": rule_query_hash(d),
                # A new-terms rule remembers every value of new_terms_fields it has seen
                # inside history_window_start ("now-5d") and alerts only on a value it has
                # NOT seen. The engine reads these to know when a re-run on the same host
                # cannot fire (run.py memory check, selector.py cooldown); 2026-10-22.
                "type": d.get("type"),
                "new_terms_fields": list(d.get("new_terms_fields") or []),
                "history_window_start": d.get("history_window_start"),
            }
    # Merged only for the real pack, by basename: every caller's export_path ends in
    # rules_export.ndjson (run.py, lint.py, coverage.py all default to it), while a
    # test's own small fixture (fixtures/rules_export.sample.ndjson) stays exactly
    # what it says on its tin. The pack never carries a managed rule's own name (by
    # design, see MANAGED_RULES), so a name collision here would mean the pack
    # started shipping a rule of the exact same name - loud, not silently
    # overridden either way.
    if os.path.basename(export_path) == "rules_export.ndjson":
        for name, meta in MANAGED_RULES.items():
            if name in out:
                raise RuleNameError(f"{name!r} is a managed rule AND in the committed pack - rename one")
            out[name] = meta
    return out

def resolve_rule_names(doc, enabled):
    """Errors for ONE use-case's rules[] against the enabled export, expect-aware.

    ONE implementation, called by loader.py (the runtime path) and lint.py (the CI
    gate). A second copy would become a second answer, the way the safe-pool probe
    did before `safePoolIds`.

    Names are resolved for EVERY use-case, not just expect:detected ones: a
    non-detected use-case's rules[] is inert today but becomes the verification
    target the day its expect flips, and until 2026-09-02 nothing ever resolved it,
    so a typo'd or deleted rule name sat silent for as long as it stayed non-detected.

    What "resolves" MEANS depends on expect, and conflating the two is what cost the
    2026-09-03 nightly run its whole loop:

      detected     the rule IS the verification target, so it must be ENABLED.
      env_gap      the ENVIRONMENT cannot produce the telemetry; the rule itself is
                   live, so it must be ENABLED too. 59 of the 60 env_gap use-cases
                   already were - the 60th was mislabelled and should have been
                   not_enabled.
      not_enabled  the rule is installed and deliberately OFF, so it is absent from
                   the enabled export BY DEFINITION. Requiring it to be present made
                   the one honest use of `not_enabled` a hard crash. What IS
                   checkable here is the opposite drift: the rule got enabled and
                   nobody flipped the use-case to detected.

    Returns bare messages; the caller prefixes them with the file it read.

    WARNING: nothing offline can prove a not_enabled name exists AT ALL - the repo
    tracks only the enabled export - so a typo in a not_enabled use-case's rules[]
    stays silent. Closing that needs an installed-rule name list synced from live.
    """
    expect = doc.get("expect", "detected")
    errs = []
    for name in doc.get("rules") or []:
        if expect == "not_enabled":
            if name in enabled:
                errs.append(f"expect:not_enabled but rule {name!r} IS enabled "
                            "- flip expect to detected")
        elif name not in enabled:
            errs.append(f"rule name {name!r} not in enabled export")
    return errs


def build_lock(usecases, export_path):
    enabled = load_enabled_rules(export_path)
    lock, unresolved = {}, []
    for uc in usecases:
        if uc.get("expect", "detected") != "detected":
            continue
        for name in uc.get("rules") or []:
            if name not in enabled:
                unresolved.append((uc["id"], name))
                continue
            lock[name] = {"rule_id": enabled[name]["rule_id"],
                          "rule_uuid": enabled[name]["rule_uuid"]}
    if unresolved:
        lines = "\n".join(f"  {uid}: {name!r}" for uid, name in unresolved)
        raise RuleNameError(f"{len(unresolved)} rule name(s) resolve to no enabled rule:\n{lines}")
    return lock

def check_lock(lock_path, usecases, export_path):
    with open(lock_path) as f:
        on_disk = json.load(f)
    return on_disk == build_lock(usecases, export_path)
