# rules/engine/schema.py
"""Pure validation of a use-case record. Returns a list of human-readable errors."""
import re

REQUIRED = ("id", "title", "rules", "technique", "tactic", "executor", "params", "safety")
VALID_EXPECT = ("detected", "env_gap", "not_enabled")
VALID_SAFETY = ("safe", "supervised", "never")
# What a detonation can reach besides the lab. `lab` is the default and is never written; `internet` means
# the payload fetches a URL or asks a public resolver, which `safe` (a statement about cleanup) does not cover.
VALID_NETWORK = ("lab", "internet")
VALID_EVIDENCE = ("real_behaviour", "stand_in")
VALID_TARGETS = ("workstation", "domain_controller")
_TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
_DASHES = ("—", "–")
_AUTHORED_STR_FIELDS = ("id", "title", "description", "tactic", "executor")

def validate_usecase(doc, path):
    errs = []
    for f in REQUIRED:
        if f not in doc or doc[f] in (None, ""):
            errs.append(f"missing required field '{f}'")
    if errs:
        return errs
    expect = doc.get("expect", "detected")
    if expect not in VALID_EXPECT:
        errs.append(f"expect '{expect}' not in {VALID_EXPECT}")
    if doc["safety"] not in VALID_SAFETY:
        errs.append(f"safety '{doc['safety']}' not in {VALID_SAFETY}")
    network = doc.get("network", "lab")
    if network not in VALID_NETWORK:
        errs.append(f"network '{network}' not in {VALID_NETWORK}")
    target = doc.get("target", "workstation")
    if target not in VALID_TARGETS:
        errs.append(f"target '{target}' not in {VALID_TARGETS}")
    # evidence is OPTIONAL at the schema level - lint.py is where it becomes
    # required, and only for safe-pool members (P-D1). Here it is only ever
    # checked for shape: absent is fine, present-and-wrong is not.
    evidence = doc.get("evidence")
    if evidence is not None and evidence not in VALID_EVIDENCE:
        errs.append(f"evidence '{evidence}' not in {VALID_EVIDENCE}")
    if "destroys_evidence" in doc and not isinstance(doc["destroys_evidence"], bool):
        errs.append("destroys_evidence must be a boolean when present")
    # leaves_no_artifact is the OTHER way to satisfy "safe": a payload that writes
    # nothing has nothing to clean up, and a cleanup written for it would be a
    # no-op pretending to be a control. Declaring both is a contradiction, not a
    # belt-and-braces: one of the two statements about the payload is false.
    if "leaves_no_artifact" in doc and not isinstance(doc["leaves_no_artifact"], bool):
        errs.append("leaves_no_artifact must be a boolean when present")
    managed = doc.get("cleanup_managed_by")
    if managed is not None and (not isinstance(managed, str) or managed != doc.get("executor")):
        errs.append("cleanup_managed_by must name this use-case's executor")
    if managed and (doc.get("cleanup") or "").strip():
        errs.append("cleanup_managed_by contradicts a separate cleanup command")
    if managed and doc.get("leaves_no_artifact"):
        errs.append("cleanup_managed_by contradicts leaves_no_artifact:true")
    if doc.get("leaves_no_artifact") and (doc.get("cleanup") or "").strip():
        errs.append("leaves_no_artifact:true contradicts a non-empty cleanup - "
                    "a payload that writes nothing has nothing to clean up")
    # Only a use-case FILE path has an id to equal: loader and lint always pass one ('a/b.yaml'),
    # and a doc validated in memory under any other label is not compared with it.
    if path.endswith(".yaml") and doc["id"] != path[:-5]:
        errs.append(f"id '{doc['id']}' must equal path minus .yaml ('{path[:-5]}')")
    if not _TECH.match(str(doc["technique"])):
        errs.append(f"technique '{doc['technique']}' is not a MITRE id (T#### or T####.###)")
    additional = doc.get("additional_techniques", [])
    if not isinstance(additional, list):
        errs.append("additional_techniques must be a list when present")
    else:
        for tech in additional:
            if not _TECH.match(str(tech)):
                errs.append(f"additional technique '{tech}' is not a MITRE id (T#### or T####.###)")
        if doc["technique"] in additional:
            errs.append("additional_techniques must not repeat the primary technique")
    rules = doc.get("rules") or []
    if not rules and expect == "detected":
        errs.append("rules[] may be empty only when expect is env_gap/not_enabled")
    for field in _AUTHORED_STR_FIELDS:
        val = doc.get(field)
        if isinstance(val, str) and any(d in val for d in _DASHES):
            errs.append(f"long dash in authored field '{field}'")
    return errs
