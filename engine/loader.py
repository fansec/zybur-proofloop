# rules/engine/loader.py
"""Walk rules/usecases, validate, resolve rule_ids. Fail-loud across the whole tree."""
import os, re, yaml
from schema import validate_usecase
from ruleid import load_enabled_rules, resolve_rule_names

class LoaderError(Exception):
    pass

def new_terms_memory_seconds(rule):
    """Seconds a new-terms rule remembers a value, from its history_window_start.

    None for any other rule type and for a window this cannot parse (an unknown shape
    must not read as "no memory": it reads as "unknown", which is also None here, so a
    caller that needs the distinction reads rule["type"] itself).
    """
    if not rule or rule.get("type") != "new_terms":
        return None
    return parse_relative_window(rule.get("history_window_start"))


def parse_relative_window(spec):
    """'now-5d' -> 432000. Only the shapes Elastic writes: now-<n><s|m|h|d>."""
    m = re.fullmatch(r"now-(\d+)([smhd])", str(spec or "").strip())
    if not m:
        return None
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def load_usecases(usecases_dir, export_path, include_draft=False):
    enabled = load_enabled_rules(export_path)
    out, errs = [], []
    for root, _, files in os.walk(usecases_dir):
        for fn in sorted(files):
            if not fn.endswith(".yaml") or fn.startswith("_"):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, usecases_dir)
            with open(full) as fh:
                doc = yaml.safe_load(fh) or {}
            schema_errs = validate_usecase(doc, rel)
            if schema_errs:
                errs.extend(f"{rel}: {e}" for e in schema_errs)
                continue
            if doc.get("status") == "draft" and not include_draft:
                continue
            rule_ids, rule_meta = [], {}
            # Every use-case's rules[] is resolved, whatever its expect, and what
            # resolution MEANS per expect lives in ruleid.resolve_rule_names - one
            # implementation shared with lint.py.
            errs.extend(f"{rel}: {e}" for e in resolve_rule_names(doc, enabled))
            # Only a detected use-case carries a verification target. A name that
            # did not resolve is already an error above, so skipping it here just
            # avoids a KeyError on the way to raising.
            if doc.get("expect", "detected") == "detected":
                for name in doc.get("rules") or []:
                    if name not in enabled:
                        continue
                    rule_ids.append(enabled[name]["rule_id"])
                    rule_meta[name] = {"interval": enabled[name]["interval"],
                                       "from_": enabled[name]["from_"]}
                    memory_s = new_terms_memory_seconds(enabled[name])
                    if memory_s:
                        rule_meta[name]["memory_s"] = memory_s
            doc["rule_ids"] = rule_ids
            doc["rule_meta"] = rule_meta
            # The longest memory among the use-case's new-terms targets, or absent. The
            # selector keeps the use-case off the rotation for that long after its last
            # detonation (selector.py cooldown): a re-run inside the window is a guaranteed
            # MISSED that says nothing about the rule (measured 2026-10-21 and 2026-10-22,
            # the two MSBuild use-cases on dc1).
            memories = [m["memory_s"] for m in rule_meta.values() if m.get("memory_s")]
            if memories:
                doc["rule_memory_s"] = max(memories)
            out.append(doc)
    if errs:
        raise LoaderError("registry errors:\n" + "\n".join("  " + e for e in errs))
    return out


def load_usecase_docs(usecases_dir):
    """The use-case files as plain documents keyed by id: no schema check, no rule resolution.

    load_usecases above fails loud across the tree and needs the enabled-rules export, which is
    right for a run and wrong for reading a finished night: report_md only needs each file's
    title, technique and rules as written, and a public user may hold a results file without the
    export it was run against. A file that does not parse, or has no id, is skipped here (the
    runner and lint.py are the places that complain about it); the report then says the file was
    not found rather than refusing to render the night.
    """
    out = {}
    for root, _, files in os.walk(usecases_dir):
        for fn in sorted(files):
            if not fn.endswith(".yaml") or fn.startswith("_"):
                continue
            try:
                with open(os.path.join(root, fn), encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
            # UnicodeDecodeError is a ValueError: a file that is not UTF-8 is as unreadable as one
            # that is not YAML, and must not kill the report with a traceback.
            except (OSError, ValueError, yaml.YAMLError):
                continue
            if isinstance(doc, dict) and doc.get("id"):
                out[str(doc["id"])] = doc
    return out
