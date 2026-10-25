# rules/engine/coverage.py
"""Join the registry against rules_export.ndjson: covered / uncovered / broken + scaffold.

Note: this shadows the stdlib/pip `coverage`; the engine tests run with CWD on the
engine dir so the local module wins. The engine never uses the coverage.py tool.
"""
import os, sys, json, argparse
from ruleid import load_enabled_rules
from ledger import last_verdict

def _slug(name):
    return "".join(c.lower() if c.isalnum() else "-" for c in name).strip("-")[:60]

def join(usecases, export_path, ledger_path=None):
    """Covered / uncovered / broken split of the enabled corpus vs the registry.

    broken = a covered rule whose every coverer's last ledger verdict is in
    {MISSED, INCONCLUSIVE, None} (needs ledger_path; otherwise broken is empty).
    """
    enabled = load_enabled_rules(export_path)
    covered_ids, coverers = set(), {}
    for uc in usecases:
        if uc.get("status") == "draft":
            continue
        for rid in uc.get("rule_ids") or []:
            covered_ids.add(rid)
            coverers.setdefault(rid, []).append(uc)
    covered, uncovered, broken = [], [], []
    for name, meta in enabled.items():
        rid = meta["rule_id"]
        rec = {"rule_id": rid, "name": name}
        if rid in covered_ids:
            covered.append(rec)
            if ledger_path:
                verdicts = [last_verdict(ledger_path, uc["id"]) for uc in coverers[rid]]
                if verdicts and all(v in ("MISSED", "INCONCLUSIVE", None) for v in verdicts):
                    broken.append(rec)
        else:
            uncovered.append(rec)
    return {"covered": covered, "uncovered": uncovered, "broken": broken}

def worklist(report):
    return sorted(report["uncovered"], key=lambda r: r["name"])

def scaffold(uncovered_rules, out_dir, export_path):
    """Write a draft stub file per uncovered rule; return the paths written."""
    paths = []
    for r in uncovered_rules:
        path = os.path.join(out_dir, "unsorted", _slug(r["name"]) + ".yaml")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        rel_id = os.path.relpath(path, out_dir)[:-5]
        with open(path, "w") as f:
            f.write(
                f"id: {rel_id}\n"
                f"title: {r['name']}\n"
                f"rules:\n  - {r['name']}\n"
                f"technique: TODO\ntactic: TODO\nseverity: TODO\n"
                f"executor: caldera_command\nstatus: draft\n"
                f"params:\n  shell: psh\n  command: 'TODO: attack that triggers this rule'\n"
            )
        paths.append(path)
    return paths

def check(usecases, export_path):
    rep = join(usecases, export_path)
    if rep["uncovered"]:
        print(f"COVERAGE GAP: {len(rep['uncovered'])} enabled rule(s) have no non-draft use-case:")
        for r in rep["uncovered"][:20]:
            print(f"  - {r['name']}")
        return 1
    print(f"COVERAGE OK: all {len(rep['covered'])} enabled rules have a use-case")
    return 0

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _rule_techniques(export_path):
    """rule_id -> set of MITRE technique/subtechnique ids from the rule's threat[]."""
    out = {}
    with open(export_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if not d.get("enabled") or not d.get("rule_id"):
                continue
            techs = set()
            for t in d.get("threat") or []:
                for tech in t.get("technique") or []:
                    if tech.get("id"):
                        techs.add(tech["id"])
                    for sub in tech.get("subtechnique") or []:
                        if sub.get("id"):
                            techs.add(sub["id"])
            out[d["rule_id"]] = techs
    return out

def _load_registry():
    here = os.path.dirname(os.path.abspath(__file__))
    uc_dir = os.path.join(here, "..", "usecases")
    export = os.path.join(here, "..", "rules_export.ndjson")
    from loader import load_usecases
    return load_usecases(uc_dir, export), export

def main(argv=None):
    ap = argparse.ArgumentParser(description="Coverage: use-case registry vs enabled rules")
    ap.add_argument("--scaffold", metavar="TECH", help="write draft stubs for uncovered rules of a technique")
    ap.add_argument("--check", action="store_true", help="exit 1 if an enabled rule has no non-draft use-case")
    args = ap.parse_args(argv)
    usecases, export = _load_registry()
    if args.check:
        return check(usecases, export)
    rep = join(usecases, export)
    if args.scaffold:
        techs = _rule_techniques(export)
        want = [r for r in rep["uncovered"] if args.scaffold in techs.get(r["rule_id"], set())]
        out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "usecases")
        paths = scaffold(want, out_dir, export)
        print(f"scaffolded {len(paths)} stub(s) for {args.scaffold}")
        for p in paths:
            print(f"  {p}")
        return 0
    wl = worklist(rep)
    print(f"coverage: {len(rep['covered'])} covered, {len(rep['uncovered'])} uncovered (top 40 by name):")
    for r in wl[:40]:
        print(f"  UNCOVERED  {r['name']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
