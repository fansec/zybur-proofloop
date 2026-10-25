# rules/engine/report_md.py
"""The attack half of the nightly report, rendered from the engine's own results.

Two sections: the table of what each attack scored ("Detected, prevented or missed") and a
short block per attack saying what it did and how it was delivered. It is the same content the
Node loop prints (validation/lib/render.js), so a user of the engine alone gets it too.

Pure: reads the two inputs it is handed, imports nothing that touches the network, an env file
or a credential. Rule 2 of validation/lib/attack-report.js holds here as well: a value that was
not measured renders as n/a, never as 0.

    python3 report_md.py <results.json> [--usecases DIR] [--night YYYY-MM-DD]

One table row and one block per result, in input order, with no collapsing: the input must
already be one final row per attack. `run.py --emit-json` writes its file before the recheck,
so a report from it shows the pre-recheck verdicts (PENDING, latency n/a); the ledger holds
several rows per attack per night (PENDING first, then the rechecked ones), so pass it only
after keeping the last row per (id, run_ts): one use-case can detonate twice in a night and those
are two attacks (validation/lib/attack-report.js latestRows does the same). The Node report
(validation/lib/render.js) reads the rechecked night and stays the reference for a finished night.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime

from loader import load_usecase_docs

HERE = os.path.dirname(os.path.abspath(__file__))
NA = "n/a"

# The order the front matter lists verdicts in; any other value (a result that never got a
# verdict) is counted after these so the counts always add up to the number of use-cases.
VERDICT_ORDER = ("DETECTED", "MISSED", "PREVENTED", "PENDING", "INCONCLUSIVE", "ABORT")


def _one_line(v):
    """A value on one line: a newline would end a table row or a bullet early."""
    return " ".join(str(v).split())


def _cell(v):
    """A table cell: one line, and a literal | escaped so one result stays one row."""
    return _one_line(v).replace("|", "\\|")


def _text(v):
    return NA if v is None or str(v).strip() == "" else _one_line(v)


def _verdict(r):
    return _text(r.get("verdict"))


def _latency(v):
    # Number as given. A real 0 is a measurement and prints; only None is absent.
    return NA if v is None else _one_line(v)


def _later_siblings(r, results):
    """rule_id -> use-case id, for the other attacks whose detonation started after r's window closed.

    Rule 3 of validation/lib/attack-report.js: an alert on a neighbour's target rule, raised by a
    neighbour that had not started yet, cannot be evidence about this attack. Compared as strings
    like the Node loop does (ISO timestamps from one writer sort the same way).
    """
    end = r.get("attack_end")
    owners = {}
    if not end:
        return owners
    for s in results:
        if s is r or not s.get("attack_start") or str(s["attack_start"]) <= str(end):
            continue
        for rid in s.get("rule_ids") or []:
            owners[rid] = s.get("id")
    return owners


def _co_firing(r, results=()):
    """(names of the other alerts in the window, number of distinct prevention alerts).

    The ledger and run.py write dicts ({"name", "prevented", "rule_id", "ts"}); plain strings
    are accepted as well. As in the Node report, a prevention alert is counted apart from the
    detections (a block nearby is not something that fired for this attack) and an alert on a
    later sibling's target rule is dropped as mis-attributed.
    """
    later = _later_siblings(r, results)
    names, prevention = [], []
    for c in r.get("co_firing") or []:
        if isinstance(c, dict):
            name = c.get("name") or c.get("rule_id")
            if not name:
                continue
            name = _one_line(name)
            if c.get("prevented"):
                if name not in prevention:
                    prevention.append(name)
                continue
            if c.get("rule_id") in later:
                continue
        else:
            name = _one_line(c)
        if name and name not in names:
            names.append(name)
    return names, len(prevention)


def _parse_ts(v):
    try:
        # fromisoformat only reads a Z suffix from Python 3.11 on
        return datetime.fromisoformat(re.sub(r"[zZ]$", "+00:00", str(v).strip()))
    except (TypeError, ValueError):
        return None


def _window_line(r):
    start, end = r.get("attack_start"), r.get("attack_end")
    if not start:
        return "- window: " + NA
    line = "- window: %s to %s" % (_one_line(start), _text(end))
    a, b = _parse_ts(start), _parse_ts(end)
    if a and b:
        try:
            line += " (%.1fs on the box)" % (b - a).total_seconds()
        except TypeError:  # one timestamp has an offset and the other does not
            pass
    return line


def _hosts(results):
    names = set()
    for r in results:
        h = r.get("host")
        name = h.get("name") if isinstance(h, dict) else None
        if name:
            names.add(_one_line(name))
    return ", ".join(sorted(names)) if names else NA


def _verdict_counts(results):
    counts = {}
    for r in results:
        v = r.get("verdict")
        counts[v] = counts.get(v, 0) + 1
    parts = ["%s %d" % (v, counts[v]) for v in VERDICT_ORDER if counts.get(v)]
    parts += ["%s %d" % (_text(v), n) for v, n in counts.items() if v not in VERDICT_ORDER]
    return ", ".join(parts)


def _table(results, usecases):
    rows = [
        "| Use-case | Technique | Verdict | Latency (s) | Target rule fired | Also fired in the window |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        uc = usecases.get(r.get("id")) or {}
        co, n_prev = _co_firing(r, results)
        # "blocked by" only where the engine concluded PREVENTED, as the Node report words it
        also = "; ".join(co) if co else "nothing else fired"
        if n_prev:
            also += ("; blocked by %d prevention alert(s)" if r.get("verdict") == "PREVENTED"
                     else "; %d prevention alert(s) elsewhere in the window") % n_prev
        rows.append("| `%s` | %s | %s | %s | %s | %s |" % (
            _cell(r.get("id") or NA).replace("`", "'"), _cell(_text(uc.get("technique"))), _cell(_verdict(r)),
            _cell(_latency(r.get("latency_s"))), "yes" if r.get("verdict") == "DETECTED" else "no",
            _cell(also)))
    return rows


def _details(results, usecases):
    out = []
    for r in results:
        uc = usecases.get(r.get("id"))
        out += ["### %s - %s" % (_text(r.get("id")), _verdict(r)), ""]
        if uc:
            out.append("- %s (%s, %s)" % (_text(uc.get("title")), _text(uc.get("technique")), _text(uc.get("tactic"))))
            out.append("- what it does: " + _text(uc.get("description")))
        else:
            out.append("- use-case file not found")
        out.append(_window_line(r))
        out.append("- delivered by: " + _text(r.get("executor") or (uc or {}).get("executor")))
        if uc:
            rules = uc.get("rules") or []
            out.append("- target rule: " + ("; ".join(_one_line(x) for x in rules) if rules else NA))
        out.append("")
    return out


def render_attack_report(results, usecases, night):
    """results: one final Result dict (or ledger row, the last per (id, run_ts)) per attack; usecases: id -> use-case doc."""
    results = list(results or [])
    usecases = usecases or {}
    lines = [
        "---",
        "night: " + _text(night),
        "attack_execution: %s over %d use-cases on %s" % (_verdict_counts(results) or NA, len(results), _hosts(results)),
        "---",
        "",
        "## Detected, prevented or missed",
        "",
    ]
    lines += _table(results, usecases) + ["", "## How each attack was executed", ""]
    lines += _details(results, usecases) if results else ["No detonation is on record, so there is nothing to describe.", ""]
    return "\n".join(lines).rstrip("\n") + "\n"


def _night_of(results):
    for r in results:
        start = r.get("attack_start")
        if start:
            return str(start)[:10]
    return NA


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render the attack sections of the nightly report from a results file.")
    ap.add_argument("results", help="JSON array with one final result per attack, i.e. the last ledger row per (id, run_ts) (an --emit-json file shows pre-recheck verdicts)")
    ap.add_argument("--usecases", default=None, help="use-case directory (default ../usecases)")
    ap.add_argument("--night", default=None, help="YYYY-MM-DD (default: date of the first attack_start)")
    args = ap.parse_args(argv)
    try:
        with open(args.results) as fh:
            results = json.load(fh)
    except (OSError, ValueError) as e:
        print("report_md: cannot read %s: %s" % (args.results, e), file=sys.stderr)
        return 2
    if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
        print("report_md: %s is not a JSON array of results" % args.results, file=sys.stderr)
        return 2
    ucdir = args.usecases or os.path.join(HERE, "..", "usecases")
    if not os.path.isdir(ucdir):
        if args.usecases:
            print("report_md: no such use-case directory: %s" % ucdir, file=sys.stderr)
            return 2
        print("report_md: default use-case directory %s is missing, rendering without it" % ucdir, file=sys.stderr)
    usecases = load_usecase_docs(ucdir)
    sys.stdout.write(render_attack_report(results, usecases, args.night or _night_of(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
