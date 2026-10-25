# rules/engine/dataset_export.py
"""The catalogue, the lagged record and the scoreboard as files a researcher can cite.

build() is a pure function of its arguments; main() reads the use-case files, the ledger and the
lab-hosts registry and writes the dataset folder. Three rules decide what leaves the building:

  1. Only use-cases that are safe to describe are published: `safety: never`, drafts (not yet part
     of the nightly, and kept private by the public export too) and the canary use-cases are
     neither in the catalogue nor in the record.
  2. The record is lagged. A night is published only once it is `lag_days` old, so a rule author
     cannot read today's gaps off the dataset before they have had time to close them.
  3. Hosts become roles. The ledger carries host names, aliases and ids of the attack range; the
     record carries one word (workstation, domain_controller, unknown) and nothing it could be
     joined back to. `output` and `nonce` never leave the ledger either.

The record keeps the rows of ids the use-case directory does not know (a use-case deleted after it
ran): they are neither in the catalogue nor in the scoreboard, and nothing marks them safe or
unsafe, so schema.md says so. The scoreboard covers the catalogue use-cases only.
"""
import argparse
import csv
import datetime
import io
import json
import os
import statistics
import sys

from schema import VALID_SAFETY

HERE = os.path.dirname(os.path.abspath(__file__))

CATALOGUE_KEYS = ("id", "title", "technique", "tactic", "severity", "safety", "evidence",
                  "expect", "executor", "rules", "rule_ids")
RECORD_KEYS = ("id", "verdict", "attack_start", "attack_end", "run_ts", "rechecked_at", "latency_s",
               "rule_ids", "co_firing", "rule_versions", "rule_query_hashes", "host_role")
# PENDING (waiting for the rule to run) and ABORT (the detonation did not happen) are the loop, not
# the rule: they stay in the record and never count as a night.
FINAL_VERDICTS = ("DETECTED", "PREVENTED", "MISSED", "INCONCLUSIVE")
PROVEN_VERDICTS = ("DETECTED", "PREVENTED")
# A co_firing entry in the real ledger is a dict; only these keys of it are published.
CO_FIRING_KEYS = ("name", "rule_id", "prevented", "ts")

SCHEMA_MD = """\
# Dataset schema

Four data files, one citation file. All dates are ISO 8601, all times UTC unless an offset is given.
Output is deterministic: sorted keys, stable ordering, a trailing newline.

## catalogue.json and catalogue.csv

One entry per use-case, sorted by id. Use-cases whose `safety` is `never`, drafts (`status: draft`)
and the `canary/` use-cases are not listed. In the CSV, list columns are joined with `; `.

| column | type | meaning |
|---|---|---|
| id | string | stable use-case id, `<tactic folder>/<name>` |
| title | string | short human title |
| technique | string | MITRE ATT&CK technique id |
| tactic | string | MITRE ATT&CK tactic |
| severity | string | severity the detection rule is expected to carry |
| safety | string | `safe` (runs unattended) or `supervised` |
| evidence | string or null | `real_behaviour` (the real thing ran) or `stand_in` (a harmless imitation of it) |
| expect | string | `detected`, `env_gap` or `not_enabled`: what the lab is expected to show |
| executor | string | how the behaviour is produced on the lab host |
| rules | list of string | names of the detection rules the use-case targets |
| rule_ids | list of string | ids of those rules in the SIEM export; empty when the dataset was built without the export or `expect` is not `detected` |

## record.jsonl

One JSON object per line, sorted by `attack_start`. Only rows whose `attack_start` date is on or
before `until` minus `lag_days` are published; a row without an `attack_start` or without a verdict
is not published. Rows of `canary/` ids and of `safety: never` or draft use-cases are never published. A row
whose id is not in the catalogue (a use-case removed after it ran) is published as is: nothing in
this dataset says whether that use-case was safe, so treat such rows with that in mind.

| column | type | meaning |
|---|---|---|
| id | string | use-case id |
| verdict | string | `DETECTED`, `PREVENTED`, `MISSED`, `INCONCLUSIVE` (the four verdicts that count as a night), `PENDING` (not judged yet) or `ABORT` (the detonation did not run) |
| attack_start | string | when the behaviour started |
| attack_end | string or null | when it ended |
| run_ts | string | when the row was written |
| rechecked_at | string or null | when the verdict was last re-judged |
| latency_s | number or null | seconds from attack start to the alert, for detections |
| rule_ids | list of string | ids of the rules the use-case targeted that night |
| co_firing | list | other rules that fired in the window: objects with `name`, `rule_id`, `prevented`, `ts` (older rows may hold plain names) |
| rule_versions | object | rule id to the rule version that was live |
| rule_query_hashes | object | rule id to a hash of the rule query that was live |
| host_role | string | role of the host the behaviour ran on: `workstation`, `domain_controller` or `unknown` |

Host names, addresses, host ids, command output and nonces are not published.

## scoreboard.json

Aggregates over the record rows of the catalogue use-cases (rows of ids outside the catalogue are not
counted). Only `DETECTED`, `PREVENTED`, `MISSED` and `INCONCLUSIVE` rows are nights.

| column | type | meaning |
|---|---|---|
| generated | string | the day the file was written |
| until | string | the date the dataset was cut at |
| lag_days | integer | publication lag in days |
| totals.use_cases | integer | use-cases in the catalogue |
| totals.rows | integer | rows in record.jsonl |
| totals.nights | integer | nights counted over all use-cases |
| use_cases.<id>.nights | integer | nights of the use-case |
| use_cases.<id>.detected | integer | nights ending `DETECTED` |
| use_cases.<id>.prevented | integer | nights ending `PREVENTED` |
| use_cases.<id>.missed | integer | nights ending `MISSED` |
| use_cases.<id>.inconclusive | integer | nights ending `INCONCLUSIVE` |
| use_cases.<id>.latest_final | string or null | verdict of the newest night |
| use_cases.<id>.latest_final_at | string or null | `attack_start` of the newest night |
| use_cases.<id>.median_latency_s | number or null | median latency over `DETECTED` rows that have one |
| use_cases.<id>.proof_age_days | integer or null | days from the newest `DETECTED` or `PREVENTED` row to `until` |

## CITATION.cff

Citation File Format 1.2.0. `version` and `date-released` are the `until` date. The `url` is a
placeholder until the dataset has an address.
"""


def _as_date(value, what):
    try:
        return datetime.date.fromisoformat(str(value))
    except ValueError:
        raise ValueError(f"{what} must be YYYY-MM-DD, got {value!r}")


def _private(uc):
    """Same test as the slice-4 export (stage.py) plus the canary: never, draft and canary stay out."""
    return (uc.get("safety") == "never" or uc.get("status") == "draft"
            or str(uc.get("id", "")).startswith("canary/"))


def _catalogue(usecases):
    out = []
    for uc in usecases:
        if _private(uc):
            continue
        entry = {k: uc.get(k) for k in CATALOGUE_KEYS}
        entry["expect"] = uc.get("expect") or "detected"
        entry["rules"] = list(uc.get("rules") or [])
        entry["rule_ids"] = list(uc.get("rule_ids") or [])
        out.append(entry)
    return sorted(out, key=lambda e: e["id"])


def _role_lookup(hosts):
    """Lower-cased name, alias or host id to role. An entry without a role is a workstation, as in labhosts."""
    entries = hosts.get("hosts") if isinstance(hosts, dict) else hosts
    table = {}
    for h in entries or []:
        role = h.get("role") or "workstation"
        keys = [h.get("name"), h.get("host_id")] + list(h.get("aliases") or [])
        for k in keys:
            if k not in (None, ""):
                table.setdefault(str(k).lower(), role)
    return table


def _host_role(host, table):
    # Only the row's own name is looked up (its id only when it has no name): a row carries the
    # aliases of the machine it ran on and an id that may be shared, and neither may rescue a name
    # the registry does not know, or an unknown machine would be shown as a lab role.
    if isinstance(host, str):
        host = {"name": host}
    if not isinstance(host, dict):
        return "unknown"
    key = host.get("name") or host.get("id")
    if key in (None, ""):
        return "unknown"
    return table.get(str(key).lower(), "unknown")


def _co_firing(items):
    out = []
    for c in items or []:
        if isinstance(c, dict):
            out.append({k: c[k] for k in CO_FIRING_KEYS if k in c})
        else:
            out.append(c)
    return out


def _record_row(row, table):
    out = {k: row.get(k) for k in RECORD_KEYS if k not in ("rule_ids", "co_firing", "rule_versions",
                                                           "rule_query_hashes", "host_role")}
    out["rule_ids"] = list(row.get("rule_ids") or [])
    out["co_firing"] = _co_firing(row.get("co_firing"))
    out["rule_versions"] = dict(row.get("rule_versions") or {})
    out["rule_query_hashes"] = dict(row.get("rule_query_hashes") or {})
    out["host_role"] = _host_role(row.get("host"), table)
    return out


def _sort_key(r):
    return (r["attack_start"], r.get("run_ts") or "", r["id"])


def _scoreboard(catalogue, record, until, lag_days, today):
    by_id = {c["id"]: [] for c in catalogue}
    for r in record:
        if r["id"] in by_id and r["verdict"] in FINAL_VERDICTS:
            by_id[r["id"]].append(r)
    until_d = _as_date(until, "until")
    use_cases, nights_total = {}, 0
    for uid, rows in by_id.items():
        rows = sorted(rows, key=_sort_key)
        count = lambda v: sum(1 for r in rows if r["verdict"] == v)
        lat = [r["latency_s"] for r in rows
               if r["verdict"] == "DETECTED" and isinstance(r["latency_s"], (int, float))]
        proven = [r for r in rows if r["verdict"] in PROVEN_VERDICTS]
        age = None
        if proven:
            age = (until_d - _as_date(proven[-1]["attack_start"][:10], "attack_start")).days
        use_cases[uid] = {
            "nights": len(rows), "detected": count("DETECTED"), "prevented": count("PREVENTED"),
            "missed": count("MISSED"), "inconclusive": count("INCONCLUSIVE"),
            "latest_final": rows[-1]["verdict"] if rows else None,
            "latest_final_at": rows[-1]["attack_start"] if rows else None,
            "median_latency_s": float(statistics.median(lat)) if lat else None,
            "proof_age_days": age,
        }
        nights_total += len(rows)
    return {"generated": today, "until": until, "lag_days": lag_days,
            "totals": {"use_cases": len(catalogue), "rows": len(record), "nights": nights_total},
            "use_cases": use_cases}


def build(usecases, ledger_rows, hosts, until, lag_days, today=None):
    until_d = _as_date(until, "until")
    if not isinstance(lag_days, int) or isinstance(lag_days, bool) or lag_days < 0:
        raise ValueError(f"lag_days must be a non-negative integer, got {lag_days!r}")
    cutoff = (until_d - datetime.timedelta(days=lag_days)).isoformat()
    private_ids = {uc.get("id") for uc in usecases if _private(uc)}
    table = _role_lookup(hosts)

    record = []
    for row in ledger_rows:
        start = row.get("attack_start")
        # Without a date the lag cannot be applied, and without a verdict there is nothing to cite.
        if not isinstance(start, str) or not row.get("verdict"):
            continue
        if (str(row.get("id")).startswith("canary/") or row.get("id") in private_ids
                or start[:10] > cutoff):
            continue
        record.append(_record_row(row, table))
    record.sort(key=_sort_key)

    catalogue = _catalogue(usecases)
    today = today or datetime.date.today().isoformat()
    return {"catalogue": catalogue, "record": record,
            "scoreboard": _scoreboard(catalogue, record, until, lag_days, today)}


def _json(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _catalogue_csv(catalogue):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CATALOGUE_KEYS)
    for c in catalogue:
        w.writerow(["; ".join(str(x) for x in v) if isinstance(v, list) else ("" if v is None else v)
                    for v in (c[k] for k in CATALOGUE_KEYS)])
    return buf.getvalue()


def _citation(until):
    return ("cff-version: 1.2.0\n"
            "message: If you use this dataset, please cite it as below.\n"
            "title: Nightly detection validation record and use-case catalogue\n"
            "authors:\n"
            "  - name: Zybur\n"
            f"date-released: {until}\n"
            f"version: {until}\n"
            "license: CC-BY-4.0\n"
            "url: https://example.org/replace-with-the-dataset-url\n")


def write(out_dir, built, until):
    os.makedirs(out_dir, exist_ok=True)
    files = {
        "catalogue.json": _json(built["catalogue"]),
        "catalogue.csv": _catalogue_csv(built["catalogue"]),
        "record.jsonl": "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                                for r in built["record"]),
        "scoreboard.json": _json(built["scoreboard"]),
        "schema.md": SCHEMA_MD,
        "CITATION.cff": _citation(until),
    }
    for name, text in files.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="") as f:
            f.write(text)


def _resolve_rule_ids(usecases, export_path):
    """Rule ids through ruleid.build_lock, the resolution run.py uses; a name that resolves to no
    enabled rule raises, so a dataset never claims a target the export does not hold."""
    from ruleid import build_lock
    lock = build_lock(usecases, export_path)
    for uc in usecases:
        ids = []
        if uc.get("expect", "detected") == "detected":
            for name in uc.get("rules") or []:
                rid = lock[name]["rule_id"]
                if rid not in ids:
                    ids.append(rid)
        uc["rule_ids"] = ids


def main(argv=None):
    ap = argparse.ArgumentParser(description="Write the catalogue, the lagged record and the scoreboard.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--usecases", required=True)
    ap.add_argument("--until", required=True)
    ap.add_argument("--lag-days", type=int, default=90)
    ap.add_argument("--no-lock", action="store_true",
                    help="skip rule-id resolution (rule_ids stay empty); no rules export needed")
    args = ap.parse_args(argv)

    import ledger
    import labhosts
    from loader import load_usecase_docs
    # ledger.read answers a missing file with no rows: an empty record would look like a lag that
    # cut everything, so a mistyped path is refused here.
    if not os.path.isfile(args.ledger):
        print(f"dataset_export: ledger not found: {args.ledger}", file=sys.stderr)
        return 2
    export = os.environ.get("RULES_EXPORT") or os.path.join(HERE, "..", "rules_export.ndjson")
    try:
        usecases = list(load_usecase_docs(args.usecases).values())
        # The `safety: never` filter only knows the ids it has read. load_usecase_docs skips a file
        # it cannot parse, and a mistyped folder yields nothing: either would publish the rows of
        # the attacks that are not meant to leave, so the count of files must match the count read.
        files = sum(1 for _, _, fs in os.walk(args.usecases) for f in fs
                    if f.endswith(".yaml") and not f.startswith("_"))
        if not usecases or files != len(usecases):
            raise ValueError(f"{len(usecases)} use-case(s) read from {files} file(s) in {args.usecases}; "
                             "refusing to publish rows whose safety cannot be checked")
        # The filter compares `safety` with the literal `never` and `status` with `draft`: a typo
        # (`Never`, `nevr`, a missing key) would pass it and publish the use-case and its rows, so
        # an invalid value is refused here, the same check the nightly loader and lint apply.
        bad = sorted(str(uc.get("id")) for uc in usecases
                     if uc.get("safety") not in VALID_SAFETY or uc.get("status") not in (None, "draft"))
        if bad:
            raise ValueError(f"{len(bad)} use-case(s) with an invalid safety or status value "
                             f"(first: {bad[0]}); refusing to publish rows whose safety cannot be checked")
        if not args.no_lock:
            _resolve_rule_ids(usecases, export)
        hosts = labhosts.load_lab_hosts(args.hosts)
        built = build(usecases, ledger.read(args.ledger), hosts, args.until, args.lag_days)
    except Exception as e:  # a bad input is a message and exit 2, never a half-written dataset
        print(f"dataset_export: {e}", file=sys.stderr)
        return 2
    write(args.out, built, args.until)
    print(f"dataset: use-cases={len(built['catalogue'])} rows={len(built['record'])} "
          f"until={args.until} lag_days={args.lag_days}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
