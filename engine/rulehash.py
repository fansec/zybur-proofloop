# rules/engine/rulehash.py
"""The one rule query hash: what a proof was measured against.

A proof is stale when the rule's QUERY moved, not when Elastic bumped its version
(462 of the 493 pack rules were re-versioned in 2026-09 by tag-only commits).
validation/lib/rule-hash.js is the same function in JS; both assert
validation/fixtures/rule-hash.golden.json, and a disagreement is a bug in neither
side's test alone, so neither side may be "fixed" to match the other without finding
the encoding difference.

The hash is sha256, first 16 hex characters, over canonical JSON (keys sorted at every
level, no whitespace, non-ASCII kept as UTF-8) of the fields below. A key that is
absent or null is omitted; an empty list is NOT absent (`filters: []` is hashed as
`[]`). `index` is sorted because Elastic does not keep its order. No float may be
hashed: Python prints 1.0 where JS prints 1 (the real export carries none, scanned
2026-10-20).
"""
import hashlib, json, sys

HASHED_KEYS = (
    "type", "language", "query", "index", "filters", "threshold", "new_terms_fields",
    "history_window_start", "threat_query", "threat_index", "machine_learning_job_id",
    "anomaly_threshold",
)


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def rule_query_hash(rule):
    picked = {}
    for k in HASHED_KEYS:
        v = rule.get(k)
        if v is None:
            continue
        if k == "index" and isinstance(v, list):
            v = sorted(v)
        picked[k] = v
    return hashlib.sha256(canonical_json(picked).encode("utf-8")).hexdigest()[:16]


def check_golden(path):
    with open(path, encoding="utf-8") as f:
        cases = json.load(f)
    bad = [c["case"] for c in cases if rule_query_hash(c["rule"]) != c["hash"]]
    for name in bad:
        print(f"rule-hash: golden case {name!r} does not match", file=sys.stderr)
    if bad:
        return 1
    print(f"rule-hash: {len(cases)} of {len(cases)} golden hashes match")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--golden":
        sys.exit(check_golden(sys.argv[2]))
    print("usage: rulehash.py --golden <golden.json>", file=sys.stderr)
    sys.exit(2)
