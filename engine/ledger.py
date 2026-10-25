# rules/engine/ledger.py
"""Append-only cross-run verdict history (state/ledger.jsonl)."""
import json, os

def append(path, entries):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a") as f:
        for e in entries:
            f.write(json.dumps(e, sort_keys=True) + "\n")

def read(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]

def last_verdict(path, usecase_id):
    v = None
    for e in read(path):
        if e.get("id") == usecase_id:
            v = e.get("verdict")
    return v
