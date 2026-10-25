# rules/engine/siem/recorded.py
"""Alerts read from a file: the adapter a replay uses, so no SIEM and no lab are needed.

`<path>/alerts.json` is the list a live adapter returned for one recorded night. It is
handed back as is: the classifier already filters by rule, host and time, and filtering
here as well would be a second, silent copy of those rules.
"""
import json
import os


class RecordedAdapter:
    name = "recorded"

    def __init__(self, path):
        self.path = path

    def query_alerts(self, rule_ids, since_iso, hosts=None):
        try:
            with open(os.path.join(self.path, "alerts.json")) as f:
                alerts = json.load(f)
        except (OSError, ValueError):
            return None  # absent or unreadable: could not measure, never an empty list
        return alerts if isinstance(alerts, list) else None
