# rules/engine/siem/elastic.py
"""Elastic Security (Serverless) as a SIEM adapter: one _search over the alerts-as-data indices.

Moved here from verify.py on 2026-10-22 without a behaviour change: same query body, same
transport, and the same rule that anything that is not a clean answer is None, never an
empty list. verify.py re-exports the old names for its callers.
"""
import json
import ssl
import sys
import urllib.request

# One search page is all this adapter reads: no pagination, no look at the total. A response
# that FILLS the page may have dropped the very alert the verdict hangs on (a seven-day
# re-check on a noisy rule), and a dropped alert reads as MISSED. So a full page is not
# evidence: query_alerts returns None for it, which the classifier records as INCONCLUSIVE.
MAX_HITS = 1000

# The fields one alert is read from. Dotted names, because that is what _source holds
# whether ES returns them nested or flat (see _flat).
ALERT_SOURCE_FIELDS = [
    "kibana.alert.rule.rule_id", "kibana.alert.rule.name", "@timestamp",
    "kibana.alert.original_time", "event.ingested", "host.id", "host.name",
    "winlog.computer_name", "event.type", "event.dataset",
    "kibana.alert.group.id", "kibana.alert.group.index",
    "kibana.alert.building_block_type", "kibana.alert.rule.version",
]


def build_alert_query(rule_ids, since_iso, hosts=None):
    """One query answering both questions: did MY rule fire, and what else fired here.

    An empty host clause is omitted rather than sent as terms:[] - an empty terms
    filter is a coin flip between matching nothing and being ignored, and neither is
    a decision anyone made on purpose.
    """
    hosts = hosts or {}
    should = []
    if rule_ids:
        should.append({"terms": {"kibana.alert.rule.rule_id": list(rule_ids)}})
    if hosts.get("names"):
        should.append({"terms": {"host.name": list(hosts["names"])}})
    if hosts.get("ids"):
        should.append({"terms": {"host.id": list(hosts["ids"])}})
    return {
        "size": MAX_HITS,
        # Oldest first, so what a cap would cut is the same set every time, not whatever
        # relevance order Elasticsearch happened to give a filter-only query.
        "sort": [{"@timestamp": "asc"}],
        "_source": list(ALERT_SOURCE_FIELDS),
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": since_iso}}}],
            "should": should,
            "minimum_should_match": 1,
        }},
    }


def _flat(src, dotted):
    """Read a field that ES may return nested or dotted, without inventing a value."""
    if dotted in src:
        return src[dotted]
    cur = src
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class ElasticAdapter:
    name = "elastic"

    def __init__(self, es_url, api_key, http=urllib.request, ssl_ctx=None):
        self.es_url = es_url
        self.api_key = api_key
        self.http = http
        self.ssl_ctx = ssl_ctx

    def query_alerts(self, rule_ids, since_iso, hosts=None):
        """Return a list of alert dicts, or None if it could not be measured."""
        # No url is the same as no key: nothing to ask, so nothing was measured.
        if not (self.es_url and self.api_key):
            return None
        http, ssl_ctx = self.http, self.ssl_ctx
        body = json.dumps(build_alert_query(rule_ids, since_iso, hosts)).encode()
        # The WILDCARD, deliberately: the lab detonates into whatever space a rule is
        # scoped to, so this reads every alerts-as-data index rather than pinning the
        # default space. The JS side's default-space constant is ALERTS_INDEX in
        # onboarding/lib/elastic-namespace.js; onboarding/lib/index-names.test.js
        # asserts these two stay different on purpose.
        req = http.Request(f"{self.es_url}/.alerts-security.alerts-*/_search", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"ApiKey {self.api_key}")
        if ssl_ctx is None:
            ssl_ctx = ssl.create_default_context()
        try:
            with http.urlopen(req, timeout=30, context=ssl_ctx) as resp:
                data = json.loads(resp.read())
        except Exception:
            return None
        hits = data.get("hits", {}).get("hits")
        if hits is None:
            return None  # shape drift: could not measure, never an empty list
        if len(hits) >= MAX_HITS:
            print(f"elastic: {len(hits)} hits, window too wide to trust (cap {MAX_HITS}); "
                  f"could not measure", file=sys.stderr)
            return None
        out = []
        for h in hits:
            src = h.get("_source", {})
            host = src.get("host") if isinstance(src.get("host"), dict) else {}
            out.append({
                "rule_id": _flat(src, "kibana.alert.rule.rule_id"),
                "name": _flat(src, "kibana.alert.rule.name"),
                "@timestamp": src.get("@timestamp"),
                "original_time": _flat(src, "kibana.alert.original_time"),
                "event_ingested": _flat(src, "event.ingested"),
                "host_name": host.get("name") if host else _flat(src, "host.name"),
                "host_id": host.get("id") if host else _flat(src, "host.id"),
                "winlog_computer_name": _flat(src, "winlog.computer_name"),
                "event_type": _flat(src, "event.type"),
                "event_dataset": _flat(src, "event.dataset"),
                "group_id": _flat(src, "kibana.alert.group.id"),
                "group_index": _flat(src, "kibana.alert.group.index"),
                "building_block_type": _flat(src, "kibana.alert.building_block_type"),
                "rule_version": _flat(src, "kibana.alert.rule.version"),
            })
        return out
