"""Slice 8 acceptance: a full page from Elastic is "could not measure", never evidence.

Green since slice 8 (2026-10-24); it was pending_test_elastic_truncation.py. The external review
(2026-10-24): the adapter asks for exactly 1,000 hits with no sort, no pagination and no check of
the total, so a wide window (a seven-day re-check on a noisy rule) can drop the target alert and
the row reads MISSED.

Spec: siem.elastic.MAX_HITS = 1000 is the page size the query sends, the query sorts by @timestamp
ascending so a cap is deterministic, and a response carrying MAX_HITS hits returns None (the
classifier's INCONCLUSIVE path) with one stderr line that names the count and says the window is
too wide to trust. One hit below the cap is a measurement.
"""
import io
import json
import unittest
import urllib.request
from contextlib import redirect_stderr

from siem import elastic
from siem.elastic import ElasticAdapter

SINCE = "2026-10-24T00:00:00Z"


def fake_http(n):
    payload = {"hits": {"hits": [
        {"_source": {"kibana": {"alert": {"rule": {"rule_id": "r"}}}, "host": {"name": "ws"},
                     "@timestamp": "2026-10-24T01:00:00Z"}}
        for _ in range(n)]}}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(payload).encode()

    class _Http:
        Request = urllib.request.Request
        captured = {}

        @staticmethod
        def urlopen(req, timeout=None, context=None):
            _Http.captured["body"] = json.loads(req.data)
            return _Resp()
    return _Http


def adapter(http):
    # ssl_ctx=object(): anything not None, so no real TLS context is built for a fake transport.
    return ElasticAdapter("https://es.example", "k", http=http, ssl_ctx=object())


class Truncation(unittest.TestCase):
    def test_the_cap_is_named_and_is_the_page_size(self):
        self.assertEqual(elastic.MAX_HITS, 1000)
        self.assertEqual(elastic.build_alert_query(["r"], SINCE)["size"], elastic.MAX_HITS)

    def test_a_full_page_is_could_not_measure_not_evidence(self):
        err = io.StringIO()
        with redirect_stderr(err):
            out = adapter(fake_http(elastic.MAX_HITS)).query_alerts(["r"], SINCE)
        self.assertIsNone(out)
        self.assertIn("1000 hits", err.getvalue())
        self.assertIn("too wide", err.getvalue())

    def test_one_below_the_cap_is_a_measurement(self):
        out = adapter(fake_http(elastic.MAX_HITS - 1)).query_alerts(["r"], SINCE)
        self.assertEqual(len(out), elastic.MAX_HITS - 1)

    def test_the_query_sorts_by_time_so_a_cap_is_deterministic(self):
        http = fake_http(1)
        adapter(http).query_alerts(["r"], SINCE)
        self.assertEqual(http.captured["body"].get("sort"), [{"@timestamp": "asc"}])


if __name__ == "__main__":
    unittest.main()
