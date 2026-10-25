import json, unittest

import close_alerts as ca


class FakeHTTP:
    """Minimal urllib stand-in: records requests, replays canned responses."""

    class Request:
        def __init__(self, url, data=None, method="GET"):
            self.url, self.data, self.method, self.headers = url, data, method, {}

        def add_header(self, k, v):
            self.headers[k] = v

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def urlopen(self, req, timeout=None, context=None):
        self.calls.append(req)
        status, body = self._responses.pop(0)
        if status >= 400:
            raise ca.HttpError(status, json.dumps(body))
        outer = self

        class R:
            def read(self_inner):
                return json.dumps(body).encode()

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False
        return R()


HOST = {"name": "production", "id": "00000000-0000-4000-8000-0000000000a1"}


class TestProbe(unittest.TestCase):
    def test_probe_true_on_200(self):
        http = FakeHTTP([(200, {"updated": 0})])
        ok, reason = ca.probe_can_close("https://kb", "k", http=http)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    # Measured 2026-07-25: ELASTIC_VALIDATION_API_KEY is read-scoped and 403s here.
    # The named reason is the whole point; a silent skip would look like success.
    def test_probe_false_on_403_with_the_reason(self):
        http = FakeHTTP([(403, {"message": "unauthorized for user, granted by [alerts-all]"})])
        ok, reason = ca.probe_can_close("https://kb", "k", http=http)
        self.assertFalse(ok)
        self.assertIn("alerts-all", reason)

    def test_probe_matches_nothing_so_it_cannot_mutate(self):
        http = FakeHTTP([(200, {"updated": 0})])
        ca.probe_can_close("https://kb", "k", http=http)
        body = json.loads(http.calls[0].data.decode())
        self.assertEqual(body["query"]["ids"]["values"], [ca.PROBE_ID])
        self.assertEqual(body["status"], "closed")

    def test_probe_false_without_a_key(self):
        ok, reason = ca.probe_can_close("https://kb", None)
        self.assertFalse(ok)
        self.assertIn("no api key", reason)


class TestClose(unittest.TestCase):
    def test_skips_and_names_the_reason_when_the_key_cannot_close(self):
        http = FakeHTTP([(403, {"message": "unauthorized, granted by [alerts-all]"})])
        out = ca.close_own_alerts("https://kb", "k", HOST, "2026-07-25T17:44:00Z", http=http)
        # None, never 0. Zero would claim we closed nothing when we closed nothing
        # BECAUSE WE COULD NOT TRY, which is a different fact.
        self.assertIsNone(out["closed"])
        self.assertIn("alerts-all", out["skipped"])
        self.assertEqual(len(http.calls), 1, "must not attempt the close after a failed probe")

    def test_closes_and_reports_the_count(self):
        http = FakeHTTP([(200, {"updated": 0}), (200, {"updated": 3})])
        out = ca.close_own_alerts("https://kb", "k", HOST, "2026-07-25T17:44:00Z", http=http)
        self.assertEqual(out["closed"], 3)
        self.assertIsNone(out["skipped"])

    def test_the_close_query_is_scoped_to_the_lab_host_and_the_run_window(self):
        http = FakeHTTP([(200, {"updated": 0}), (200, {"updated": 1})])
        ca.close_own_alerts("https://kb", "k", HOST, "2026-07-25T17:44:00Z",
                            until_iso="2026-07-25T18:44:00Z", http=http)
        body = json.loads(http.calls[1].data.decode())
        f = body["query"]["bool"]["filter"]
        self.assertIn({"term": {"kibana.alert.workflow_status": "open"}}, f)
        self.assertIn({"range": {"@timestamp": {"gte": "2026-07-25T17:44:00Z",
                                                "lte": "2026-07-25T18:44:00Z"}}}, f)
        should = body["query"]["bool"]["should"]
        self.assertIn({"term": {"host.name": "production"}}, should)
        self.assertIn({"term": {"host.id": HOST["id"]}}, should)
        self.assertEqual(body["query"]["bool"]["minimum_should_match"], 1)

    # An unscoped close would reach every open signal in the project, including a
    # real customer incident. The host clause is the only thing standing there.
    def test_refuses_to_run_without_a_host(self):
        with self.assertRaises(ValueError):
            ca.close_own_alerts("https://kb", "k", {}, "2026-07-25T17:44:00Z", http=FakeHTTP([]))

    def test_refuses_to_run_without_a_window_start(self):
        with self.assertRaises(ValueError):
            ca.close_own_alerts("https://kb", "k", HOST, None, http=FakeHTTP([]))

    def test_a_failed_close_reports_null_not_zero(self):
        http = FakeHTTP([(200, {"updated": 0}), (500, {"message": "boom"})])
        out = ca.close_own_alerts("https://kb", "k", HOST, "2026-07-25T17:44:00Z", http=http)
        self.assertIsNone(out["closed"])
        self.assertIn("500", out["skipped"])

    def test_a_reshaped_response_is_not_read_as_zero(self):
        http = FakeHTTP([(200, {"updated": 0}), (200, {"nothing": "familiar"})])
        out = ca.close_own_alerts("https://kb", "k", HOST, "2026-07-25T17:44:00Z", http=http)
        self.assertIsNone(out["closed"])
        self.assertIn("shape", out["skipped"])


class TestFinalVerdicts(unittest.TestCase):
    def test_pending_results_block_the_close(self):
        # Erasing a PENDING use-case's evidence turns tomorrow's re-check into a
        # false MISSED. Same reason deletion is gated on a durable bundle.
        self.assertFalse(ca.verdicts_are_final(["DETECTED", "PENDING"]))
        self.assertTrue(ca.verdicts_are_final(["DETECTED", "PREVENTED", "MISSED"]))
        self.assertFalse(ca.verdicts_are_final([]))
        self.assertFalse(ca.verdicts_are_final([None]))


if __name__ == "__main__":
    unittest.main()
