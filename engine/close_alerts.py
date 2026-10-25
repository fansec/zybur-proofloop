# rules/engine/close_alerts.py
"""Close the alerts the validation loop caused, once their verdicts are final.

Hygiene, not correctness: verification correlates on `@timestamp >= attack_start`
and cannot be confused by an old alert. This keeps the Kibana view readable and the
janitor's numbers honest.

Two things make this safe to run unattended:

1. **It probes before it writes.** Measured 2026-07-25, the read-scoped
   `ELASTIC_VALIDATION_API_KEY` answers 403 on `POST /api/detection_engine/signals/status`
   ("granted by the Kibana privileges [alerts-all, ...]"). So the capability is
   probed with a query that matches a nonexistent signal id, and a refusal is
   returned as a NAMED SKIP. It is never reported as a close that happened.
2. **It is scoped to the lab host and the run window.** An unscoped close would
   reach every open signal in the project, including a real customer incident. The
   host clause is the only thing standing there, so a missing host is a hard error
   rather than a wider query.

`closed` is an integer or None. None means "we did not close, and here is why".
Zero means "we ran the close and it matched nothing". Collapsing those two is the
fake-zero class this whole subsystem exists to remove.
"""
import json, ssl, urllib.request

PROBE_ID = "zybur-capability-probe-nonexistent"
STATUS_PATH = "/api/detection_engine/signals/status"
FINAL_VERDICTS = {"DETECTED", "PREVENTED", "MISSED", "INCONCLUSIVE", "ABORT"}


class HttpError(Exception):
    def __init__(self, status, body=""):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status, self.body = status, body


def _post(kb_url, api_key, path, body, http=urllib.request, ssl_ctx=None):
    req = http.Request(f"{kb_url}{path}", data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"ApiKey {api_key}")
    req.add_header("elastic-api-version", "2023-10-31")
    req.add_header("kbn-xsrf", "true")
    if ssl_ctx is None:
        ssl_ctx = ssl.create_default_context()
    with http.urlopen(req, timeout=30, context=ssl_ctx) as resp:
        return json.loads(resp.read())


def probe_can_close(kb_url, api_key, http=urllib.request, ssl_ctx=None):
    """(True, None) if this key may close signals, else (False, reason).

    The probe targets a signal id that cannot exist, so it mutates nothing whatever
    the answer is.
    """
    if not api_key:
        return False, "no api key available for the signals status route"
    body = {"query": {"ids": {"values": [PROBE_ID]}}, "status": "closed"}
    try:
        _post(kb_url, api_key, STATUS_PATH, body, http, ssl_ctx)
        return True, None
    except HttpError as e:
        return False, f"signals status route refused this key ({e})"
    except Exception as e:  # transport, TLS, timeout
        return False, f"signals status probe failed: {e}"


def verdicts_are_final(verdicts):
    """PENDING blocks the close: tomorrow's re-check still needs the evidence."""
    vs = list(verdicts)
    if not vs:
        return False
    return all(v in FINAL_VERDICTS for v in vs)


def close_own_alerts(kb_url, api_key, host, since_iso, until_iso=None,
                     http=urllib.request, ssl_ctx=None):
    """Close open signals on the lab host inside the run window. Never wider."""
    name, hid = (host or {}).get("name"), (host or {}).get("id")
    if not name and not hid:
        raise ValueError("close_own_alerts refuses to run without a host: an unscoped "
                         "close would reach real customer incidents")
    if not since_iso:
        raise ValueError("close_own_alerts refuses to run without a window start")

    ok, reason = probe_can_close(kb_url, api_key, http, ssl_ctx)
    if not ok:
        return {"closed": None, "skipped": reason}

    should = []
    if name:
        should.append({"term": {"host.name": name}})
    if hid:
        should.append({"term": {"host.id": hid}})
    rng = {"gte": since_iso}
    if until_iso:
        rng["lte"] = until_iso
    body = {
        "query": {"bool": {
            "filter": [
                {"term": {"kibana.alert.workflow_status": "open"}},
                {"range": {"@timestamp": rng}},
            ],
            "should": should,
            "minimum_should_match": 1,
        }},
        "status": "closed",
    }
    try:
        data = _post(kb_url, api_key, STATUS_PATH, body, http, ssl_ctx)
    except Exception as e:
        return {"closed": None, "skipped": f"close failed: {e}"}
    updated = data.get("updated")
    if not isinstance(updated, int):
        return {"closed": None, "skipped": "close response shape not understood; "
                                           "refusing to report a count we did not read"}
    return {"closed": updated, "skipped": None}
