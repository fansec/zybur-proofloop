# rules/engine/test_caldera_client.py
import json, os, unittest
from config import load_config, subst
import testenv
from caldera_client import CalderaClient

def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()


class FakeResp:
    def __init__(self, payload): self._p = json.dumps(payload).encode()
    def read(self): return self._p
    def __enter__(self): return self
    def __exit__(self, *a): return False

class FakeHttp:
    def __init__(self, payload): self.payload = payload; self.last = None
    def Request(self, url, data=None, method=None):
        self.last = {"url": url, "data": data, "method": method, "headers": {}}
        req = self.last
        class R:
            def add_header(self, k, v): req["headers"][k] = v
        return R()
    def urlopen(self, req, timeout=None): return FakeResp(self.payload)

class TestCalderaClient(unittest.TestCase):
    def test_load_config_defaults(self):
        # No lab fact has a default since 2026-10-22: unset, the server is None (and
        # --preflight names it); set, the environment wins. The group is a label.
        with testenv.no_lab_values():
            cfg = load_config()
        self.assertIsNone(cfg["server"])
        self.assertEqual(cfg["group"], "red")
        with testenv.no_lab_values(CALDERA_SERVER="http://caldera.example.invalid:8888"):
            self.assertEqual(load_config()["server"], "http://caldera.example.invalid:8888")
    def test_subst_templates(self):
        cfg = {"server": "http://s:8888", "win_host": "1.2.3.4", "attacker_ip": "5.6.7.8"}
        self.assertEqual(subst("dl {{SERVER}}/file for {{WIN_HOST}}", cfg),
                         "dl http://s:8888/file for 1.2.3.4")
        self.assertEqual(subst("no placeholders", cfg), "no placeholders")
        self.assertIsNone(subst(None, cfg))
    def test_subst_refuses_a_lab_value_nobody_configured(self):
        # None would otherwise be written into the attack command as the text "None".
        cfg = {"server": None, "win_host": "1.2.3.4", "attacker_ip": None}
        with self.assertRaises(ValueError) as cm:
            subst("curl {{SERVER}}/x", cfg)
        self.assertIn("CALDERA_SERVER", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            subst("ping {{ATTACKER_IP}}", cfg)
        self.assertIn("ATTACKER_IP", str(cm.exception))
        self.assertEqual(subst("ping {{WIN_HOST}}", cfg), "ping 1.2.3.4")
        # A template the text does not use costs nothing, and an absent key is "".
        self.assertEqual(subst("plain", cfg), "plain")
        self.assertEqual(subst("x{{WIN_USER}}y", {}), "xy")
    def test_create_ability_posts_command(self):
        http = FakeHttp({"ability_id": "abil-1"})
        with testenv.no_lab_values(CALDERA_SERVER="http://caldera.example.invalid:8888",
                                   CALDERA_API_KEY="test-key"):
            c = CalderaClient(load_config(), http=http)
        uc = {"id": "c/x", "title": "T", "technique": "T1003.001", "tactic": "credential-access",
              "rules": ["R"], "params": {"shell": "psh", "command": "whoami"}}
        aid = c.create_ability(uc)
        self.assertEqual(aid, "abil-1")
        body = json.loads(http.last["data"])
        self.assertEqual(body["executors"][0]["command"], "whoami")
        self.assertEqual(body["executors"][0]["name"], "psh")

if __name__ == "__main__":
    unittest.main()


class TestLinkOutput(unittest.TestCase):
    """The command's ACTUAL stdout, which the engine never had.

    `link['output']` is CALDERA v4's boolean "was output collected" flag,
    serialised as the STRING 'True' - measured live 2026-07-28 against the lab
    server. So every caldera_command result carried output='True' and a use-case
    whose payload silently no-opped was indistinguishable from one that attacked.
    Two of that day's three MISSED verdicts were exactly that: the attack never
    happened and the detection got the blame.

    The real output is at /api/v2/operations/{op}/links/{link}/result, base64 of
    a {"stdout","stderr","exit_code"} envelope. Shape confirmed against the live
    server, not assumed - the repo's other reader (caldera/deploy_and_run.py)
    still base64-decodes link['output'] directly and swallows the exception.
    """

    def _client(self, payload):
        import caldera_client as cc
        c = CalderaClient({"server": "http://s:8888", "api_key": "k", "group": "red",
                           "planner_id": "p"})
        calls = []

        def fake_api(method, endpoint, data=None):
            calls.append(endpoint)
            return payload
        c.api = fake_api
        return c, calls

    @staticmethod
    def _b64(doc):
        import base64
        return base64.b64encode(json.dumps(doc).encode()).decode()

    def test_stdout_is_decoded_from_the_result_endpoint(self):
        c, calls = self._client({"result": self._b64(
            {"stdout": "Defender tampered\r\nRestored\r\n", "stderr": "", "exit_code": "0"})})
        out = c.link_output("op1", "lnk1")
        self.assertIn("Defender tampered", out)
        self.assertEqual(calls, ["/api/v2/operations/op1/links/lnk1/result"])

    def test_stderr_and_a_nonzero_exit_survive(self):
        # A payload that failed inside its own try/catch exits 0 and says so on
        # stdout; one that failed outright says so on stderr. Both must reach the
        # ledger or the verdict is a guess.
        c, _ = self._client({"result": self._b64(
            {"stdout": "Tamper protection blocked: Access denied", "stderr": "boom", "exit_code": "1"})})
        out = c.link_output("op1", "lnk1")
        self.assertIn("Tamper protection blocked", out)
        self.assertIn("boom", out)
        self.assertIn("1", out)

    def test_a_missing_result_is_said_out_loud_not_blanked(self):
        c, _ = self._client({})
        self.assertIn("no result", c.link_output("op1", "lnk1").lower())

    def test_an_unreachable_result_endpoint_never_raises(self):
        import caldera_client as cc
        c = CalderaClient({"server": "http://s:8888", "api_key": "k", "group": "red", "planner_id": "p"})

        def boom(*a, **kw):
            raise RuntimeError("404 Not Found")
        c.api = boom
        out = c.link_output("op1", "lnk1")
        self.assertIn("404", out, "the reason must reach the ledger")

    def test_raw_non_json_output_is_returned_as_text(self):
        # Older CALDERA base64s the raw output rather than a JSON envelope. Falling
        # back keeps this working across a server upgrade instead of blanking.
        import base64
        c, _ = self._client({"result": base64.b64encode(b"plain text output").decode()})
        self.assertIn("plain text output", c.link_output("op1", "lnk1"))

    def test_utf16le_powershell_output_decodes(self):
        import base64
        raw = b"\xff\xfe" + "OK\r\n".encode("utf-16-le")
        c, _ = self._client({"result": base64.b64encode(raw).decode()})
        self.assertIn("OK", c.link_output("op1", "lnk1"))


class TestAgentLiveness(unittest.TestCase):
    """`trusted` is not liveness.

    Measured live 2026-07-29: PREPARE recycled the lab, the agent died with the
    box, and `is_agent_alive` answered "alive" about a record 190 s stale because
    its second pass returned `alive[0]` with no age test. `--ensure-agent` then
    reported `already_alive: true`, no redeploy ran, and the gate sat on
    sandcat_beacon=1020 for the full 900 s window. CALDERA's untrusted_timer is
    300 s, so the dead-but-still-trusted window is ~30-300 s - exactly where a
    recycle lands. A cold boot hid it: an overnight-off agent is long untrusted.
    """

    def _client(self, agents):
        c = CalderaClient.__new__(CalderaClient)
        c.cfg = {"group": "red"}
        c.api = lambda method, path, body=None: agents
        return c

    def _agent(self, age_s, trusted=True, group="red"):
        from datetime import datetime, timezone, timedelta
        seen = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=age_s)
        return {"paw": "p1", "trusted": trusted, "group": group,
                "last_seen": seen.isoformat() + "Z"}

    def test_a_beaconing_agent_is_alive(self):
        c = self._client([self._agent(5)])
        self.assertIsNotNone(c.is_agent_alive())

    def test_a_dead_but_still_trusted_agent_is_NOT_alive(self):
        # THE REGRESSION. 190 s stale is inside CALDERA's 300 s untrusted_timer,
        # so the record still says trusted - and the old code returned it.
        c = self._client([self._agent(190)])
        self.assertIsNone(c.is_agent_alive(),
                          "a stale record must not block the redeploy")

    def test_an_agent_in_another_group_is_never_ours(self):
        c = self._client([self._agent(5, group="blue")])
        self.assertIsNone(c.is_agent_alive())

    def test_an_untrusted_agent_is_not_alive(self):
        c = self._client([self._agent(5, trusted=False)])
        self.assertIsNone(c.is_agent_alive())

    def test_an_unparseable_timestamp_deploys_rather_than_refuses(self):
        # Not evidence of death, and deploying twice beats never deploying.
        c = self._client([{"paw": "p1", "trusted": True, "group": "red",
                           "last_seen": "not-a-date"}])
        self.assertIsNotNone(c.is_agent_alive())
