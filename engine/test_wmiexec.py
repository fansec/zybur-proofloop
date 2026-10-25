"""Offline tests for the wmiexec executor (added 2026-10-14).

The embedded impacket script is not just string-checked: FakeDedup EXECUTES it
in-process against a fake impacket, so the ReturnValue decision, the WMI call chain
and the base64 round trip of the credentials are the code that runs in the netns,
not a description of it. Whether the rule fires is the live retest, not this file.
"""
import base64
import contextlib
import io
import os
import sys
import types
import unittest
from unittest import mock

from ctx import Ctx
from result import Result
import executors.plugins  # noqa: F401  (registers all plugins)
import executors.registry as reg
from executors.wmiexec import _script
from firewall import FIREWALL_RULES

SOURCE_IP = "198.51.100.150"
# Distinctive, and full of the characters that would break a string literal.
USER = 'zyb-wmi-"user"\\x'
PASS = "p'a\"ss\\w0rd-7f3"
CFG = {"win_host": "10.255.255.1", "win_user": USER, "win_pass": PASS,
       "attacker_ip": "198.51.100.103"}
def fake_impacket(log, return_value=0, process_id=4242, fail_at=None):
    """sys.modules entries standing in for the four impacket modules the script imports."""
    class Out:
        pass

    class Win32Process:
        def Create(self, command, cwd, env):
            log.append(("Create", command, cwd, env))
            if fail_at == "Create":
                raise Exception("rpc_s_access_denied")
            o = Out()
            if return_value is not None:
                o.ReturnValue = return_value
            if process_id is not None:
                o.ProcessId = process_id
            return o

    class Services:
        def GetObject(self, path):
            log.append(("GetObject", path))
            return Win32Process(), None

        def RemRelease(self):
            log.append(("Services.RemRelease",))

    class Login:
        def __init__(self, iface):
            log.append(("IWbemLevel1Login", iface))

        def NTLMLogin(self, namespace, locale, pctx):
            log.append(("NTLMLogin", namespace, locale, pctx))
            return Services()

        def RemRelease(self):
            log.append(("Login.RemRelease",))

    class DCOMConnection:
        def __init__(self, *a, **k):
            log.append(("DCOMConnection", a, k))
            if fail_at == "connect":
                raise Exception("Could not connect: [Errno 111] Connection refused")

        def CoCreateInstanceEx(self, clsid, iid):
            log.append(("CoCreateInstanceEx", clsid, iid))
            return "iface"

        def disconnect(self):
            log.append(("disconnect",))

    names = ["impacket", "impacket.dcerpc", "impacket.dcerpc.v5", "impacket.dcerpc.v5.dcom"]
    mods = {n: types.ModuleType(n) for n in names}
    dcomrt = types.ModuleType("impacket.dcerpc.v5.dcomrt")
    dcomrt.DCOMConnection = DCOMConnection
    wmi = types.ModuleType("impacket.dcerpc.v5.dcom.wmi")
    wmi.CLSID_WbemLevel1Login = "CLSID_WbemLevel1Login"
    wmi.IID_IWbemLevel1Login = "IID_IWbemLevel1Login"
    wmi.IWbemLevel1Login = Login
    dtypes = types.ModuleType("impacket.dcerpc.v5.dtypes")
    dtypes.NULL = "NULL"
    mods["impacket.dcerpc.v5.dcom"].wmi = wmi
    mods.update({dcomrt.__name__: dcomrt, wmi.__name__: wmi, dtypes.__name__: dtypes})
    return mods


class FakeDedup:
    """allocate() + run_in_netns() that executes the script against a fake impacket."""

    def __init__(self, raises=None, canned=None, **impacket_kw):
        self.allocated, self.runs, self.log = [], [], []
        self.raises, self.canned, self.impacket_kw = raises, canned, impacket_kw

    def allocate(self, key):
        self.allocated.append(key)
        return SOURCE_IP

    def run_in_netns(self, source_ip, code, timeout=60):
        self.runs.append((source_ip, code, timeout))
        if self.raises:
            raise self.raises
        if self.canned is not None:
            return self.canned
        buf = io.StringIO()
        with mock.patch.dict(sys.modules, fake_impacket(self.log, **self.impacket_kw)), \
                contextlib.redirect_stdout(buf):
            exec(compile(code, "<wmiexec-netns>", "exec"), {"__name__": "__netns__"})
        return 0, buf.getvalue().strip(), ""


class FakeFirewall:
    def __init__(self):
        self.opened, self.closed = [], []

    def open(self, session, executor_name, cfg, remoteip=None):
        self.opened.append((executor_name, remoteip))
        return [rn for rn, _, _ in FIREWALL_RULES[executor_name]]

    def close(self, session, rule_names):
        self.closed.append(list(rule_names))


class FakeSession:
    def __init__(self):
        self.ps = []

    def run_ps(self, cmd):
        self.ps.append(cmd)


def usecase(command="echo zyb_wmi > C:\\Windows\\Temp\\wmi_test.txt",
            cleanup='Remove-Item "C:\\Windows\\Temp\\wmi_test.txt" -Force'):
    return {"id": "lateral-movement/sample-wmi", "rule_ids": [],
            "executor": "wmiexec", "params": {"command": command}, "cleanup": cleanup}


def run(dedup=None, firewall=None, session=None, uc=None):
    dedup = dedup if dedup is not None else FakeDedup()
    firewall = firewall or FakeFirewall()
    session = session or FakeSession()
    ctx = Ctx(cfg=dict(CFG), winrm_factory=lambda: session, dedup=dedup, firewall=firewall)
    return reg.get("wmiexec")(uc or usecase(), ctx), dedup, firewall, session


class TestWmiexec(unittest.TestCase):
    def setUp(self):
        p = mock.patch("time.sleep", lambda *a, **k: None)
        p.start()
        self.addCleanup(p.stop)

    def test_registered(self):
        self.assertIn("wmiexec", reg.executor_names())

    def test_the_script_runs_in_the_netns_of_the_deduped_ip(self):
        r, d, _, _ = run()
        self.assertEqual(d.allocated, ["lateral-movement/sample-wmi"])
        self.assertEqual(len(d.runs), 1)
        self.assertEqual(d.runs[0][0], SOURCE_IP)
        self.assertEqual(d.runs[0][2], 90)
        self.assertIn(f"[src={SOURCE_IP}]", r.output)

    def test_the_firewall_is_scoped_to_the_deduped_ip_and_closed(self):
        _, _, fw, _ = run()
        self.assertEqual(fw.opened, [("wmiexec", SOURCE_IP)])
        self.assertEqual(fw.closed, [["P1-TEST-RPC-In", "P1-TEST-RPC-HighPorts"]])

    def test_the_firewall_is_closed_when_the_netns_run_raises(self):
        r, _, fw, s = run(dedup=FakeDedup(raises=RuntimeError("netns exec failed")))
        self.assertFalse(r.executed)
        self.assertTrue(r.status.startswith("WMI_FAIL"))
        self.assertEqual(len(fw.closed), 1)
        self.assertEqual(s.ps, [])

    def test_the_firewall_table_opens_rpc_and_its_high_ports(self):
        ports = {port for _, port, _ in FIREWALL_RULES["wmiexec"]}
        self.assertEqual(ports, {"135", "49152-65535"})
        self.assertNotIn("445", ports)

    def test_success_on_return_value_zero(self):
        r, d, _, _ = run()
        self.assertIsInstance(r, Result)
        self.assertTrue(r.executed)
        self.assertEqual(r.status, "SUCCESS")
        self.assertEqual(r.op_id, "direct-wmi-win32process")
        self.assertIn("ProcessId=4242", r.output)

    def test_a_nonzero_return_value_is_a_failure(self):
        # 2 = access denied, 9 = path not found: the call went through, no process.
        for rv in (2, 9, 21):
            with self.subTest(return_value=rv):
                r, _, _, s = run(dedup=FakeDedup(return_value=rv))
                self.assertFalse(r.executed)
                self.assertTrue(r.status.startswith("WMI_FAIL"))
                self.assertIn(f"ReturnValue={rv}", r.status)
                self.assertEqual(s.ps, [], "no cleanup for a process that was never created")

    def test_zero_without_a_process_id_or_no_return_value_is_a_failure(self):
        for kw in ({"process_id": None}, {"return_value": None}):
            with self.subTest(**kw):
                r, _, _, _ = run(dedup=FakeDedup(**kw))
                self.assertFalse(r.executed)

    def test_an_rpc_error_is_a_failure_and_still_disconnects(self):
        for at in ("connect", "Create"):
            with self.subTest(fail_at=at):
                r, d, fw, _ = run(dedup=FakeDedup(fail_at=at))
                self.assertFalse(r.executed)
                self.assertTrue(r.status.startswith("WMI_FAIL"))
                self.assertEqual(len(fw.closed), 1)
                if at == "Create":
                    self.assertIn(("disconnect",), d.log)

    def test_only_the_exact_success_line_counts(self):
        # dcomexec accepts any "SUCCESS" substring; here an error text carrying the
        # word, or a bare SUCCESS from some other script, must not read as a process.
        for stdout in ("SUCCESS", "WMI_FAIL: STATUS_SUCCESS but no object",
                       "x SUCCESS: Win32_Process.Create ReturnValue=0 ProcessId=1",
                       "SUCCESS: Win32_Process.Create ReturnValue=0 ProcessId=None"):
            with self.subTest(stdout=stdout):
                r, _, _, _ = run(dedup=FakeDedup(canned=(0, stdout, "")))
                self.assertFalse(r.executed)

    def test_the_wmi_chain_is_the_impacket_wmiexec_core(self):
        _, d, _, _ = run()
        kinds = [e[0] for e in d.log]
        self.assertEqual(kinds, ["DCOMConnection", "CoCreateInstanceEx", "IWbemLevel1Login",
                                 "NTLMLogin", "Login.RemRelease", "GetObject", "Create",
                                 "Services.RemRelease", "disconnect"])
        conn = d.log[0]
        self.assertEqual(conn[1][:3], ("10.255.255.1", USER, PASS))
        self.assertEqual(conn[1][3:], ("", "", "", ""))
        self.assertTrue(conn[2].get("oxidResolver"))
        self.assertEqual(d.log[1][1:], ("CLSID_WbemLevel1Login", "IID_IWbemLevel1Login"))
        self.assertEqual(d.log[3][1:], ("//./root/cimv2", "NULL", "NULL"))
        self.assertEqual(d.log[5], ("GetObject", "Win32_Process"))
        self.assertEqual(d.log[6], ("Create",
                                    "cmd.exe /Q /c echo zyb_wmi > C:\\Windows\\Temp\\wmi_test.txt",
                                    "C:\\", None))

    def test_the_default_child_writes_nothing(self):
        uc = usecase()
        uc["params"] = {}
        _, d, _, _ = run(uc=uc)
        self.assertEqual(d.log[6][1], "cmd.exe /Q /c echo zyb_wmi")

    def test_credentials_never_appear_unencoded_in_the_script(self):
        code = _script(SOURCE_IP, CFG, "echo zyb_wmi")
        for secret in (USER, PASS):
            self.assertNotIn(secret, code)
            self.assertIn(base64.b64encode(secret.encode()).decode(), code)
        # ...and the encoded values survive the round trip byte for byte, which
        # test_the_wmi_chain_is_the_impacket_wmiexec_core proves by executing it.
        compile(code, "<wmiexec-netns>", "exec")

    def test_the_cleanup_runs_over_winrm_after_a_created_process(self):
        _, _, _, s = run()
        self.assertEqual(s.ps, ['Remove-Item "C:\\Windows\\Temp\\wmi_test.txt" -Force'])

    def test_a_cleanup_failure_never_fails_the_run(self):
        class Boom(FakeSession):
            def run_ps(self, cmd):
                raise ConnectionError("winrm down")
        r, _, fw, _ = run(session=Boom())
        self.assertTrue(r.executed)
        self.assertEqual(len(fw.closed), 1)

    def test_no_dedup_refuses_before_touching_the_firewall(self):
        fw = FakeFirewall()
        ctx = Ctx(cfg=dict(CFG), winrm_factory=lambda: FakeSession(), dedup=None, firewall=fw)
        r = reg.get("wmiexec")(usecase(), ctx)
        self.assertFalse(r.executed)
        self.assertEqual(fw.opened, [])


if __name__ == "__main__":
    unittest.main()
