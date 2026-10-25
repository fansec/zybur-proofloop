import unittest

from impacket.krb5.asn1 import AS_REQ
from pyasn1.codec.der import decoder

from executors.kerberos_asreq import (
    ATTACK_MARKER, AUDIT_MARKER, CLEANUP_MARKER, PROBE_MARKER, SETUP_MARKER,
    build_asreq, run_kerberos_asreq,
)


CFG = {
    "target": "domain_controller", "win_host": "192.0.2.40",
    "win_user": "Administrator", "win_pass": "workstation-password",
    "dc_host": "192.0.2.40", "dc_user": "Administrator",
    "dc_pass": "dc-password",
}


class Response:
    def __init__(self, out=b"", err=b"", code=0):
        self.std_out = out
        self.std_err = err
        self.status_code = code


class DcFactory:
    def __init__(self, residual=False, audit=True):
        self.sessions = 0
        self.scripts = []
        self.residual = residual
        self.audit = audit

    def __call__(self):
        self.sessions += 1
        outer = self

        class Session:
            def run_ps(self, script):
                outer.scripts.append(script)
                if PROBE_MARKER in script:
                    value = "ZYBUR_KERBEROS_ASREQ_RESIDUAL:user" if outer.residual else PROBE_MARKER
                    return Response((value + "\n").encode())
                if CLEANUP_MARKER in script:
                    return Response((CLEANUP_MARKER + "\n").encode())
                if AUDIT_MARKER in script:
                    if outer.audit:
                        return Response((AUDIT_MARKER + "\n").encode())
                    return Response(err=b"4768 absent", code=1)
                return Response((SETUP_MARKER + ":LAB.INVALID\n").encode())

        return Session()


class WorkstationFactory:
    def __init__(self):
        self.sessions = 0
        self.scripts = []

    def __call__(self):
        self.sessions += 1
        outer = self

        class Session:
            def run_ps(self, script):
                outer.scripts.append(script)
                return Response((ATTACK_MARKER + ":49152\n").encode())

        return Session()


class TestAsReq(unittest.TestCase):
    def test_packet_is_a_valid_no_preauth_as_req(self):
        packet = build_asreq(
            "zv-krb-0123abcd", "lab.invalid", nonce=123,
            now=__import__("datetime").datetime(2026, 9, 5,
                                                   tzinfo=__import__("datetime").timezone.utc))
        request, rest = decoder.decode(packet, asn1Spec=AS_REQ())
        self.assertEqual(rest, b"")
        self.assertEqual(int(request["pvno"]), 5)
        self.assertEqual(int(request["msg-type"]), 10)
        self.assertEqual(str(request["req-body"]["realm"]), "LAB.INVALID")
        self.assertEqual(int(request["req-body"]["nonce"]), 123)

    def test_dc_local_execution_cleans_and_probes(self):
        dc, source = DcFactory(), WorkstationFactory()
        summary = run_kerberos_asreq(
            CFG, source, dc_factory=dc, token="0123abcd",
            password="Ephemeral!aA9")
        self.assertEqual(dc.sessions, 4)
        self.assertEqual(source.sessions, 1)
        self.assertIn("cleanup independently proven", summary)
        self.assertNotIn("Ephemeral!aA9", summary)
        self.assertIn("TcpClient", source.scripts[0])
        self.assertIn("HostToNetworkOrder", source.scripts[0])
        self.assertIn("Start-Sleep -Milliseconds 1000", source.scripts[0])
        self.assertNotIn("curl.exe", source.scripts[0])
        self.assertNotIn("UdpClient", source.scripts[0])
        self.assertTrue(any("EventID=4768" in script for script in dc.scripts))
        self.assertTrue(any("zv-krb-0123abcd" in script for script in dc.scripts))

    def test_residual_state_fails(self):
        with self.assertRaisesRegex(RuntimeError, "residual state"):
            run_kerberos_asreq(
                CFG, WorkstationFactory(), dc_factory=DcFactory(residual=True),
                token="0123abcd", password="Ephemeral!aA9")

    def test_missing_4768_fails_but_still_cleans_and_probes(self):
        dc = DcFactory(audit=False)
        with self.assertRaisesRegex(RuntimeError, "4768 confirmation failed"):
            run_kerberos_asreq(
                CFG, WorkstationFactory(), dc_factory=dc,
                token="0123abcd", password="Ephemeral!aA9")
        self.assertTrue(any(CLEANUP_MARKER in script for script in dc.scripts))
        self.assertTrue(any(PROBE_MARKER in script for script in dc.scripts))

    def test_requires_domain_controller_target(self):
        with self.assertRaisesRegex(ValueError, "target: domain_controller"):
            run_kerberos_asreq(
                dict(CFG, target="workstation"), WorkstationFactory(),
                dc_factory=DcFactory(), token="0123abcd", password="Ephemeral!aA9")


if __name__ == "__main__":
    unittest.main()
