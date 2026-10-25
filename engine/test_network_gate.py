"""Edges of the `network:` class (slice 9, 2026-10-24) that test_network_class.py leaves open: the
detector's boundaries, a use-case in two refused classes, the --select-nightly flag path through
run.main, and the evidence rule still applying to an internet use-case that the nightly can draw.
"""
import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

import yaml

import lint
import run as runmod
import selector as sel
import testenv

NOW = datetime(2026, 10, 24, 4, 0, tzinfo=timezone.utc)


def uc(uid, **kw):
    d = {"id": uid, "title": uid, "safety": "safe", "expect": "detected", "executor": "winrm_command",
         "params": {"command": "whoami"}, "rules": ["r"], "technique": "T1059", "tactic": "execution"}
    d.update(kw)
    return d


class Detector(unittest.TestCase):
    def reaches(self, command, **kw):
        return lint.reaches_internet(dict(params={"command": command}, **kw))

    def test_a_resolver_is_matched_as_a_whole_address(self):
        for text in ("nslookup x 8.8.8.8", "dig @9.9.9.9. x", "Resolve-DnsName -Server 1.0.0.1 a", "x=8.8.4.4;"):
            self.assertTrue(self.reaches(text), text)
        for text in ("ping 11.1.1.1", "ping 1.1.1.10", "ping 8.8.8.88", "version 21.1.1.1.5"):
            self.assertFalse(self.reaches(text), text)

    def test_the_labs_templated_server_is_not_the_internet_but_a_literal_host_is(self):
        self.assertFalse(self.reaches("curl http://{{SERVER}}:8888/x"))
        self.assertFalse(self.reaches("curl https://{{ATTACKER_IP}}/x"))
        self.assertTrue(self.reaches("curl https://example.com/{{SERVER}}"))
        self.assertTrue(self.reaches("curl http://10.0.0.5/x"), "a private literal is still a URL the lint cannot judge")

    def test_nested_params_and_cleanup_are_walked(self):
        self.assertTrue(lint.reaches_internet({"params": {"a": [{"b": "iwr https://example.com/x"}]}}))
        self.assertTrue(lint.reaches_internet({"params": {}, "cleanup": "iwr https://example.com/x"}))
        self.assertFalse(lint.reaches_internet({"params": {"n": 5, "ok": True}, "description": "see https://example.com"}),
                         "prose is not a payload")

    def test_something_that_is_not_a_use_case_is_not_a_reach(self):
        for junk in (None, [], "x", {}):
            self.assertFalse(lint.reaches_internet(junk))


class Pool(unittest.TestCase):
    def test_lab_is_the_default_and_an_explicit_lab_is_in(self):
        pool = sel.safe_pool([uc("a"), uc("b", network="lab"), uc("c", network="internet")])
        self.assertEqual([u["id"] for u in pool], ["a", "b"])

    def test_the_meta_pool_count_follows_the_allowance(self):
        cases = [uc(f"a{i}") for i in range(6)] + [uc("net", network="internet")]
        _, without = sel.select_nightly(cases, [], 5, now=NOW)
        ids, with_ = sel.select_nightly(cases, [], 99, now=NOW, allow_internet=True)
        self.assertEqual((without["pool"], with_["pool"]), (6, 7))
        self.assertIn("net", ids)


class Gate(unittest.TestCase):
    def gate(self, selected, **flags):
        ns = argparse.Namespace(**{"allow_supervised": False, "allow_internet": False, **flags})
        return runmod.gate_selection(selected, ns)

    def test_a_supervised_internet_use_case_needs_both_flags(self):
        u = uc("both", safety="supervised", network="internet")
        allowed, lines = self.gate([u])
        self.assertEqual(allowed, [])
        self.assertEqual(len(lines), 2)
        allowed, lines = self.gate([u], allow_supervised=True)
        self.assertEqual((allowed, len(lines)), ([], 1))
        self.assertIn("--allow-internet", lines[0])
        allowed, lines = self.gate([u], allow_internet=True)
        self.assertEqual((allowed, len(lines)), ([], 1))
        self.assertIn("--allow-supervised", lines[0])
        allowed, lines = self.gate([u], allow_supervised=True, allow_internet=True)
        self.assertEqual(([x["id"] for x in allowed], lines), (["both"], []))

    def test_a_never_use_case_is_listed_once_whatever_else_it_is(self):
        _, lines = self.gate([uc("n", safety="never", network="internet")], allow_internet=True)
        self.assertEqual(lines, ["run: 1 never use-case(s) refused: n"])
        _, lines = self.gate([uc("n", safety="never", network="internet")])
        self.assertEqual(lines, ["run: 1 never use-case(s) refused: n"], "no flag could admit it, so no flag is suggested")


class SelectNightlyThroughMain(unittest.TestCase):
    def ids(self, *argv):
        out = io.StringIO()
        docs = [uc(f"lab{i}") for i in range(5)] + [uc("net", network="internet")]
        with testenv.no_lab_values(ZYBUR_ENV_ROOT=tempfile.mkdtemp(), LAB_HOSTS_FILE=testenv.LAB_HOSTS_FIXTURE), \
                mock.patch.object(runmod, "load_enabled_rules", return_value={}), \
                mock.patch.object(runmod, "load_usecases", return_value=docs), \
                mock.patch.object(runmod.ledgermod, "read", return_value=[]), \
                contextlib.redirect_stdout(out):
            rc = runmod.main(["--select-nightly", "99", "--json", *argv])
        self.assertEqual(rc, 0)
        return json.loads(out.getvalue())["ids"]

    def test_the_flag_reaches_the_selector(self):
        self.assertNotIn("net", self.ids())
        self.assertIn("net", self.ids("--allow-internet"))


class EvidenceStillOwed(unittest.TestCase):
    def test_a_safe_internet_use_case_without_evidence_is_an_error_not_a_warning(self):
        real_lock = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "usecases", "_ruleid.lock.json")
        rule = "LSASS Memory Dump Creation"
        with tempfile.TemporaryDirectory() as d, open(real_lock) as f:
            os.makedirs(os.path.join(d, "execution"))
            lock = os.path.join(d, "_ruleid.lock.json")
            with open(lock, "w") as out:
                json.dump({rule: json.load(f)[rule]}, out)
            doc = {"id": "execution/net", "title": "t", "rules": [rule], "technique": "T1059", "tactic": "execution",
                   "executor": "winrm_command", "safety": "safe", "network": "internet",
                   "params": {"command": "curl https://example.com/x.exe"}, "cleanup": "del x.exe"}
            with open(os.path.join(d, "execution", "net.yaml"), "w") as out:
                yaml.safe_dump(doc, out)
            errs = lint.lint(d, testenv.SAMPLE_EXPORT, lock, resolve=False)
        evidence = [e for e in errs if "no evidence" in e]
        self.assertTrue(evidence and all(not e.startswith("WARN") for e in evidence), evidence)


if __name__ == "__main__":
    unittest.main()
