# rules/engine/testenv.py
"""Hermetic inputs for the engine tests that go through the lab registry or the rule pack.

The engine runs from configuration (config.py, labhosts.py, run.py read LAB_HOSTS_FILE,
ZYBUR_CREDS_FILE, RULES_EXPORT), so a test must not depend on the validation/ folder or
the live rule pack of the checkout it happens to sit in: the public export carries
neither. Tests that exercise code paths use these fixtures; tests that guard a fact
about the LIVE pack or registry say so with `requires_live_pack` and are skipped where
that file does not exist, instead of passing on something else.
"""
import contextlib
import os
import re
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
LAB_HOSTS_FIXTURE = os.path.join(FIXTURES, "lab-hosts.json")
SAMPLE_EXPORT = os.path.join(FIXTURES, "rules_export.sample.ndjson")
LIVE_EXPORT = os.path.join(HERE, "..", "rules_export.ndjson")
LIVE_LAB_HOSTS = os.path.join(HERE, "..", "..", "validation", "lab-hosts.json")

requires_live_pack = unittest.skipUnless(
    os.path.exists(LIVE_EXPORT), "the live rule pack (rules/rules_export.ndjson) is not in this tree")
requires_live_lab_hosts = unittest.skipUnless(
    os.path.exists(LIVE_LAB_HOSTS), "the live lab registry (validation/lab-hosts.json) is not in this tree")
# The whole private corpus: the canary, and the `never` and `draft` use-cases the public export
# leaves out (scripts/oss-export/manifest.txt). A test that pins the size or the make-up of THAT
# corpus says so with this; the canary folder is the marker because the export never carries it.
PRIVATE_CORPUS_MARK = os.path.join(HERE, "..", "usecases", "canary")
requires_private_corpus = unittest.skipUnless(
    os.path.isdir(PRIVATE_CORPUS_MARK), "the full private use-case corpus (rules/usecases/canary/) is not in this tree")


def use_fixture_lab_hosts(test):
    """Point the registry at the synthetic one for the length of one test."""
    patcher = mock.patch.dict(os.environ, {"LAB_HOSTS_FILE": LAB_HOSTS_FIXTURE})
    patcher.start()
    test.addCleanup(patcher.stop)


def use_sample_pack_for_module():
    """Call from a module's setUpModule: run.EXPORT is the sample pack for every test in it.

    For the tests that drive verify_results or the re-check paths with made-up rule ids:
    they need an export to resolve names and hashes against, not the live one."""
    import run
    patcher = mock.patch.object(run, "EXPORT", SAMPLE_EXPORT)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


def use_fixture_lab_hosts_for_module():
    """Call from a module's setUpModule: the synthetic registry for every test in it."""
    patcher = mock.patch.dict(os.environ, {"LAB_HOSTS_FILE": LAB_HOSTS_FIXTURE})
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


@contextlib.contextmanager
def no_lab_values(**env):
    """An environment with no lab value in it and no creds file to read, plus `env`.

    For the tests that assert what the engine does when nothing is configured, or that
    must not pick up the values of the box they happen to run on."""
    base = {k: v for k, v in os.environ.items()
            if not re.match(r"^(CALDERA_|WIN_|DC_|ATTACKER_|ES_|ELASTIC_|PROXMOX_|DEDUP_|RULES_EXPORT|LEDGER_FILE)", k)}
    base["ZYBUR_CREDS_FILE"] = os.devnull
    base.update(env)
    with mock.patch.dict(os.environ, base, clear=True):
        yield
