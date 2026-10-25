# rules/engine/test_run_registry_isolation.py
"""A registry error must cost the subcommands that READ the registry, and nothing else.

On 2026-09-03 it cost the whole nightly loop. `main()` called `load_usecases` above
every branch, ONE use-case named a rule that Elastic ships installed-but-disabled,
and the LoaderError took down `--ensure-agent` - which opens no use-case file at all.
PREPARE went red at `sandcat_deployed`, nothing detonated, and the stage-0a carry-over
re-check lost the previous night's PENDING rows on the same exception.

Both `--ensure-agent` and `--reconcile` carry comments in run.py saying they must be
reachable with no use-case, because validation's PREPARE gate cannot go green without
them. The eager load made those comments false. These tests hold the line by RUNNING
the CLI against a deliberately broken registry, not by reading the source.
"""
import contextlib
import io
import os
import unittest
from unittest import mock

import run as runmod
import testenv
from loader import LoaderError


def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()

HERE = os.path.dirname(os.path.abspath(__file__))
BROKEN = os.path.join(HERE, "fixtures", "usecases_unresolvable")
SAMPLE = os.path.join(HERE, "fixtures", "rules_export.sample.ndjson")


class _FakeCaldera:
    """Reports a live agent, so --ensure-agent needs neither CALDERA nor WinRM."""

    def __init__(self, cfg):
        self.cfg = cfg

    def is_agent_alive(self):
        return True


@contextlib.contextmanager
def _broken_registry():
    with mock.patch.object(runmod, "UC_DIR", BROKEN), \
         mock.patch.object(runmod, "EXPORT", SAMPLE), \
         mock.patch.object(runmod, "CalderaClient", _FakeCaldera):
        yield


def _run(argv):
    """main() with stdout swallowed; returns the exit code."""
    with _broken_registry(), contextlib.redirect_stdout(io.StringIO()) as out:
        code = runmod.main(argv)
    return code, out.getvalue()


class TestRegistryErrorsDoNotBlockTheGateSubcommands(unittest.TestCase):
    def test_the_fixture_registry_really_is_broken(self):
        """Otherwise every test below would pass for the wrong reason."""
        from loader import load_usecases
        with self.assertRaises(LoaderError):
            load_usecases(BROKEN, SAMPLE)

    def test_ensure_agent_survives_it(self):
        code, out = _run(["--ensure-agent"])
        self.assertEqual(code, 0)
        self.assertIn('"ok": true', out.lower())

    def test_a_subcommand_that_reads_the_registry_still_fails_loud(self):
        """The other half of the contract: isolation is not silence. --list has to
        keep raising, or the fix would have traded a crash for a lie."""
        with self.assertRaises(LoaderError):
            _run(["--list", "--all"])

    def test_select_nightly_still_fails_loud(self):
        with self.assertRaises(LoaderError):
            _run(["--select-nightly", "5", "--json"])


if __name__ == "__main__":
    unittest.main()
