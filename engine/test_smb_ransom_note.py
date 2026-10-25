# rules/engine/test_smb_ransom_note.py
"""The ransom-note payload against the live rule's shape, and its cleanup.

Added 2026-10-14 (triage n=66): rule 02bab13d needs the SAME file.name created
three times in a minute, and the old payload wrote four names once each. These
tests read the exported rule so the payload cannot drift from it again unseen.
"""
import fnmatch
import json
import os
import re
import unittest
from unittest import mock

import executors.smb_ransom_note as mod
import testenv
from cmdline import MAX_RUN_PS_CMDLINE, run_ps_cmdline_len
from ctx import Ctx
from reconcile import MANIFEST

HERE = os.path.dirname(os.path.abspath(__file__))
EXPORT = os.path.join(HERE, "..", "rules_export.ndjson")
USECASE = {"id": "impact/sample-ransom-note",
           "rule_ids": ["99999999-9999-4999-8999-999999999999"],
           "executor": "smb_ransom_note", "params": {"shell": "psh", "command": ""}}
TOKEN = "0123abcd"


def _rule_query():
    with open(EXPORT, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            doc = json.loads(line)
            if doc.get("rule_id") == USECASE["rule_ids"][0]:
                return doc["query"]
    raise AssertionError("rule 02bab13d is not in rules_export.ndjson")


def _globs(query, field):
    """The quoted patterns of `field : (...)` in an EQL query, unescaped."""
    match = re.search(re.escape(field) + r"\s*:\s*\(([^)]*)\)", query)
    if not match:
        raise AssertionError(f"no {field} list in the rule query")
    return [p.replace("\\\\", "\\") for p in re.findall(r'"([^"]*)"', match.group(1))]


def _matches(value, globs):
    # EQL's `:` wildcard compare is case-insensitive.
    return any(fnmatch.fnmatchcase(value.lower(), g.lower()) for g in globs)


class Response:
    def __init__(self, out="", err="", code=0):
        self.std_out = out.encode()
        self.std_err = err.encode()
        self.status_code = code


class FakeFactory:
    """WinRM sessions; cleanup_failures fails that many cleanup calls (pre-run first)."""

    def __init__(self, landed=3, cleanup_failures=0, fail_from_call=1, residual=False):
        self.sessions = 0
        self.runs = []
        self.events = None
        self.landed = landed
        self.cleanup_failures = cleanup_failures
        self.fail_from_call = fail_from_call
        self.residual = residual
        self.cleanup_calls = 0

    def __call__(self):
        self.sessions += 1
        number = self.sessions
        outer = self

        class Session:
            def run_ps(self, script):
                if mod.COUNT_MARKER in script:
                    kind, response = "count", Response(f"{mod.COUNT_MARKER}{outer.landed}\n")
                elif mod.CLEANUP_MARKER in script:
                    outer.cleanup_calls += 1
                    failing = (outer.fail_from_call <= outer.cleanup_calls
                               < outer.fail_from_call + outer.cleanup_failures)
                    kind = "cleanup"
                    response = (Response("", "file in use", 1) if failing
                                else Response(mod.CLEANUP_MARKER + "\n"))
                elif mod.PROBE_MARKER in script:
                    kind = "probe"
                    response = Response(("ZYBUR_RANSOM_NOTE_RESIDUAL:x" if outer.residual
                                         else mod.PROBE_MARKER) + "\n")
                else:
                    kind, response = "other", Response()
                outer.runs.append((number, kind))
                if outer.events is not None:
                    outer.events.append(kind)
                return response

        return Session()


class SmbRecorder:
    def __init__(self, events, rc=0, out="putting file x", err="", raises=None):
        self.events = events
        self.calls = []
        self.local_exists = []
        self.rc, self.out, self.err, self.raises = rc, out, err, raises

    def __call__(self, cfg, commands, source_ip=None):
        self.events.append("smbclient")
        self.calls.append((commands, source_ip))
        local = re.search(r"put (\S+) ", commands).group(1)
        self.local_exists.append(os.path.exists(local))
        if self.raises:
            raise self.raises
        return self.rc, self.out, self.err


# The rule body is Elastic-licensed and lives in the live pack only; where the pack is not
# in the tree (the public export) this class is skipped rather than run against a stand-in.
@testenv.requires_live_pack
class TestPayloadMatchesTheLiveRule(unittest.TestCase):
    def setUp(self):
        self.query = _rule_query()

    def test_the_rule_is_still_a_same_name_sequence_we_satisfy(self):
        self.assertIn("sequence by host.id, file.name", self.query)
        runs = int(re.search(r"with runs=(\d+)", self.query).group(1))
        self.assertGreaterEqual(mod.NOTE_RUNS, runs)
        self.assertIn("process.pid == 4", self.query)
        self.assertIn('event.action == "creation"', self.query)

    def test_note_name_extension_and_paths_match_the_rule(self):
        self.assertTrue(_matches(mod.NOTE_NAME, _globs(self.query, "file.name")))
        ext = mod.NOTE_NAME.rsplit(".", 1)[1]
        self.assertTrue(_matches(ext, _globs(self.query, "file.extension")))
        path_globs = _globs(self.query, "file.path")
        for remote in mod.note_paths(TOKEN):
            self.assertTrue(_matches("C:\\" + remote, path_globs), remote)

    def test_command_sequence_creates_the_same_name_in_fresh_folders(self):
        cmds = mod.build_smb_commands("/tmp/abc_README.txt", TOKEN).split("; ")
        self.assertEqual(cmds[0], f'mkdir "{mod.REMOTE_PARENT}"')
        puts = [c for c in cmds if c.startswith("put ")]
        self.assertEqual(len(puts), mod.NOTE_RUNS)
        targets = [re.search(r'"([^"]+)"$', c).group(1) for c in puts]
        self.assertEqual({t.rsplit("\\", 1)[1] for t in targets}, {mod.NOTE_NAME})
        folders = [t.rsplit("\\", 1)[0] for t in targets]
        self.assertEqual(len(set(folders)), mod.NOTE_RUNS)
        for folder, put in zip(folders, puts):
            self.assertTrue(folder.startswith(mod.REMOTE_PARENT + "\\" + TOKEN + "-"))
            self.assertLess(cmds.index(f'mkdir "{folder}"'), cmds.index(put))
        self.assertTrue(all(c.startswith(("mkdir ", "put ")) for c in cmds))

    def test_winrm_scripts_fit_the_cmd_exe_limit(self):
        for script in mod.build_scripts(TOKEN):
            self.assertLessEqual(run_ps_cmdline_len(script), MAX_RUN_PS_CMDLINE)

    def test_reconcile_manifest_probes_the_note_folder(self):
        self.assertIn(("file", mod.PARENT, "absent"), MANIFEST)
        for remote in mod.note_paths(TOKEN):
            self.assertTrue(("C:\\" + remote).startswith(mod.PARENT + "\\"))


class TestExecutorFlow(unittest.TestCase):
    def run_executor(self, factory, smb=None, **kw):
        events = []
        factory.events = events
        smb = smb or SmbRecorder(events)
        smb.events = events
        sleeps = []

        def sleep(seconds):
            events.append(f"sleep:{seconds}")
            sleeps.append(seconds)

        with mock.patch.object(mod, "smb_client_from", smb):
            result = mod.smb_ransom_note(
                USECASE, Ctx(cfg={"win_host": "192.0.2.10"}, winrm_factory=factory, **kw),
                token=TOKEN, sleep_fn=sleep)
        return result, events, smb, sleeps

    def test_clean_run_clears_writes_counts_then_proves_removal(self):
        factory = FakeFactory()
        result, events, smb, _ = self.run_executor(factory)
        self.assertEqual(result.status, "SUCCESS")
        self.assertTrue(result.executed)
        self.assertEqual(events, ["cleanup", "probe", "smbclient", "count", "sleep:15",
                                  "cleanup", "probe"])
        # One smbclient call carries every put, so all creations land inside maxspan.
        self.assertEqual(len(smb.calls), 1)
        self.assertEqual(smb.calls[0][0].count("put "), mod.NOTE_RUNS)
        self.assertEqual(smb.local_exists, [True])
        local = re.search(r"put (\S+) ", smb.calls[0][0]).group(1)
        self.assertFalse(os.path.exists(local))
        numbers = [n for n, kind in factory.runs if kind in ("cleanup", "probe")]
        self.assertEqual(len(numbers), len(set(numbers)))

    def test_leftover_folder_that_cannot_be_cleared_stops_before_writing(self):
        factory = FakeFactory(cleanup_failures=99)
        result, events, smb, sleeps = self.run_executor(factory)
        self.assertFalse(result.executed)
        self.assertTrue(result.status.startswith("ERROR: pre-run "))
        self.assertEqual(smb.calls, [])
        self.assertEqual(factory.cleanup_calls, mod.CLEANUP_ATTEMPTS)
        self.assertEqual(sleeps, [mod.CLEANUP_RETRY_DELAY_S] * (mod.CLEANUP_ATTEMPTS - 1))

    def test_post_run_cleanup_is_retried_in_fresh_sessions(self):
        factory = FakeFactory(cleanup_failures=1, fail_from_call=2)
        result, events, _, _ = self.run_executor(factory)
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(events[-5:], ["cleanup", "probe", f"sleep:{mod.CLEANUP_RETRY_DELAY_S}",
                                       "cleanup", "probe"])
        numbers = [n for n, kind in factory.runs if kind in ("cleanup", "probe")]
        self.assertEqual(len(numbers), len(set(numbers)))

    def test_notes_left_behind_fail_the_run_and_name_the_folder(self):
        factory = FakeFactory(cleanup_failures=99, fail_from_call=2)
        result, events, smb, _ = self.run_executor(factory)
        self.assertFalse(result.executed)
        self.assertNotEqual(result.status, "SUCCESS")
        self.assertIn(mod.PARENT, result.status)
        self.assertIn(f"after {mod.CLEANUP_ATTEMPTS} attempts", result.status)
        self.assertEqual(len(smb.calls), 1)

    def test_residue_seen_by_the_probe_fails_the_run(self):
        factory = FakeFactory(residual=True)
        result, _, smb, _ = self.run_executor(factory)
        self.assertFalse(result.executed)
        self.assertIn("residual state", result.status)
        self.assertEqual(smb.calls, [])

    def test_fewer_notes_than_the_rule_needs_is_an_error_and_still_cleans(self):
        factory = FakeFactory(landed=2)
        result, events, _, _ = self.run_executor(factory)
        self.assertFalse(result.executed)
        self.assertIn(f"2 of {mod.NOTE_RUNS}", result.status)
        self.assertEqual(events[-2:], ["cleanup", "probe"])

    def test_smb_failure_still_cleans(self):
        factory = FakeFactory()
        smb = SmbRecorder([], rc=1, out="NT_STATUS_ACCESS_DENIED making remote directory")
        result, events, _, _ = self.run_executor(factory, smb=smb)
        self.assertFalse(result.executed)
        self.assertTrue(result.status.startswith("SMB_ERROR: "))
        self.assertEqual(events, ["cleanup", "probe", "smbclient", "cleanup", "probe"])

    def test_smbclient_timeout_still_cleans_and_removes_the_local_note(self):
        import subprocess
        factory = FakeFactory()
        smb = SmbRecorder([], raises=subprocess.TimeoutExpired("smbclient", 30))
        result, events, _, _ = self.run_executor(factory, smb=smb)
        self.assertFalse(result.executed)
        self.assertIn("TimeoutExpired", result.status)
        self.assertEqual(events[-2:], ["cleanup", "probe"])
        local = re.search(r"put (\S+) ", smb.calls[0][0]).group(1)
        self.assertFalse(os.path.exists(local))

    def test_refuses_without_winrm_before_writing(self):
        smb = SmbRecorder([])
        with mock.patch.object(mod, "smb_client_from", smb):
            result = mod.smb_ransom_note(USECASE, Ctx(cfg={}), token=TOKEN,
                                         sleep_fn=lambda _s: None)
        self.assertFalse(result.executed)
        self.assertEqual(smb.calls, [])


if __name__ == "__main__":
    unittest.main()
