# rules/engine/test_reconcile.py
import inspect
import pathlib
import re
import unittest

import testenv

from cmdline import CMD_EXE_LIMIT, MAX_RUN_PS_CMDLINE, run_ps_cmdline_len
from reconcile import (MANIFEST, PROBE_MARKER, build_probe_ps, build_reset_ps,
                       item_id, manifest_chunks, reconcile)


class R:
    def __init__(self, out=b"", code=0, err=b""):
        self.std_out = out
        self.status_code = code
        self.std_err = err


def probe_out(deviations):
    """What a probe that ran to its end prints: the deviations, then the marker."""
    return "\n".join(sorted(deviations) + [PROBE_MARKER]).encode()


class FakeSession:
    """A lab box with a set of deviations that the reset may or may not clear."""

    def __init__(self, dirty=(), unfixable=(), probe_raises=False, reset_raises=False):
        self.dirty = set(dirty)
        self.unfixable = set(unfixable)
        self.probe_raises = probe_raises
        self.reset_raises = reset_raises
        self.ps = []
        self.cmd = []

    def run_ps(self, c):
        self.ps.append(c)
        if PROBE_MARKER in c:
            if self.probe_raises:
                raise RuntimeError("WinRM connection refused")
            return R(out=probe_out(self.dirty))
        # the reset: clears everything except what is declared unfixable
        if self.reset_raises:
            raise RuntimeError("PowerShell exited 1")
        self.dirty &= self.unfixable
        return R(out=b"ok")

    def run_cmd(self, shell, args):
        self.cmd.append((shell, args))
        return R(out=b"ok")


ALL_IDS = [item_id(k, t) for k, t, _ in MANIFEST]


class TestGeneration(unittest.TestCase):
    """The superseded design hand-wrote 3 checks for 19 items, so residual==[] was
    reported over a dirty lab. Coverage is now structural: one check per entry."""

    def test_the_probe_checks_every_manifest_item(self):
        ps = build_probe_ps()
        for ident in ALL_IDS:
            self.assertIn(ident, ps, f"{ident} has no probe check")

    def test_the_reset_acts_on_every_manifest_item(self):
        ps = build_reset_ps()
        for kind, target, _ in MANIFEST:
            needle = target[0] if kind in ("regvalue", "regmember") else str(target)
            self.assertIn(needle.replace("'", "''"), ps, f"{kind}:{target} has no reset action")

    def test_probe_and_reset_cover_the_same_number_of_items(self):
        # The exact failure mode being guarded: a manifest that grew while one of
        # the two generators did not.
        self.assertEqual(len(ALL_IDS), len(MANIFEST))
        checks = build_probe_ps().count("if ")
        self.assertEqual(checks, len(MANIFEST),
                         "the probe must have exactly one check per manifest entry")

    def test_an_unknown_kind_is_refused_rather_than_silently_skipped(self):
        bad = [("nonsense", "x", "absent")]
        with self.assertRaises(ValueError):
            build_probe_ps(bad)
        with self.assertRaises(ValueError):
            build_reset_ps(bad)

    def test_a_wildcard_target_is_carried_as_fileglob_not_file(self):
        # -LiteralPath does not expand a wildcard: a `*` under the "file" kind
        # looks for a file literally named with an asterisk, so the probe reports
        # clean forever. That is a vacuous check dressed as coverage, and it is
        # the one way the corpus guard below could be satisfied by nothing.
        wild = [t for k, t, _ in MANIFEST if k == "file" and ("*" in t or "?" in t)]
        self.assertEqual(wild, [], "a wildcard path must use the fileglob kind")

    def test_a_fileglob_probes_with_Path_so_the_wildcard_actually_expands(self):
        ps = build_probe_ps([("fileglob", r"C:\T\a_*.txt", "absent")])
        self.assertIn("-Path", ps)
        self.assertNotIn("-LiteralPath", ps)

    def test_an_environment_variable_in_a_path_is_expanded_ON_THE_BOX(self):
        # PowerShell does not expand inside single quotes, so a bare '%TEMP%\x'
        # would be probed as a literal name and never found.
        for ps in (build_probe_ps([("file", r"%TEMP%\x.exe", "absent")]),
                   build_reset_ps([("file", r"%TEMP%\x.exe", "absent")])):
            self.assertIn("ExpandEnvironmentVariables", ps)

    def test_a_regmember_probe_asks_about_the_MEMBER_not_the_value(self):
        # Security Packages must keep existing - lsass reads it to decide which
        # providers to load - so the deviation is one entry of the list. A probe
        # that asked whether the VALUE existed would be red on a healthy box, and
        # a reset that deleted it would stop the box authenticating anyone.
        item = ("regmember", (r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
                              "Security Packages", "custom_ssp_test"), "absent")
        probe, reset = build_probe_ps([item]), build_reset_ps([item])
        self.assertIn("-contains 'custom_ssp_test'", probe)
        self.assertIn("-contains 'custom_ssp_test'", reset)
        self.assertNotIn("Remove-ItemProperty", reset)
        self.assertIn("MultiString", reset)

    def test_a_regkey_is_probed_as_a_key_and_reset_by_deleting_it(self):
        item = ("regkey", r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox", "absent")
        self.assertIn("Test-Path", build_probe_ps([item]))
        self.assertIn("Remove-Item -LiteralPath", build_reset_ps([item]))

    def test_a_set_expectation_treats_a_MISSING_value_as_a_deviation(self):
        # "the key is gone" and "the key is at its safe default" are different
        # states, and only one of them is the baseline.
        ps = build_probe_ps([("regvalue", (r"HKLM:\X", "Y"), "set:1")])
        self.assertIn("-ne 1", ps)


class TestScriptLength(unittest.TestCase):
    """Every script reaches Windows as ONE cmd.exe command string (pywinrm run_ps is
    `powershell -encodedcommand <base64 UTF-16LE>`, and WinRS runs it under
    `cmd.exe /C`), and cmd.exe refuses one over 8,191 characters without a sound.
    The chunks were budgeted at 24,000 from 2026-09-11 (read as CreateProcess's
    32,767), and on 2026-10-14 neither probe chunk had started PowerShell on the
    box, so every nightly reconcile since had been reading empty stdout as clean."""

    def test_every_real_chunk_fits_the_command_string_cmd_exe_will_run(self):
        for chunk in manifest_chunks(MANIFEST):
            for ps in (build_probe_ps(chunk), build_reset_ps(chunk)):
                self.assertLessEqual(run_ps_cmdline_len(ps), MAX_RUN_PS_CMDLINE)
                self.assertLess(run_ps_cmdline_len(ps), CMD_EXE_LIMIT)

    def test_the_default_budget_is_the_shared_cmd_exe_one(self):
        # The 24,000 of 2026-09-11 was a number of this file's own. One place for
        # it (cmdline.py), so reconcile, the executors and lint cannot disagree.
        default = inspect.signature(manifest_chunks).parameters["budget"].default
        self.assertEqual(default, MAX_RUN_PS_CMDLINE)
        self.assertLess(MAX_RUN_PS_CMDLINE, CMD_EXE_LIMIT)

    def test_the_2026_10_14_chunking_would_be_refused_now(self):
        # The regression itself: the old budget packed probes cmd.exe never ran.
        old = manifest_chunks(MANIFEST, budget=24_000)
        self.assertTrue(any(run_ps_cmdline_len(build_probe_ps(c)) > CMD_EXE_LIMIT for c in old))
        self.assertGreater(len(manifest_chunks(MANIFEST)), len(old))

    def test_the_chunks_are_the_manifest_in_order_nothing_dropped_or_doubled(self):
        flat = [e for chunk in manifest_chunks(MANIFEST) for e in chunk]
        self.assertEqual(flat, list(MANIFEST))

    def test_a_manifest_many_times_larger_still_fits(self):
        big = [("file", rf"C:\Windows\Temp\zyb_growth_test_{i:04d}.bin", "absent")
               for i in range(600)]
        chunks = manifest_chunks(big)
        self.assertGreater(len(chunks), 1)
        self.assertEqual([e for c in chunks for e in c], big)
        for chunk in chunks:
            self.assertLessEqual(run_ps_cmdline_len(build_probe_ps(chunk)), MAX_RUN_PS_CMDLINE)
            self.assertLessEqual(run_ps_cmdline_len(build_reset_ps(chunk)), MAX_RUN_PS_CMDLINE)

    def test_an_entry_too_long_to_fit_alone_is_refused_not_dropped(self):
        huge = [("file", "C:\\" + "x" * 20_000, "absent")]
        with self.assertRaises(ValueError):
            manifest_chunks(huge)

    def test_the_encoded_length_is_what_pywinrm_actually_sends(self):
        from base64 import b64encode
        ps = build_probe_ps(MANIFEST[:3])
        sent = "powershell -encodedcommand " + b64encode(ps.encode("utf_16_le")).decode("ascii")
        self.assertEqual(run_ps_cmdline_len(ps), len(sent))

    def test_an_item_in_the_LAST_chunk_is_still_seen_by_the_probe(self):
        class ChunkAwareSession(FakeSession):
            # Answers only for items whose check is IN the script it was sent, the
            # way the box does. The base fake answers everything on every call and
            # would pass even if a chunk were never sent.
            def run_ps(self, c):
                self.ps.append(c)
                if PROBE_MARKER in c:
                    return R(out=probe_out(i for i in self.dirty if f"'{i}'" in c))
                self.dirty = {i for i in self.dirty if f"'{i}'" not in c} | (self.dirty & self.unfixable)
                return R(out=b"ok")

        chunks = manifest_chunks(MANIFEST)
        self.assertGreater(len(chunks), 1, "the real manifest no longer needs chunking; revisit this test")
        last_kind, last_target, _ = chunks[-1][-1]
        last_id = item_id(last_kind, last_target)
        s = ChunkAwareSession(dirty={last_id}, unfixable={last_id})
        out = reconcile(s)
        self.assertEqual(out["residual"], [last_id])


class TestReconcile(unittest.TestCase):
    def test_a_dirty_box_is_cleaned_and_reports_what_changed(self):
        s = FakeSession(dirty={ALL_IDS[0], "task:P2TestTask"})
        out = reconcile(s)
        self.assertEqual(out["residual"], [])
        self.assertIn(ALL_IDS[0], out["reset"] + out["removed"])
        self.assertIn("task:P2TestTask", out["removed"])
        self.assertEqual(out["checked"], len(MANIFEST))

    def test_an_ALREADY_CLEAN_box_is_not_reset_at_all(self):
        s = FakeSession(dirty=set())
        out = reconcile(s)
        self.assertEqual(out["residual"], [])
        self.assertEqual(out["reset"], [])
        self.assertEqual(out["removed"], [])
        # two probe PASSES, no reset: nothing to fix means nothing to touch. A pass
        # is one run_ps per chunk since 2026-09-11, see TestScriptLength.
        self.assertEqual(sum(1 for c in s.ps if PROBE_MARKER in c),
                         2 * len(manifest_chunks(MANIFEST)))
        self.assertEqual(sum(1 for c in s.ps if PROBE_MARKER not in c), 0)

    def test_what_the_reset_CANNOT_fix_is_reported_as_residual(self):
        stubborn = "regvalue:HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"
        s = FakeSession(dirty={stubborn, "task:P2TestTask"}, unfixable={stubborn})
        out = reconcile(s)
        self.assertEqual(out["residual"], [stubborn])
        self.assertEqual(out["removed"], ["task:P2TestTask"])
        self.assertNotIn(stubborn, out["reset"] + out["removed"],
                         "a repair that did not happen must never be claimed")

    def test_reset_and_removed_can_only_name_items_the_probe_saw_change(self):
        s = FakeSession(dirty={"task:P2TestTask"})
        out = reconcile(s)
        for ident in out["reset"] + out["removed"]:
            self.assertEqual(ident, "task:P2TestTask")

    def test_an_unreadable_box_is_residual_NOT_clean(self):
        # The fabricated zero this subsystem exists to remove.
        out = reconcile(FakeSession(probe_raises=True))
        self.assertEqual(len(out["residual"]), 1)
        self.assertIn("probe_failed", out["residual"][0])
        self.assertEqual(out["reset"], [])
        self.assertEqual(out["removed"], [])

    def test_a_failed_reset_still_reports_honestly_from_the_second_probe(self):
        s = FakeSession(dirty={"task:P2TestTask"}, reset_raises=True)
        out = reconcile(s)
        self.assertEqual(out["residual"], ["task:P2TestTask"])
        self.assertTrue(any("reset_failed" in a for a in out["attempted"]))

    def test_firewall_and_dedup_are_ATTEMPTED_never_claimed_as_verified(self):
        class Dedup:
            def __init__(self): self.called = False
            def cleanup(self): self.called = True

        d = Dedup()
        s = FakeSession(dirty={"task:P2TestTask"})
        out = reconcile(s, dedup=d)
        self.assertTrue(d.called)
        self.assertIn("dedup:netns", out["attempted"])
        self.assertTrue(any(a.startswith("fwrule:") for a in out["attempted"]))
        # There is no probe for these from the Windows host, so they may never
        # appear in the verified halves.
        self.assertNotIn("dedup:netns", out["reset"] + out["removed"])

    def test_the_firewall_names_come_from_the_one_table_that_defines_them(self):
        from firewall import FIREWALL_RULES
        expected = {rn for rules in FIREWALL_RULES.values() for rn, _, _ in rules}
        out = reconcile(FakeSession(), dedup=None)
        swept = {a.split(":", 1)[1] for a in out["attempted"] if a.startswith("fwrule:")}
        self.assertEqual(swept, expected)


class ScriptedSession(FakeSession):
    """A box whose probe answer is chosen per call: answer(n, script) -> R, where n
    counts probe calls from 1 across both passes. Reset calls clear the dirt."""

    def __init__(self, answer, dirty=()):
        super().__init__(dirty=dirty)
        self.answer = answer
        self.probes = 0

    def run_ps(self, c):
        if PROBE_MARKER not in c:
            return super().run_ps(c)
        self.ps.append(c)
        self.probes += 1
        return self.answer(self.probes, c, self)


class TestProbeProvesItRan(unittest.TestCase):
    """Measured live 2026-10-14: cmd.exe refused both probe chunks, PowerShell never
    started, run_ps returned empty stdout and no error, and _probe read that as a
    clean lab. The marker is the proof the probe ran; its absence is not silence."""

    def _ok(self, n, c, s):
        return R(out=probe_out(i for i in s.dirty if f"'{i}'" in c))

    def assertProbeFailed(self, out):
        self.assertEqual(len(out["residual"]), 1, out["residual"])
        self.assertTrue(out["residual"][0].startswith("probe_failed: "), out["residual"])
        self.assertEqual(out["reset"], [])
        self.assertEqual(out["removed"], [])

    def test_empty_stdout_is_a_probe_failure_never_a_clean_lab(self):
        # Exactly the 2026-10-14 shape: the call returns, nothing was printed.
        s = ScriptedSession(lambda n, c, s: R(out=b"", code=0))
        out = reconcile(s)
        self.assertProbeFailed(out)
        self.assertIn(PROBE_MARKER, out["residual"][0])
        self.assertEqual(s.probes, 1, "the first unproven chunk ends the read")

    def test_the_marker_and_no_deviations_is_a_clean_lab(self):
        out = reconcile(ScriptedSession(self._ok))
        self.assertEqual(out["residual"], [])

    def test_one_markerless_chunk_among_good_ones_fails_the_probe(self):
        chunks = manifest_chunks(MANIFEST)
        self.assertGreater(len(chunks), 2, "the real manifest no longer needs 3 chunks; revisit this test")

        def answer(n, c, s):
            return R(out=b"") if n == 2 else self._ok(n, c, s)

        self.assertProbeFailed(reconcile(ScriptedSession(answer)))

    def test_a_markerless_chunk_in_the_SECOND_pass_still_fails(self):
        # The first pass saw dirt and the reset ran; a second pass that did not
        # run must not be read as "the reset fixed everything".
        n_chunks = len(manifest_chunks(MANIFEST))
        dirty = {"task:P2TestTask"}

        def answer(n, c, s):
            return R(out=b"") if n == 2 * n_chunks else self._ok(n, c, s)

        out = reconcile(ScriptedSession(answer, dirty=dirty))
        self.assertEqual(len(out["residual"]), 1)
        self.assertTrue(out["residual"][0].startswith("probe_failed: "))

    def test_deviations_without_the_marker_mean_the_probe_did_not_finish(self):
        # The marker is the LAST statement, so lines without it are a probe that
        # stopped part way: the checks after the stop were never asked.
        s = ScriptedSession(lambda n, c, s: R(out=b"task:P2TestTask\n"), dirty={"task:P2TestTask"})
        self.assertProbeFailed(reconcile(s))

    def test_a_nonzero_exit_status_fails_even_with_the_marker(self):
        s = ScriptedSession(lambda n, c, s: R(out=probe_out([]), code=1))
        out = reconcile(s)
        self.assertProbeFailed(out)
        self.assertIn("exit status 1", out["residual"][0])

    def test_the_refusal_cmd_exe_prints_reaches_the_residual(self):
        # What the box says when it refuses, so the night's record names the cause.
        s = ScriptedSession(lambda n, c, s: R(out=b"", code=1,
                                              err=b"The command line is too long.\r\n"))
        out = reconcile(s)
        self.assertProbeFailed(out)
        self.assertIn("The command line is too long.", out["residual"][0])

    def test_the_marker_is_the_last_statement_of_every_chunk_and_appears_once(self):
        for chunk in manifest_chunks(MANIFEST):
            ps = build_probe_ps(chunk)
            self.assertTrue(ps.endswith(f"Write-Output '{PROBE_MARKER}'"), ps[-80:])
            self.assertEqual(ps.count(PROBE_MARKER), 1)


class TestManifestCoversCorpus(unittest.TestCase):
    """The manifest fell behind the corpus once already: of the 8 posture values the
    use-case cleanups write, the superseded list carried only 5, and named 3 that
    nothing touches. This is the guard, not a memory."""

    # A Remove-Item target list: one or more quoted or bare paths, ending at the
    # first switch. `Remove-Item\b` does not match Remove-ItemProperty - "m" and
    # "P" are both word characters, so there is no boundary between them - which
    # is what keeps the registry VALUE cleanups out of the file scan.
    _TOKEN = r'"[^"]*"|\'[^\']*\'|[^\s,;]+'
    _REMOVE_ITEM = re.compile(
        r'Remove-Item\b\s*(?:-(?:Literal)?Path\s+)?((?:%s)(?:\s*,\s*(?:%s))*)'
        % (_TOKEN, _TOKEN))

    def _usecases(self):
        # The folder beside this one, not a path from the repository root: the public export
        # (scripts/oss-export.sh) has engine/ and usecases/ side by side and no rules/ above
        # them, and a root-relative path there found nothing, which only the guard below noticed.
        return pathlib.Path(__file__).resolve().parent.parent / "usecases"

    @staticmethod
    def _norm(path):
        """Compare the way Windows does. Paths are case-insensitive, and the corpus
        writes an environment variable as $env:VAR where the manifest writes %VAR%."""
        path = re.sub(r'\$env:([A-Za-z_][A-Za-z0-9_]*)',
                      lambda m: "%" + m.group(1).upper() + "%", path)
        return path.casefold()

    # `-Path X -Name "Y"` where X is a literal or a $variable. The variable form
    # was invisible until 2026-09-10, which is how the SSP `Security Packages`
    # write and the Firefox DNSOverHTTPS write both stayed out of the manifest.
    _REGVALUE = re.compile(r'-Path\s+(?:"([^"]+)"|\$([A-Za-z_][A-Za-z0-9_]*))\s+-Name\s+"([^"]+)"')

    def _corpus_regvalues(self):
        """(path, name) pairs, plus the $variable paths that cannot be resolved.

        A variable is resolved from its assignment IN THE SAME FILE, and only when
        the file assigns it exactly one literal. Anything else is unresolved and
        fails: a scan that quietly drops what it cannot read is the fake safety
        this class exists to remove.
        """
        found, unresolved = set(), set()
        for f in sorted(self._usecases().rglob("*.yaml")):
            text = f.read_text()
            for m in self._REGVALUE.finditer(text):
                path, var, name = m.group(1), m.group(2), m.group(3)
                if var:
                    lits = set(re.findall(r'\$%s\s*=\s*"([^"]+)"' % re.escape(var), text))
                    if len(lits) != 1:
                        unresolved.add(f"{f.name}: -Path ${var} -Name \"{name}\"")
                        continue
                    path = lits.pop()
                found.add((path, name))
        return found, unresolved

    def _corpus_paths(self):
        """Every FILE or DIRECTORY a `cleanup:` line removes, as
        {normalised: "path (use-case)"}, plus the targets the scan cannot resolve.

        Registry KEY deletes come back separately rather than as files: they are
        the `regkey` kind, and test_every_registry_key_a_cleanup_deletes_has_a_
        manifest_entry checks them.
        """
        found, unresolved, regkeys = {}, set(), set()
        for f in sorted(self._usecases().rglob("*.yaml")):
            for line in f.read_text().splitlines():
                if not line.startswith("cleanup:"):
                    continue
                for m in self._REMOVE_ITEM.finditer(line):
                    for tok in re.findall(self._TOKEN, m.group(1)):
                        tok = tok.strip('"\'')
                        if tok.startswith("-"):
                            # A switch where the target should be: the line puts
                            # its switches first (Remove-Item -Force "C:\x"), so
                            # this scan cannot see the path. Loud, not skipped.
                            unresolved.add(f"{f.name}: {tok}")
                            continue
                        if re.match(r"HK[A-Z_]*:", tok, re.I):
                            regkeys.add(tok)              # a key, not a file
                            continue
                        if tok.startswith("$") and not tok.lower().startswith("$env:"):
                            unresolved.add(f"{f.name}: {tok}")
                            continue
                        found.setdefault(self._norm(tok), f"{tok} ({f.name})")
        return found, unresolved, regkeys

    def test_every_registry_value_a_cleanup_writes_has_a_manifest_entry(self):
        # A regmember entry covers its (path, name) with a NARROWER expectation
        # than absent, not a weaker one: it names the member that must go and
        # leaves the rest of a real MultiString value alone.
        known = {t for k, t, _ in MANIFEST if k == "regvalue"}
        known |= {(t[0], t[1]) for k, t, _ in MANIFEST if k == "regmember"}
        found, _ = self._corpus_regvalues()
        missing = sorted(found - known)
        self.assertEqual(missing, [],
                         "a use-case cleanup writes a posture value reconcile does not know, "
                         "so a night could leave it flipped and the gate would still go green")

    def test_a_variable_registry_path_the_scan_cannot_resolve_fails_LOUDLY(self):
        _, unresolved = self._corpus_regvalues()
        self.assertEqual(sorted(unresolved), [],
                         "-Path $x cannot be checked against the manifest unless the file "
                         "assigns $x exactly one literal path")

    def test_every_file_a_cleanup_removes_has_a_manifest_entry(self):
        # The file half, added 2026-09-10. Until then this class matched only
        # `-Path "..." -Name "..."`, so it was structurally blind to file and
        # directory cleanups: 44 of the 53 paths the corpus drops had no probe,
        # and post_reconcile reported 0 without having looked at any of them.
        known = {self._norm(t) for k, t, _ in MANIFEST if k in ("file", "fileglob")}
        found, _, _ = self._corpus_paths()
        missing = sorted(v for k, v in found.items() if k not in known)
        self.assertEqual(missing, [],
                         "a use-case cleanup removes a file reconcile does not know, "
                         "so a night could leave it on the box and the gate would still go green")

    def test_a_cleanup_target_the_scan_cannot_resolve_fails_LOUDLY(self):
        # A path built from a PowerShell variable cannot be checked against the
        # manifest. Skipping it quietly would be the fake safety this class
        # exists to remove, so it fails and a human decides.
        _, unresolved, _ = self._corpus_paths()
        self.assertEqual(sorted(unresolved), [],
                         "make the cleanup target a literal path, or add the manifest "
                         "entry by hand and teach this scan to see it")

    def test_every_registry_key_a_cleanup_deletes_has_a_manifest_entry(self):
        # `Remove-Item -Path "HKLM:\..."` with no -Name deletes a whole key, which
        # the -Name regex above cannot see and the file scan must not treat as a
        # path on disk. Five cleanups do it, including the Firefox DoH policy key.
        known = {t.casefold() for k, t, _ in MANIFEST if k == "regkey"}
        _, _, regkeys = self._corpus_paths()
        missing = sorted(k for k in regkeys if k.casefold() not in known)
        self.assertEqual(missing, [],
                         "a use-case cleanup deletes a registry key reconcile does not know, "
                         "so a night could leave it installed and the gate would still go green")

    @testenv.requires_private_corpus
    def test_the_scan_actually_found_something(self):
        # A guard that silently matches nothing is the same fake safety it guards
        # against.
        regvalues, _ = self._corpus_regvalues()
        self.assertGreaterEqual(len(regvalues), 5)
        found, _, regkeys = self._corpus_paths()
        self.assertGreaterEqual(len(found), 40)
        # 4 since 2026-10-14: the Event Viewer rewrite (name-simulated on DC1) no
        # longer writes the HKCU mscfile hijack, so its cleanup no longer deletes it.
        self.assertGreaterEqual(len(regkeys), 4)


if __name__ == "__main__":
    unittest.main()
