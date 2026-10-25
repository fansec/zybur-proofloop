"""Slice 8 acceptance: the CLI enforces the safety classes, and a run verifies unless told not to.

Green since slice 8 (2026-10-24); it was pending_test_cli_safety.py. The external review of the
public export (2026-10-24) found that --all and --id execute supervised use-cases unattended
(select() filters by id, technique, tactic, tag or all, never by safety) and that a --id run
without --verify writes a null verdict (do_verify fell back to args.all).

Spec under test (docs/superpowers/plans/2026-10-24-harness-public-release-review-fixes-plan.md):
  run.gate_selection(selected, args) -> (allowed, refusals)
    refusals are names-only lines, one per class, in this exact wording:
      "run: N supervised use-case(s) need --allow-supervised: id ..."
      "run: N never use-case(s) refused: id ..."
      "run: N use-case(s) reach the internet and need --allow-internet: id ..."
    `never` is refused whatever the flags. The gate runs before --dry-run prints and before
    the dedup pool is built; a non-empty refusal list exits 2 after printing every line to stderr.
  run.verify_default(args) -> bool: True unless --no-verify; --verify stays an explicit True.
"""
import argparse
import pathlib
import unittest

import run as runmod


def uc(uid, safety="safe", **kw):
    d = {"id": uid, "title": uid, "safety": safety, "executor": "winrm_command",
         "params": {"command": "whoami"}, "rules": ["r"], "technique": "T1059", "tactic": "execution"}
    d.update(kw)
    return d


def args(**kw):
    ns = argparse.Namespace(id=None, technique=None, tactic=None, tag=None, all=False,
                            allow_supervised=False, allow_internet=False, verify=None, dry_run=False)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


USECASES = [uc("t/safe"), uc("t/sup", safety="supervised"), uc("t/never", safety="never"),
            uc("t/net", network="internet")]


class CliSafetyGate(unittest.TestCase):
    def test_the_flags_are_declared(self):
        ns = runmod._build_parser().parse_args(["--all", "--allow-supervised", "--allow-internet"])
        self.assertTrue(ns.allow_supervised)
        self.assertTrue(ns.allow_internet)

    def test_all_without_flags_runs_only_safe_lab_use_cases(self):
        a = args(all=True)
        allowed, refusals = runmod.gate_selection(runmod.select(USECASES, a), a)
        self.assertEqual([u["id"] for u in allowed], ["t/safe"])
        self.assertEqual(sorted(refusals), sorted([
            "run: 1 supervised use-case(s) need --allow-supervised: t/sup",
            "run: 1 never use-case(s) refused: t/never",
            "run: 1 use-case(s) reach the internet and need --allow-internet: t/net",
        ]))

    def test_allow_flags_admit_their_class_and_never_stays_refused(self):
        a = args(all=True, allow_supervised=True, allow_internet=True)
        allowed, refusals = runmod.gate_selection(runmod.select(USECASES, a), a)
        self.assertEqual([u["id"] for u in allowed], ["t/safe", "t/sup", "t/net"])
        self.assertEqual(refusals, ["run: 1 never use-case(s) refused: t/never"])

    def test_an_explicit_id_is_gated_the_same_way(self):
        a = args(id=["t/sup"])
        allowed, refusals = runmod.gate_selection(runmod.select(USECASES, a), a)
        self.assertEqual(allowed, [])
        self.assertEqual(refusals, ["run: 1 supervised use-case(s) need --allow-supervised: t/sup"])

    def test_refusal_lines_carry_ids_only(self):
        a = args(id=["t/sup", "t/never"])
        _, refusals = runmod.gate_selection(runmod.select(USECASES, a), a)
        for line in refusals:
            self.assertNotIn("whoami", line)
            self.assertNotIn("winrm", line)

    def test_the_gate_sits_before_dry_run_and_the_dedup_pool(self):
        src = pathlib.Path(runmod.__file__).read_text()
        self.assertLess(src.index("gate_selection("), src.index("WOULD RUN"),
                        "--dry-run must show what the gate would allow, not what was asked")
        self.assertLess(src.index("gate_selection("), src.index("DedupAllocator(cfg"),
                        "a refused selection must not build the pool or power anything on")


class VerifyDefault(unittest.TestCase):
    def test_a_run_verifies_unless_told_not_to(self):
        self.assertTrue(runmod.verify_default(args(id=["t/safe"])))
        self.assertTrue(runmod.verify_default(args(all=True)))
        self.assertTrue(runmod.verify_default(args(id=["t/safe"], verify=True)))
        self.assertFalse(runmod.verify_default(args(id=["t/safe"], verify=False)))


if __name__ == "__main__":
    unittest.main()
