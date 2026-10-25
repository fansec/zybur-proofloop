# rules/engine/test_run_select.py
import os
import pathlib
import tempfile
import unittest
from unittest import mock
from run import select

UCS = [
    {"id": "credential-access/lsass", "technique": "T1003.001", "tactic": "credential-access", "tags": ["cred"]},
    {"id": "impact/shadow", "technique": "T1490", "additional_techniques": ["T1486"], "tactic": "impact", "tags": ["ransomware-pre"]},
]

class Args:
    id = technique = tactic = tag = None
    all = False

class TestSelect(unittest.TestCase):
    def test_by_technique(self):
        a = Args(); a.technique = "T1490"
        self.assertEqual([u["id"] for u in select(UCS, a)], ["impact/shadow"])
    def test_by_additional_technique(self):
        a = Args(); a.technique = "T1486"
        self.assertEqual([u["id"] for u in select(UCS, a)], ["impact/shadow"])
    def test_by_tactic(self):
        a = Args(); a.tactic = "credential-access"
        self.assertEqual([u["id"] for u in select(UCS, a)], ["credential-access/lsass"])
    def test_by_id(self):
        a = Args(); a.id = "impact/shadow"
        self.assertEqual(len(select(UCS, a)), 1)
    def test_repeated_ids_keep_the_requested_order(self):
        a = Args(); a.id = ["impact/shadow", "credential-access/lsass"]
        self.assertEqual([u["id"] for u in select(UCS, a)],
                         ["impact/shadow", "credential-access/lsass"])
    def test_parser_accumulates_repeated_ids(self):
        from run import _build_parser
        a = _build_parser().parse_args([
            "--id", "credential-access/lsass", "--id", "impact/shadow"])
        self.assertEqual(a.id, ["credential-access/lsass", "impact/shadow"])
    def test_all(self):
        a = Args(); a.all = True
        self.assertEqual(len(select(UCS, a)), 2)


class TestElasticCredentials(unittest.TestCase):
    def test_explicit_api_key_overrides_shared_validation_key(self):
        import run as runmod
        with mock.patch.dict("os.environ", {"ES_API_KEY": "operator-key"}, clear=False), \
                mock.patch.object(runmod, "_read_shared_any",
                                  side_effect=lambda key: "shared-key" if key == "ELASTIC_VALIDATION_API_KEY" else None):
            self.assertEqual(runmod._es_credentials()[1], "operator-key")

    def test_deployed_release_reads_shared_key_from_absolute_env_root(self):
        import run as runmod
        with tempfile.TemporaryDirectory() as root:
            pathlib.Path(root, ".env.shared").write_text(
                "ELASTIC_VALIDATION_API_KEY=env-root-fixture\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"ZYBUR_ENV_ROOT": root}, clear=False):
                self.assertEqual(runmod._shared_env_paths()[0],
                                 os.path.join(root, ".env.shared"))
                self.assertEqual(runmod._read_shared_any("ELASTIC_VALIDATION_API_KEY"),
                                 "env-root-fixture")

    def test_relative_env_root_cannot_redirect_shared_key_lookup(self):
        import run as runmod
        with mock.patch.dict(os.environ, {"ZYBUR_ENV_ROOT": "relative/repo"}, clear=False):
            self.assertNotIn(os.path.join("relative/repo", ".env.shared"),
                             runmod._shared_env_paths())


class TestEnsureAgentFlag(unittest.TestCase):
    """--ensure-agent detonates nothing, so it must be reachable without a
    use-case selection and must never fall through to the detonation branch.

    It exists because validation's PREPARE gate MEASURES sandcat_beacon and never
    deploys, while the only redeploy path (CalderaClient.ensure_agent) is called
    from run_ability - behind the very gate a dead beacon closes. Teardown powers
    the lab off nightly, so the agent dies with it and the gate could never come
    good on its own.
    """

    def test_the_flag_is_declared(self):
        import run as runmod
        ap = runmod.build_parser() if hasattr(runmod, "build_parser") else None
        src = pathlib.Path(runmod.__file__).read_text()
        self.assertIn('"--ensure-agent"', src)

    def test_it_runs_before_the_selection_guard(self):
        # If it sat after "no use-cases selected" it would exit 2 on a bare call,
        # which is the whole point of putting it early.
        src = pathlib.Path(__import__("run").__file__).read_text()
        i_ensure = src.index("if args.ensure_agent:")
        i_guard = src.index("no use-cases selected")
        self.assertLess(i_ensure, i_guard,
                        "--ensure-agent must not require a use-case selection")

    def test_it_runs_before_the_dedup_pool_and_detonation(self):
        src = pathlib.Path(__import__("run").__file__).read_text()
        self.assertLess(src.index("if args.ensure_agent:"), src.index("DedupAllocator(cfg"),
                        "--ensure-agent must not build the dedup pool or detonate")


if __name__ == "__main__":
    unittest.main()
