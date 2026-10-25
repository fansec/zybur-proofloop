# rules/engine/pending_test_lab_config.py
# Slice 1 of docs/superpowers/plans/2026-10-22-nightly-harness-public-release-plan.md:
# the engine carries no lab constant and names what is missing, never a value.
# RED by design until the slice lands; rename to test_lab_config.py when green.
import importlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))

# Every non-test, non-fixture engine source file. Executors included: rare_smb.py and
# dedup.py carry lab literals on 2026-10-22.
def engine_sources():
    out = []
    for root, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in ("fixtures", "__pycache__", "state")]
        for f in files:
            if f.endswith(".py") and not f.startswith("test_") and not f.startswith("pending_test_"):
                out.append(os.path.join(root, f))
    return out

LAB_LITERALS = (r"192\.168\.", r"zybur\.lab", r"DEFAULT_ES_URL", r"elastic\.cloud")

def scrubbed_env(tmp):
    """An environment with no lab value in it and every file the engine may read pointed at an empty place."""
    env = {k: v for k, v in os.environ.items()
           if not re.match(r"^(CALDERA_|WIN_|DC_|ATTACKER_|ES_|ELASTIC_|PROXMOX_|DEDUP_|LAB_HOSTS|SIEM)", k)}
    empty = os.path.join(tmp, "empty.env")
    open(empty, "w").close()
    env["ZYBUR_CREDS_FILE"] = empty            # new in slice 1: overrides validation/.creds
    env["ZYBUR_ENV_ROOT"] = tmp                # no .env.shared / .env.internal here
    env["LAB_HOSTS_FILE"] = os.path.join(tmp, "lab-hosts.json")  # new in slice 1
    with open(env["LAB_HOSTS_FILE"], "w") as f:
        f.write('{"hosts":[{"name":"ws","role":"workstation","ip":"10.0.0.2","aliases":[]},'
                '{"name":"dc","role":"domain_controller","ip":"10.0.0.3","aliases":[]}]}')
    return env


class TestNoLabLiterals(unittest.TestCase):
    def test_engine_sources_carry_no_lab_literal(self):
        hits = []
        for p in engine_sources():
            with open(p, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    for pat in LAB_LITERALS:
                        if re.search(pat, line):
                            hits.append(f"{os.path.relpath(p, HERE)}:{n} {pat}")
        self.assertEqual(hits, [], "lab literals left in the engine:\n" + "\n".join(hits))


class TestConfigNamesMissingKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = scrubbed_env(self.tmp)

    def test_load_config_has_no_lab_defaults(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            import config
            importlib.reload(config)
            cfg = config.load_config()
        for key in ("server", "attacker_ip", "dc_fqdn", "dc_domain"):
            self.assertIsNone(cfg.get(key), f"{key} still has a default")
        # The registry file is honoured, so the public user points at their own.
        self.assertEqual(cfg.get("win_host"), "10.0.0.2")
        self.assertEqual(cfg.get("dc_host"), "10.0.0.3")

    def test_every_executor_has_a_lab_key_entry(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            import config
            importlib.reload(config)
            import executors.plugins  # noqa: F401
            import executors.registry as reg
        missing = sorted(reg.executor_names() - set(config.LAB_KEYS_BY_EXECUTOR))
        self.assertEqual(missing, [], "executors without a LAB_KEYS_BY_EXECUTOR entry")

    def test_missing_lab_config_names_only(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            import config
            importlib.reload(config)
            cfg = config.load_config()
            names = config.missing_lab_config(cfg, ["caldera_command", "winrm_command"])
        self.assertEqual(names, sorted(set(names)))
        self.assertIn("CALDERA_SERVER", names)
        self.assertIn("CALDERA_API_KEY", names)
        self.assertIn("WIN_PASS", names)
        self.assertNotIn("WIN_HOST", names, "the registry supplied WIN_HOST")
        for n in names:
            self.assertRegex(n, r"^[A-Z_]+$", "a name, never a value")

    def test_es_credentials_have_no_default_url(self):
        with mock.patch.dict(os.environ, self.env, clear=True):
            import run
            importlib.reload(run)
            es_url, api_key = run._es_credentials()
        self.assertIsNone(es_url)
        self.assertIsNone(api_key)


class TestPreflightCommand(unittest.TestCase):
    def test_preflight_lists_names_and_exits_1(self):
        tmp = tempfile.mkdtemp()
        env = scrubbed_env(tmp)
        p = subprocess.run([sys.executable, os.path.join(HERE, "run.py"), "--preflight",
                            "--executors", "winrm_command,caldera_command"],
                           env=env, capture_output=True, text=True, cwd=HERE)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertRegex(p.stdout, r"^preflight: missing ([A-Z_]+ ?)+$", p.stdout)
        self.assertIn("ES_URL", p.stdout)
        self.assertIn("CALDERA_API_KEY", p.stdout)
        self.assertNotIn("=", p.stdout, "a preflight prints names, never values")

    def test_preflight_ok_when_every_name_is_set(self):
        tmp = tempfile.mkdtemp()
        env = scrubbed_env(tmp)
        env.update({"ES_URL": "https://es.example.invalid", "ES_API_KEY": "x",
                    "WIN_USER": "u", "WIN_PASS": "p"})
        p = subprocess.run([sys.executable, os.path.join(HERE, "run.py"), "--preflight",
                            "--executors", "winrm_command"],
                           env=env, capture_output=True, text=True, cwd=HERE)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(p.stdout.strip(), "preflight ok")


class TestRequirementsFile(unittest.TestCase):
    IMPORT_TO_DIST = {"yaml": "PyYAML", "impacket": "impacket", "pypsrp": "pypsrp"}

    def test_requirements_lists_every_third_party_import_with_a_pin(self):
        path = os.path.join(HERE, "requirements.txt")
        self.assertTrue(os.path.exists(path), "rules/engine/requirements.txt is missing")
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        dists = {}
        for l in lines:
            m = re.match(r"^([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*)$", l)
            self.assertIsNotNone(m, f"unpinned requirement: {l}")
            dists[m.group(1).lower()] = m.group(2)
        imports = set()
        for p in engine_sources():
            with open(p, encoding="utf-8") as f:
                for line in f:
                    m = re.match(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
                    if m and m.group(1) in self.IMPORT_TO_DIST:
                        imports.add(self.IMPORT_TO_DIST[m.group(1)].lower())
        self.assertEqual(sorted(imports - set(dists)), [], "third-party imports not in requirements.txt")


if __name__ == "__main__":
    unittest.main()
