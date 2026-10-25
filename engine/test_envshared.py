# rules/engine/test_envshared.py
import os, unittest
from envshared import read_shared_env, require_shared_env

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "env.shared.sample")

class TestEnvShared(unittest.TestCase):
    def test_reads_present_key(self):
        self.assertEqual(read_shared_env("ELASTIC_LEGACY_API_KEY", FIX), "abc123==")
    def test_ignores_comments_and_blank(self):
        self.assertIsNone(read_shared_env("NOT_THERE", FIX))
    def test_strips_optional_quotes_and_export(self):
        self.assertEqual(read_shared_env("QUOTED", FIX), "with spaces")
    def test_missing_file_returns_none(self):
        self.assertIsNone(read_shared_env("ANY", "/no/such/file"))
    def test_require_raises_when_absent(self):
        with self.assertRaises(KeyError):
            require_shared_env("NOT_THERE", FIX)

    # 2026-10-16: Zybur's own keys moved to .env.internal beside the shared file.
    def test_falls_back_to_the_internal_file_beside_the_shared_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            shared = os.path.join(d, ".env.shared")
            with open(shared, "w") as f:
                f.write("BOTH=from-shared\nONLY_SHARED=s\n")
            with open(os.path.join(d, ".env.internal"), "w") as f:
                f.write("BOTH=from-internal\nELASTIC_VALIDATION_API_KEY=fake-internal\n")
            self.assertEqual(read_shared_env("ELASTIC_VALIDATION_API_KEY", shared), "fake-internal")
            self.assertEqual(read_shared_env("BOTH", shared), "from-shared")
            self.assertEqual(read_shared_env("ONLY_SHARED", shared), "s")
            self.assertIsNone(read_shared_env("NOWHERE", shared))
            # The shared file itself may be absent (a tree that holds only the internal file).
            os.remove(shared)
            self.assertEqual(read_shared_env("ELASTIC_VALIDATION_API_KEY", shared), "fake-internal")

    # The default used to be the FILESYSTEM root, so a bare call read nothing and
    # every caller had to know the path. It resolves to the repo root now.
    def test_default_path_is_the_repo_root(self):
        from envshared import DEFAULT_PATH
        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
            os.path.join(os.path.dirname(__file__), "envshared.py")))))
        self.assertEqual(os.path.dirname(DEFAULT_PATH), repo)
        self.assertTrue(os.path.isabs(DEFAULT_PATH))
        # And a bare call finds the real file on a checkout that has one.
        if os.path.exists(DEFAULT_PATH):
            self.assertIsNone(read_shared_env("A_KEY_THAT_IS_NOT_THERE"))

if __name__ == "__main__":
    unittest.main()
