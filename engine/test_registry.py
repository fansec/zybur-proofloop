# rules/engine/test_registry.py
import unittest
import executors.registry as reg

class TestRegistry(unittest.TestCase):
    def test_register_and_get(self):
        @reg.register("dummy_exec")
        def h(usecase, ctx): return "ran"
        self.assertIs(reg.get("dummy_exec"), h)
        self.assertIn("dummy_exec", reg.executor_names())
    def test_get_unknown_raises_named(self):
        with self.assertRaises(KeyError) as cm:
            reg.get("nope")
        self.assertIn("nope", str(cm.exception))

if __name__ == "__main__":
    unittest.main()
