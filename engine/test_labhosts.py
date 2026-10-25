import json, os, tempfile, unittest

import labhosts
import testenv


def _write(tmp, doc):
    p = os.path.join(tmp, "lab-hosts.json")
    with open(p, "w") as f:
        json.dump(doc, f)
    return p


GOOD = {"hosts": [
    {"name": "production", "role": "workstation", "aliases": ["infected"], "ip": "192.0.2.56",
     "host_id": "00000000-0000-4000-8000-0000000000a1", "note": "range"},
    {"name": "lab-two", "role": "domain_controller", "ip": "192.0.2.57", "host_id": None, "note": "no id yet"},
]}


class TestLabHosts(unittest.TestCase):
    def test_loads_every_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = labhosts.load_lab_hosts(_write(tmp, GOOD))
            self.assertEqual(len(hosts), 2)
            self.assertEqual(hosts[0]["name"], "production")

    def test_primary_host_is_the_first_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(labhosts.primary_host(_write(tmp, GOOD))["name"], "production")

    def test_host_for_role_selects_the_dc(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, GOOD)
            self.assertEqual(labhosts.host_for_role("domain_controller", p)["name"], "lab-two")

    def test_host_for_missing_role_fails_loud(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(labhosts.LabHostsError):
                labhosts.host_for_role("domain_controller", _write(tmp, {"hosts": [GOOD["hosts"][0]]}))

    def test_invalid_role_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = {"hosts": [{"name": "bad", "role": "customer"}]}
            with self.assertRaises(labhosts.LabHostsError):
                labhosts.load_lab_hosts(_write(tmp, bad))

    # Fail loud, never an empty list: an empty lab-host set would silently detonate
    # attacks into the customer-facing path.
    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(labhosts.LabHostsError):
                labhosts.load_lab_hosts(os.path.join(tmp, "nope.json"))

    def test_empty_list_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(labhosts.LabHostsError):
                labhosts.load_lab_hosts(_write(tmp, {"hosts": []}))

    def test_nameless_host_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(labhosts.LabHostsError):
                labhosts.load_lab_hosts(_write(tmp, {"hosts": [{"ip": "10.0.0.1"}]}))

    def test_projections(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = labhosts.load_lab_hosts(_write(tmp, GOOD))
            self.assertEqual(labhosts.host_names(hosts), ["production", "infected", "lab-two"])
            self.assertEqual(labhosts.host_ips(hosts), ["192.0.2.56", "192.0.2.57"])
            # a null host_id is dropped, never carried through as None
            self.assertEqual(labhosts.host_ids(hosts), ["00000000-0000-4000-8000-0000000000a1"])

    def test_is_lab_host_matches_name_id_and_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = labhosts.load_lab_hosts(_write(tmp, GOOD))
            self.assertTrue(labhosts.is_lab_host({"name": "PRODUCTION"}, hosts))
            # renamed from `infected` on 2026-05-15; 4752 alerts still carry the old name
            self.assertTrue(labhosts.is_lab_host({"name": "infected"}, hosts))
            self.assertTrue(labhosts.is_lab_host(
                {"id": "00000000-0000-4000-8000-0000000000a1"}, hosts))
            self.assertTrue(labhosts.is_lab_host({"ip": "192.0.2.56"}, hosts))
            self.assertFalse(labhosts.is_lab_host({"name": "laptop-jfk3"}, hosts))
            self.assertFalse(labhosts.is_lab_host({}, hosts))


class TestConfigDefaultsFromRegistry(unittest.TestCase):
    """The engine's lab addresses come from lab-hosts.json, not from a literal.

    config.py carried its own lab address defaults, and after the 2026-07-29
    move they sat stale for about four weeks. A stale address is not an inert
    failure: .65 is held by a DIFFERENT device now, so a stale default aims the
    attack path at someone else's machine.

    Both cases neutralise the credentials reader. `_resolve` consults the local
    credentials file for every key, and the founder's box carries WIN_HOST and
    DC_HOST there (the 2026-07-29 IP-move checklist), so without this the test
    would never exercise the new default on that machine while exercising it on CI.
    """

    def setUp(self):
        import config
        testenv.use_fixture_lab_hosts(self)
        self.config = config
        self._read_creds = config._read_creds
        config._read_creds = lambda key: None

    def tearDown(self):
        self.config._read_creds = self._read_creds

    def test_win_host_defaults_to_the_registry_workstation(self):
        os.environ.pop("WIN_HOST", None)
        self.assertEqual(
            self.config.load_config()["win_host"],
            labhosts.host_for_role("workstation")["ip"])

    def test_dc_host_defaults_to_the_registry_domain_controller(self):
        os.environ.pop("DC_HOST", None)
        self.assertEqual(
            self.config.load_config()["dc_host"],
            labhosts.host_for_role("domain_controller")["ip"])

    def test_an_explicit_environment_value_still_wins(self):
        os.environ["WIN_HOST"] = "10.9.9.9"
        try:
            self.assertEqual(self.config.load_config()["win_host"], "10.9.9.9")
        finally:
            os.environ.pop("WIN_HOST", None)

    def test_an_unreadable_registry_fails_loud_rather_than_guessing(self):
        """A registry that cannot be read is a repo defect, not a lab fact."""
        original = labhosts.host_for_role
        labhosts.host_for_role = lambda *a, **k: (_ for _ in ()).throw(
            labhosts.LabHostsError("boom"))
        os.environ.pop("WIN_HOST", None)
        try:
            with self.assertRaises(labhosts.LabHostsError):
                self.config.load_config()
        finally:
            labhosts.host_for_role = original


if __name__ == "__main__":
    unittest.main()
