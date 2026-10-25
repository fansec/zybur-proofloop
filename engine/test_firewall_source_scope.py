# rules/engine/test_firewall_source_scope.py
"""Every executor that sends from a deduped source IP opens the firewall for THAT IP.

2026-10-14: five executors allocated a netns source IP, sent their SMB or RPC traffic
from it, and opened the inbound rule for attacker_ip instead, so the target dropped
the connection and the ransomware-note case aborted (NT_STATUS_IO_TIMEOUT). Read from
the source, so a new executor that repeats the pattern fails here before a live run.
"""
import os, pathlib, re, unittest

EXEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "executors")


class TestFirewallFollowsTheSourceIp(unittest.TestCase):
    def test_every_netns_executor_scopes_its_firewall_to_the_netns_ip(self):
        checked = []
        for fn in sorted(os.listdir(EXEC)):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            src = pathlib.Path(EXEC, fn).read_text()
            if "ctx.dedup.allocate" not in src or "ctx.firewall.open(" not in src:
                continue
            checked.append(fn)
            for call in re.findall(r"ctx\.firewall\.open\([^)]*\)", src):
                self.assertIn("remoteip=source_ip", call, f"{fn}: {call}")
        self.assertGreaterEqual(len(checked), 7, checked)


if __name__ == "__main__":
    unittest.main()
