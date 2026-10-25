# rules/engine/firewall.py
"""Windows Firewall port management for SMB/RPC DIRECT_* plugins (ported).

Ports keyed by executor name, from tests.yaml's firewall_rules. open() adds inbound
allow rules scoped to the attacker IP before the detonation; close() removes them.
Optional: plugins skip firewall when ctx.firewall is None (e.g. in wiring tests).
"""
import logging
log = logging.getLogger("engine.firewall")

FIREWALL_RULES = {
    "smb_write":        [("P1-TEST-SMB-In", "445", "TCP")],
    "smb_exe_transfer": [("P1-TEST-SMB-In", "445", "TCP")],
    "smb_ransom_note":  [("P1-TEST-SMB-In", "445", "TCP")],
    "smb_rename":       [("P1-TEST-SMB-In", "445", "TCP")],
    "remote_service":   [("P1-TEST-SMB-In", "445", "TCP"), ("P1-TEST-RPC-In", "135", "TCP"),
                         ("P1-TEST-RPC-HighPorts", "49152-65535", "TCP")],
    "remote_schtask":   [("P1-TEST-SMB-In", "445", "TCP"), ("P1-TEST-RPC-In", "135", "TCP"),
                         ("P1-TEST-RPC-HighPorts", "49152-65535", "TCP")],
    "dcomexec":         [("P1-TEST-RPC-In", "135", "TCP"),
                         ("P1-TEST-RPC-HighPorts", "49152-65535", "TCP")],
    "wmiexec":          [("P1-TEST-RPC-In", "135", "TCP"),
                         ("P1-TEST-RPC-HighPorts", "49152-65535", "TCP")],
}


class FirewallService:
    def open(self, session, executor_name, cfg, remoteip=None):
        rules = FIREWALL_RULES.get(executor_name)
        if not rules or not session:
            return []
        # Scope the inbound allow to where the traffic really originates. Netns-based
        # executors come from the deduped source IP, not attacker_ip, and must pass it.
        # Until 2026-10-14 only dcomexec and wmiexec did: smb_ransom_note, smb_rename,
        # smb_exe_transfer, remote_service and remote_schtask sent from the netns IP
        # through a rule scoped to attacker_ip, so Windows dropped the connection
        # (NT_STATUS_IO_TIMEOUT, ransom note ABORT 2026-07-29 and 2026-10-14).
        rip = remoteip or cfg["attacker_ip"]
        created = []
        for rule_name, port, proto in rules:
            if rule_name in created:
                continue
            cmd = (f'netsh advfirewall firewall add rule name="{rule_name}" '
                   f'dir=in action=allow protocol={proto} localport={port} '
                   f'remoteip={rip} enable=yes')
            r = session.run_cmd('cmd', ['/c', cmd])
            out = r.std_out.decode("utf-8", errors="replace").strip()
            if "Ok" in out or r.status_code == 0:
                created.append(rule_name)
        return created

    def close(self, session, rule_names):
        if not session:
            return
        seen = set()
        for rule_name in rule_names:
            if rule_name in seen:
                continue
            seen.add(rule_name)
            session.run_cmd('cmd', ['/c', f'netsh advfirewall firewall delete rule name="{rule_name}"'])
