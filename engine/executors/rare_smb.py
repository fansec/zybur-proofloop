# rules/engine/executors/rare_smb.py
"""DIRECT_RARE_SMB: make the target connect SMB to a routable public IP that is DNAT'd
back to the local Samba listener, generating "rare SMB to the internet" telemetry."""
import time, random, subprocess
from executors.registry import register
from executors._net import now_iso
from result import make_result

@register("rare_smb")
def rare_smb(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    cfg = ctx.cfg
    # 44.x.x.x is routable and not in the rule's exclusion list; DNAT'd locally anyway.
    fake_public_ip = f"44.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    # No literal fallback: a stale address here DNATs the target's traffic to whoever
    # holds it now (the 2026-08-26 class). The attacker address is configuration.
    linux_ip = cfg.get("linux_host") or cfg.get("attacker_ip")
    if not linux_ip:
        raise ValueError("ATTACKER_IP not set")
    win_host = cfg["win_host"]
    iptables_rule = [
        "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", win_host, "-d", fake_public_ip, "-p", "tcp", "--dport", "445",
        "-j", "DNAT", "--to-destination", f"{linux_ip}:445",
    ]
    start = now_iso()
    try:
        subprocess.run(iptables_rule, check=True, capture_output=True, timeout=10)
        try:
            route_cmd = f'route add {fake_public_ip} mask 255.255.255.255 {linux_ip}'
            session.run_cmd("cmd", ["/c", route_cmd])
            time.sleep(1)
            smb_cmd = (f'net use \\\\{fake_public_ip}\\IPC$ /user:guest "" 2>nul & '
                       f'echo RARE_SMB_TEST_DONE')
            r = session.run_cmd("cmd", ["/c", smb_cmd])
            stdout = r.std_out.decode("utf-8", errors="replace").strip()
            stderr = r.std_err.decode("utf-8", errors="replace").strip()
            output = stdout or stderr
            end = now_iso()
            time.sleep(3)
            session.run_cmd("cmd", ["/c",
                f'net use \\\\{fake_public_ip}\\IPC$ /delete /y 2>nul & '
                f'route delete {fake_public_ip} 2>nul'])
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                               op_id="direct-rare-smb", output=f"SMB to {fake_public_ip}:445 via NAT. {output}")
        finally:
            cleanup_rule = list(iptables_rule)
            cleanup_rule[4] = "-D"  # -A -> -D (index 4 after the sudo prefix)
            subprocess.run(cleanup_rule, capture_output=True, timeout=10)
    except Exception as e:
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
