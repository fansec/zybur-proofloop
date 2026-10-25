# rules/engine/executors/psremoting.py
"""DIRECT_WINRM #33: PS Remoting via pypsrp (MS-PSRP) inside a macvlan netns, so the
target spawns wsmprovhost.exe from a fresh source IP that never touched 5985."""
from executors.registry import register
from executors._net import now_iso
from result import make_result

@register("psremoting")
def psremoting(usecase, ctx):
    source_ip = ctx.dedup.allocate(usecase["id"]) if ctx.dedup else None
    cfg = ctx.cfg
    start = now_iso()
    try:
        # Host, user and password reach the snippet on stdin (run_in_netns stdin_json), never as
        # text in it: nothing to quote, nothing in a process argument list, nothing in the file.
        code = f'''
import json, sys
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan

creds = json.load(sys.stdin)
host, user, passwd = creds["win_host"], creds["win_user"], creds["win_pass"]

print(f"PS Remoting (pypsrp/MS-PSRP) [src={source_ip}]")
wsman = WSMan(host, port=5985, username=user, password=passwd,
              ssl=False, auth="ntlm", encryption="never",
              operation_timeout=30, read_timeout=40)
with RunspacePool(wsman) as pool:
    ps = PowerShell(pool)
    ps.add_script("whoami")
    output = ps.invoke()
    result = "\\n".join(str(o) for o in output)
    print(f"Output: {{result}}")

    ps2 = PowerShell(pool)
    ps2.add_script("hostname")
    output2 = ps2.invoke()
    result2 = "\\n".join(str(o) for o in output2)
    print(f"Hostname: {{result2}}")
print("SUCCESS")
'''
        rc, stdout, stderr = ctx.dedup.run_in_netns(
            source_ip, code, timeout=60,
            stdin_json={"win_host": cfg["win_host"], "win_user": cfg["win_user"],
                        "win_pass": cfg["win_pass"]})
        end = now_iso()
        output = stdout + ("\n" + stderr if stderr else "")
        if "SUCCESS" in stdout:
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                               op_id="direct-psrp-netns", output=f"{stdout} [src={source_ip}]")
        return make_result(usecase, f"PSRP_FAIL: {output[:200]}", False,
                           attack_start=start, attack_end=end, output=output)
    except Exception as e:
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
