# rules/engine/executors/remote_schtask.py
"""DIRECT_REMOTE_SCHTASK: create a scheduled task remotely via impacket TSCH RPC inside
a macvlan netns, with a WMI-in-netns fallback and a WinRM belt-and-suspenders cleanup.

Host, user and password never appear in a command line or in generated code: the RPC snippet
reads them from its stdin (run_in_netns stdin_json) and the WMI fallback's child does the same
(executors.wmiexec.child_payload)."""
import sys, subprocess
from executors.registry import register
from executors._net import now_iso
from executors import wmiexec as wmi
from result import make_result
from dedup import _ensure_netns


def _cleanup_schtask_winrm(session):
    if not session:
        return
    try:
        session.run_cmd("cmd", ["/c", "schtasks /delete /tn TestRemoteTask /f 2>nul"])
    except Exception:
        pass


def _wmiexec_fallback(usecase, cfg, source_ip, session, start):
    """The three schtasks commands as WMI process creations from inside the source_ip namespace.

    One child, one `sudo ip netns exec`: the child reads the credentials and the commands from
    stdin and sleeps between them (3 s after the create, 5 s after the run, as the old
    one-command-per-process sequence did). If the first command cannot even connect the child
    ends there and the result is WMI_CONNECT_FAIL, as before. The old fallback ran
    impacket-wmiexec, whose argument list carried the password and whose SMB channel returned
    each command's own output; this one has no output channel, so `output` is the three
    Win32_Process.Create result lines.
    """
    ns_name = _ensure_netns(source_ip)
    steps = [
        ("schtasks /create /tn TestRemoteTask /tr cmd.exe /sc once /st 23:59 /f", 3),
        ("schtasks /run /tn TestRemoteTask", 5),
        ("schtasks /delete /tn TestRemoteTask /f", 0),
    ]
    r = subprocess.run(
        ["sudo", "ip", "netns", "exec", ns_name, sys.executable, "-c", wmi.child_boot()],
        input=wmi.child_payload(cfg, steps, timeout=25),
        capture_output=True, text=True, timeout=150,
    )
    out = r.stdout.strip() + r.stderr.strip()
    first = out.splitlines()[0] if out else ""
    fail_indicators = ("NT_STATUS", "Could not connect", "Connection timed out",
                       "TIMEOUT", "Connection refused", "DCOM connection failed", "WMI_FAIL")
    if r.returncode != 0 or any(ind in first for ind in fail_indicators):
        return make_result(usecase, "WMI_CONNECT_FAIL", False, op_id="direct-remote-schtask",
                           attack_start=start, attack_end=now_iso(), output=out)
    _cleanup_schtask_winrm(session)
    return make_result(usecase, "SUCCESS", True, op_id="direct-remote-schtask",
                       attack_start=start, attack_end=now_iso(), output=f"{out} [src={source_ip}]")


@register("remote_schtask")
def remote_schtask(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    source_ip = ctx.dedup.allocate(usecase["id"]) if ctx.dedup else None
    fw = ctx.firewall.open(session, "remote_schtask", ctx.cfg, remoteip=source_ip) if (ctx.firewall and session) else []
    cfg = ctx.cfg
    start = now_iso()
    try:
        code = f'''
import json, sys, time
from impacket.dcerpc.v5 import tsch, transport as impacket_transport, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

creds = json.load(sys.stdin)
host, user, passwd = creds["win_host"], creds["win_user"], creds["win_pass"]
task_name = "\\\\TestRemoteTask"

task_xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2099-01-01T23:59:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c echo DETECTION_TEST_SCHTASK</Arguments>
    </Exec>
  </Actions>
</Task>"""

print(f"Resolving Task Scheduler endpoint via EPM [src={source_ip}]")
string_binding = epm.hept_map(host, tsch.MSRPC_UUID_TSCHS, protocol="ncacn_ip_tcp")
print(f"TSCH binding: {{string_binding}}")
rpctransport = impacket_transport.DCERPCTransportFactory(string_binding)
rpctransport.setRemoteHost(host)
rpctransport.set_credentials(user, passwd, "", "", "")
dce = rpctransport.get_dce_rpc()
dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
dce.connect()
dce.bind(tsch.MSRPC_UUID_TSCHS)
print(f"Connected to Task Scheduler via TCP [src={source_ip}]")

try:
    tsch.hSchRpcDelete(dce, task_name)
    print("Cleaned up existing task")
    time.sleep(1)
except Exception:
    pass

tsch.hSchRpcRegisterTask(dce, task_name, task_xml,
                         tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
print(f"Registered task: {{task_name}}")

try:
    tsch.hSchRpcRun(dce, task_name)
    print("Task triggered")
except Exception as e:
    print(f"Task run: {{str(e)[:80]}}")

time.sleep(5)
try:
    tsch.hSchRpcDelete(dce, task_name)
    print("Task deleted")
except Exception:
    pass
dce.disconnect()
print("SUCCESS")
'''
        rc, stdout, stderr = ctx.dedup.run_in_netns(
            source_ip, code, timeout=60,
            stdin_json={"win_host": cfg["win_host"], "win_user": cfg["win_user"],
                        "win_pass": cfg["win_pass"]})
        output = stdout + ("\n" + stderr if stderr else "")
        _cleanup_schtask_winrm(session)
        if "SUCCESS" in stdout:
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=now_iso(),
                               op_id="direct-rpc-tcp-schtask", output=f"{stdout} [src={source_ip}]")
        return _wmiexec_fallback(usecase, cfg, source_ip, session, start)
    except Exception as e:
        _cleanup_schtask_winrm(session)
        try:
            return _wmiexec_fallback(usecase, cfg, source_ip, session, start)
        except Exception:
            return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall and session:
            ctx.firewall.close(session, fw)
