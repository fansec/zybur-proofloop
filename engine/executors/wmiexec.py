# rules/engine/executors/wmiexec.py
"""DIRECT_WMI: remote WMI process creation (Win32_Process.Create) over DCOM.

Ports the core of impacket's wmiexec (DCOMConnection -> IWbemLevel1Login ->
NTLMLogin root/cimv2 -> Win32_Process.Create), without its SMB output channel. Runs
inside a macvlan netns, like dcomexec, so the RPC traffic comes from a unique,
non-loopback source IP. That is the behaviour the target WMI sequence rule keys on:
  seq by host.id, maxspan 20s:
    [network, svchost.exe, incoming, destination.port 135, source.ip not loopback]
    -> [process start, parent WmiPrvSE.exe, integrity not System, user not SYSTEM]

Why it exists (2026-10-14): the use-case ran Invoke-WmiMethod -ComputerName itself
over WinRM ON the workstation. Windows refuses user credentials on a local WMI
connection and -EA SilentlyContinue hid the error, so no process was ever created,
and a local call has no incoming non-loopback RPC leg anyway. It MISSED on all 7
nightly runs since 2026-08-09. The remediation recorded on 2026-09-15
(plans/04-technical/edr/rule-trigger-remediation-2026-09-15.md) is a true remote
WMI executor from an allocated netns with temporary RPC firewall access; this is it.

params.command is the child command line, run as `cmd.exe /Q /c <command>` (the same
shape impacket wmiexec uses). Keep it benign; it defaults to an echo that writes
nothing. The child runs as cfg win_user, a real admin, so its token is High
integrity, never System, which the rule's second stage needs.

SUCCESS only when Create came back with ReturnValue 0 and a ProcessId: an RPC call
that "went through" proves nothing about a process. The declared cleanup runs over
WinRM afterwards, best-effort; the reconcile manifest probes the marker either way.
"""
import base64
import re
import socket
import sys
import time
import opensslconf
from dedup import ENGINE_DIR
from executors.registry import register
from executors._net import now_iso
from result import make_result
from config import subst

# The one line the embedded script prints when Win32_Process.Create returned 0.
# Matched whole, at the start of a line, so an exception text that happens to
# contain "SUCCESS" can never read as a created process.
_SUCCESS_LINE = re.compile(r"^SUCCESS: Win32_Process\.Create ReturnValue=0 ProcessId=(\d+)$", re.M)

# Seconds to let the child cmd.exe finish its marker write before the cleanup
# removes it. Create returns when the process exists, not when it has exited.
CLEANUP_DELAY_S = 3


def _script(source_ip, cfg, child_cmd):
    # b64 everything that comes from config/params so credentials or commands with
    # quotes/backslashes can never break the embedded script's string literals.
    b64cmd = base64.b64encode(child_cmd.encode()).decode()
    b64host = base64.b64encode(str(cfg["win_host"]).encode()).decode()
    b64user = base64.b64encode(str(cfg["win_user"]).encode()).decode()
    b64pass = base64.b64encode(str(cfg["win_pass"]).encode()).decode()
    return f'''
import base64
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

host = base64.b64decode("{b64host}").decode()
user = base64.b64decode("{b64user}").decode()
passwd = base64.b64decode("{b64pass}").decode()
command = "cmd.exe /Q /c " + base64.b64decode("{b64cmd}").decode()

print("WMI connect [src={source_ip}] -> %s" % host)
dcom = None
try:
    dcom = DCOMConnection(host, user, passwd, "", "", "", "", oxidResolver=True)
    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
    iWbemLevel1Login.RemRelease()
    win32Process, _ = iWbemServices.GetObject("Win32_Process")
    out = win32Process.Create(command, "C:\\\\", None)
    rv = getattr(out, "ReturnValue", None)
    pid = getattr(out, "ProcessId", None)
    if rv == 0 and pid is not None:
        print("SUCCESS: Win32_Process.Create ReturnValue=0 ProcessId=%s" % pid)
    else:
        print("WMI_FAIL: Win32_Process.Create ReturnValue=%s ProcessId=%s" % (rv, pid))
    try: iWbemServices.RemRelease()
    except Exception: pass
except Exception as e:
    print("WMI_FAIL: %s" % str(e)[:220])
finally:
    if dcom is not None:
        try: dcom.disconnect()
        except Exception: pass
'''


def run_wmi(cfg, command, timeout=30):
    """Win32_Process.Create of `cmd.exe /Q /c <command>` on cfg["win_host"], in THIS process.

    The call chain _script() embeds for the netns executor (DCOMConnection, IWbemLevel1Login,
    NTLMLogin to root/cimv2, Win32_Process.Create), as a function: the credentials are
    arguments, never text inside a shell string or a generated script. Returns
    (0, "SUCCESS: Win32_Process.Create ReturnValue=0 ProcessId=<n>") or (1, "WMI_FAIL: <why>").
    There is no output channel (the trade _script() makes too), so the command's own output is
    not returned. `timeout` bounds every socket operation and the previous default is restored.
    """
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    dcom = None
    try:
        dcom = DCOMConnection(cfg["win_host"], cfg["win_user"], cfg["win_pass"], "", "", "", "",
                              oxidResolver=True)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()
        win32Process, _ = iWbemServices.GetObject("Win32_Process")
        out = win32Process.Create("cmd.exe /Q /c " + command, "C:\\", None)
        rv = getattr(out, "ReturnValue", None)
        pid = getattr(out, "ProcessId", None)
        try:
            iWbemServices.RemRelease()
        except Exception:
            pass
        if rv == 0 and pid is not None:
            return 0, "SUCCESS: Win32_Process.Create ReturnValue=0 ProcessId=%s" % pid
        return 1, "WMI_FAIL: Win32_Process.Create ReturnValue=%s ProcessId=%s" % (rv, pid)
    except Exception as e:
        return 1, "WMI_FAIL: %s" % str(e)[:220]
    finally:
        if dcom is not None:
            try:
                dcom.disconnect()
            except Exception:
                pass
        socket.setdefaulttimeout(previous)


# --- run_wmi from a child process, credentials on its standard input ------------------------
# remote_schtask's fallback and _net.wmiexec need the call from a process of their own: the
# fallback inside a network namespace (through `sudo ip netns exec`, whose argument list `ps`
# shows to every local user), _net.wmiexec in a clean interpreter with the verified OpenSSL
# config. Either way the argument list holds paths and code only; host, user and password
# travel as `name=value` lines on stdin.

def child_boot():
    """The `python -c` program of the child: the verified OpenSSL config first (before anything
    can initialise OpenSSL), then the engine on sys.path, then child_main. Paths only."""
    return ("import os, sys\n"
            f"os.environ['OPENSSL_CONF'] = {opensslconf.ensure_openssl_conf()!r}\n"
            f"sys.path.insert(0, {ENGINE_DIR!r})\n"
            "from executors.wmiexec import child_main\n"
            "sys.exit(child_main())\n")


def child_payload(cfg, steps, timeout=25):
    """What child_main reads: `name=value` lines. `steps` is [(command, seconds to wait after it)].

    Lines rather than JSON so the password reaches the child as itself, with nothing to escape.
    The one thing a line cannot carry is a line break, so a value that holds one is refused here,
    naming the field, rather than truncated there.
    """
    fields = [("win_host", cfg["win_host"]), ("win_user", cfg["win_user"]),
              ("win_pass", cfg["win_pass"]), ("timeout", timeout)]
    for command, pause in steps:
        fields.append(("command", command))
        if pause:
            fields.append(("pause", pause))
    lines = []
    for name, value in fields:
        value = str(value)
        if "\n" in value or "\r" in value:
            raise ValueError(f"{name} holds a line break, which the WMI child's standard input cannot carry")
        lines.append(f"{name}={value}\n")
    return "".join(lines)


def child_main(text=None, out=None):
    """Run the payload's commands in order through run_wmi, printing one result line per command.

    The first command is the connection test: if it fails the run ends there with its return
    code. A later failure is printed and does not stop the rest (the caller's own fallback
    sequence always tolerated that). Returns the process exit code.
    """
    text = sys.stdin.read() if text is None else text
    out = out or sys.stdout
    fields, steps = {}, []
    for line in text.split("\n"):
        name, _, value = line.partition("=")
        if name == "command":
            steps.append([value, 0.0])
        elif name == "pause" and steps:
            steps[-1][1] = float(value)
        elif name:
            fields[name] = value
    cfg = {key: fields[key] for key in ("win_host", "win_user", "win_pass")}
    timeout = int(fields.get("timeout") or 30)
    for i, (command, pause) in enumerate(steps):
        rc, output = run_wmi(cfg, command, timeout=timeout)
        print(output, file=out, flush=True)
        if i == 0 and rc != 0:
            return rc
        if pause:
            time.sleep(pause)
    return 0


def _cleanup(usecase, cfg, session):
    """Best-effort: run the declared cleanup over WinRM. Never fails the run."""
    cleanup = subst(usecase.get("cleanup") or "", cfg or {})
    if not (cleanup.strip() and session):
        return
    try:
        time.sleep(CLEANUP_DELAY_S)
        session.run_ps(cleanup)
    except Exception:
        pass


@register("wmiexec")
def wmiexec(usecase, ctx):
    start = now_iso()
    if not ctx.dedup:
        # Without the netns there is no non-loopback source of our own to scope the
        # firewall to, and the run would be the self-targeting call this replaced.
        return make_result(usecase, "WMI_FAIL: no dedup allocator (netns source IP required)",
                           False, attack_start=start, attack_end=now_iso())
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    source_ip = ctx.dedup.allocate(usecase["id"])
    fw = (ctx.firewall.open(session, "wmiexec", ctx.cfg, remoteip=source_ip)
          if (ctx.firewall and session) else [])
    cfg = ctx.cfg
    p = usecase.get("params") or {}
    child_cmd = subst(p.get("command") or "echo zyb_wmi", cfg or {}).strip()
    start = now_iso()
    try:
        code = _script(source_ip, cfg, child_cmd)
        rc, stdout, stderr = ctx.dedup.run_in_netns(source_ip, code, timeout=90)
        end = now_iso()
        output = stdout + ("\n" + stderr if stderr else "")
        m = _SUCCESS_LINE.search(stdout or "")
        if m:
            _cleanup(usecase, cfg, session)
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                               op_id="direct-wmi-win32process",
                               output=f"{m.group(0)} [src={source_ip}]")
        return make_result(usecase, f"WMI_FAIL: {output[:200]}", False,
                           attack_start=start, attack_end=end, output=output)
    except Exception as e:
        return make_result(usecase, f"WMI_FAIL: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall and session:
            ctx.firewall.close(session, fw)
