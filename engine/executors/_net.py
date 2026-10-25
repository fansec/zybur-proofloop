# rules/engine/executors/_net.py
"""Subprocess network helpers shared by DIRECT_* plugins (ported from run_caldera.py).

smb_client / smb_client_from run smbclient (the _from variant inside a macvlan netns
for a unique source IP); wmiexec creates one process by WMI in a child process. A credential
never goes on a command line, where `ps` shows it to every local user: smbclient reads it from
an authentication file made for the one call, and the WMI child reads it from its standard
input. The netns paths need root. Wiring tests monkeypatch these so no real I/O happens offline.
"""
import contextlib, os, subprocess, sys, tempfile
from datetime import datetime, timezone
from dedup import _ensure_netns


def now_iso():
    return datetime.now(timezone.utc).isoformat()


@contextlib.contextmanager
def _auth_file(cfg):
    """A private smbclient authentication file (`-A`) for one call: mode 0600, removed on exit.

    Holds `username` and `password` and nothing else. There is deliberately no `domain` line:
    smbclient then applies its own default workgroup, which is exactly what `-U user%password`
    did, and a `DOMAIN\\user` written into `username` is split the same way `-U` splits it
    (both measured 2026-10-24 against smbclient 4.19). A domain line from configuration would
    change the NTLM domain the workstation sees. The file is line based, so a value with a line
    break is refused by name rather than letting it inject a line.
    """
    for name, value in (("win_user", cfg["win_user"]), ("win_pass", cfg["win_pass"])):
        if "\n" in str(value) or "\r" in str(value):
            raise ValueError(f"{name} holds a line break, which an smbclient authentication file cannot carry")
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".smbauth", delete=False)   # created 0600
    try:
        f.write(f"username = {cfg['win_user']}\npassword = {cfg['win_pass']}\n")
        f.close()
        yield f.name
    finally:
        f.close()
        try:
            os.unlink(f.name)
        except FileNotFoundError:
            pass


def smb_client(cfg, smb_commands, timeout=30):
    """Run smbclient with configured credentials. Returns (returncode, stdout, stderr)."""
    with _auth_file(cfg) as auth:
        r = subprocess.run(
            ["smbclient", f"//{cfg['win_host']}/C$", "-A", auth, "-c", smb_commands],
            capture_output=True, text=True, timeout=timeout,
        )
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def smb_client_from(cfg, smb_commands, source_ip=None, timeout=30):
    """smbclient optionally bound to source_ip via a macvlan network namespace."""
    if source_ip:
        ns_name = _ensure_netns(source_ip)
        with _auth_file(cfg) as auth:
            r = subprocess.run(
                ["sudo", "ip", "netns", "exec", ns_name,
                 "smbclient", f"//{cfg['win_host']}/C$", "-A", auth,
                 "-c", smb_commands],
                capture_output=True, text=True, timeout=timeout,
            )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    return smb_client(cfg, smb_commands, timeout)


def wmiexec(cfg, remote_command, timeout=30):
    """Create one process on cfg's host by WMI (Win32_Process.Create over DCOM).

    Returns (returncode, output): the child's exit code and its printed result line,
    `SUCCESS: Win32_Process.Create ... ProcessId=<n>` or `WMI_FAIL: <why>`. The old helper ran
    the impacket-wmiexec command line, whose argument list carried the password and whose SMB
    output channel returned the command's own output; this one has no output channel (the same
    trade executors/wmiexec.py makes), so the command's output is not returned. The work is
    executors.wmiexec.run_wmi in a child interpreter that reads the credentials from stdin.
    """
    from executors import wmiexec as wmi   # late: that module imports this one
    r = subprocess.run(
        [sys.executable, "-c", wmi.child_boot()],
        input=wmi.child_payload(cfg, [(remote_command, 0)], timeout=timeout),
        capture_output=True, text=True, timeout=timeout + 15,
    )
    return r.returncode, r.stdout.strip() + r.stderr.strip()
