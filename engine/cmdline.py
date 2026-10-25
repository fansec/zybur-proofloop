# rules/engine/cmdline.py
"""How long a WinRM command may be, measured the way the Windows box receives it.

pywinrm's run_ps is run_cmd('powershell -encodedcommand <base64 of UTF-16LE>'), and
WinRS hands every run_cmd to `cmd.exe /C <command>`. cmd.exe refuses a command
string over 8191 characters, so PowerShell never starts, nothing reaches stdout, and
the call still returns. Measured live 2026-10-14 in the endpoint process events:
every reconcile probe chunk (cmd.exe command lines of 23,814 and 12,878 characters)
started cmd.exe and no powershell.exe, while a 270-character command started both;
the BITS payload (9,027) never ran and Office (6,491) did. The earlier reading of
the limit as CreateProcess's 32,767 (reconcile.py, 2026-09-11) measured a different
failure: an HTTP 500 above 32,767, not the silent one below it.

One place for the number, so the executors, reconcile and lint cannot disagree.
"""
from base64 import b64encode

CMD_EXE_LIMIT = 8191
# Headroom under the hard ceiling for the `cmd.exe /C` framing and any quoting
# WinRS adds. Every payload measured working on 2026-10-14 is below it.
MAX_RUN_PS_CMDLINE = 8000
RUN_PS_PREFIX = "powershell -encodedcommand "


def run_ps_cmdline_len(ps):
    """The length of the command string cmd.exe receives for run_ps(ps)."""
    return len(RUN_PS_PREFIX) + len(b64encode(str(ps).encode("utf-16-le")))


def run_cmd_cmdline_len(command):
    """The length of the command string cmd.exe receives for run_cmd('cmd', ['/c', command])."""
    return len("cmd /c ") + len(str(command))


def fits(length):
    return length <= MAX_RUN_PS_CMDLINE
