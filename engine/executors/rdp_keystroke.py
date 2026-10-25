# rules/engine/executors/rdp_keystroke.py
"""DIRECT_WINRM #21 (fake CAPTCHA) + #45 (SharpRDP): xfreerdp3 + xdotool keystroke
injection over RDP so explorer.exe (not winrshost.exe) is the parent of the launched
process. The keystroke typed into Win+R comes from params.keystroke (falls back to
params.command, else 'cmd.exe'); e.g. #21 types a 'Verification ID' CAPTCHA command.

Serves two use-cases (SharpRDP and fake-CAPTCHA), so the landed check below matches
the actual typed string and assumes no cmd.exe/powershell.exe prefix. Remedies for the
vacuous-COMPLETE defect were proposed 2026-09-05 and 2026-09-06 and never applied; this
is the applied fix (finding f13f94940d29)."""
import os, shlex, time, tempfile, subprocess
from executors.registry import register
from executors._net import now_iso
from result import make_result

RDP_TOOLS = ["xfreerdp3", "xdotool", "Xvfb", "openbox"]

# The Run dialog is a single-line edit control capped at 259 characters.
RUN_DIALOG_MAX = 259

# The pre-seed writes these two values into the Administrator RunMRU hive so the key
# exists before the RDP session runs. They are deliberately notepad/calc - things no
# real attack keystroke is - so the readback can tell "explorer.exe wrote nothing new"
# from "explorer.exe recorded the typed command". They must never satisfy the landed
# check on their own.
PRESEED_VALUES = ("notepad.exe\\1", "calc.exe\\1")

# The readback reads the same Administrator HKCU RunMRU the pre-seed wrote to (the
# WinRM session runs as that account), and emits each value on its own line behind a
# marker so std_out parses cleanly. MRUList is the ordering blob, not a command.
_RUNMRU_MARKER = "RUNMRU_VALUE::"
_READBACK_PS = (
    '$p = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"; '
    '$k = Get-Item -Path $p -EA SilentlyContinue; '
    'if ($k) { $k.GetValueNames() | Where-Object { $_ -ne "MRUList" } | '
    'ForEach-Object { "' + _RUNMRU_MARKER + '" + $k.GetValue($_) } }'
)


def _redact(text, cfg):
    """Strip the RDP password out of anything that leaves this module."""
    pw = (cfg or {}).get("win_pass") or ""
    return text.replace(pw, "***") if pw else text


def _keystroke_problem(keystroke):
    """Why this string cannot be typed into Win+R, or None if it can."""
    if not keystroke.strip():
        return "empty"
    if "\n" in keystroke or "\r" in keystroke:
        return ("multi-line command; the Run dialog takes one line - give the "
                "use-case a single-line params.command")
    if len(keystroke) > RUN_DIALOG_MAX:
        return f"{len(keystroke)} chars, over the Run dialog cap of {RUN_DIALOG_MAX}"
    return None


def _runmru_values(session):
    """RunMRU value strings the WinRM (Administrator) session can see, MRUList
    excluded. Returns None if the readback itself could not run - which is a
    different thing from an empty RunMRU, and the reason string keeps them apart."""
    try:
        resp = session.run_ps(_READBACK_PS)
    except Exception:
        return None
    out = getattr(resp, "std_out", b"") or b""
    if isinstance(out, (bytes, bytearray)):
        out = bytes(out).decode("utf-8", "replace")
    return [ln[len(_RUNMRU_MARKER):] for ln in str(out).splitlines()
            if ln.startswith(_RUNMRU_MARKER)]


def _keystroke_landed(values, keystroke):
    """True iff a RunMRU value records this keystroke. The pre-seed is excluded, so
    only what explorer.exe wrote for the typed command can satisfy it. A recorded
    Run command is stored as '<typed text>\\1', so startswith(keystroke) matches."""
    for v in values:
        if v in PRESEED_VALUES:
            continue
        if v.startswith(keystroke):
            return True
    return False


def _bash_markers(log):
    """Named failure signals the generated bash echoes, so the reason can say which
    step went nowhere instead of resting on an unconditional COMPLETE."""
    m = []
    if "FAIL: RDP disconnected" in log:
        m.append("xfreerdp disconnected before typing")
    if "NO_WINDOW" in log:
        m.append("no RDP window to type into")
    if "XDOTOOL_FAIL" in log:
        m.append("a keystroke command failed locally (xdotool)")
    if "FOCUS_FAIL" in log:
        m.append("window focus failed")
    return m


def _not_landed_reason(values, keystroke, log_content):
    """A named reason the keystroke did not land, distinguishing - as far as the
    evidence allows - a session that never logged in from a keystroke that was typed
    but not recorded."""
    if values is None:
        base = "readback failed: could not read RunMRU over WinRM to confirm the keystroke"
    else:
        fresh = [v for v in values if v not in PRESEED_VALUES]
        if not fresh:
            base = ("no desktop: the RDP session never logged in - RunMRU still holds "
                    "only the pre-seed, explorer.exe wrote nothing")
        else:
            base = ("typed but not recorded: RunMRU changed but no value matches the "
                    "keystroke")
    markers = _bash_markers(log_content or "")
    return base + ("; " + ", ".join(markers) if markers else "")


@register("rdp_keystroke")
def rdp_keystroke(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    cfg = ctx.cfg
    p = usecase.get("params", {})
    keystroke = p.get("keystroke") or p.get("command") or "cmd.exe"
    start = now_iso()
    # The keystroke is typed into the Win+R Run dialog, so it has to be something a
    # Run dialog can take: one line, under the box's 259-character cap. A payload
    # written for a shell executor (multi-line PowerShell, embedded quotes) used to
    # be interpolated into the generated bash below and die as a bash syntax error,
    # which surfaced as a bare ABORT with no reason attached - three nights running
    # (2026-07-29, 2026-08-16, 2026-09-04) before anyone read the log. Fail here,
    # named, before any RDP state is changed on the box.
    bad = _keystroke_problem(keystroke)
    if bad:
        return make_result(usecase, f"BAD_KEYSTROKE: {bad}", False,
                           attack_start=start, attack_end=now_iso())
    missing = [t for t in RDP_TOOLS if subprocess.run(["which", t], capture_output=True).returncode != 0]
    if missing:
        return make_result(usecase, f"MISSING_TOOLS: {','.join(missing)}", False,
                           attack_start=start, attack_end=now_iso())
    try:
        # Enable RDP and open the port. NLA is left at the box's own setting: the
        # keystroke path needs a real interactive logon, and forcing UserAuthentication=0
        # + SecurityLayer=0 + /sec:rdp (as this did through 2026-09-10) is exactly what
        # gave us six nights of MISSED - FreeRDP 3 does not auto-logon over legacy RDP
        # security, so smss spawned winlogon but userinit/explorer never ran and there
        # was no desktop to type into (measured 2026-09-10: winlogon at 04:05:42, no
        # userinit, no explorer, no whoami). See Part B note on the connect line below.
        session.run_ps(
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            '-Name "fDenyTSConnections" -Value 0 -Type DWord -Force; '
            'Set-Service -Name TermService -StartupType Automatic; '
            'Restart-Service TermService -Force -EA SilentlyContinue; '
            'netsh advfirewall firewall add rule name="P2A-RDP-Test" dir=in action=allow protocol=tcp localport=3389 enable=yes 2>$null'
        )
        time.sleep(2)
        session.run_ps(
            '$p = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"; '
            'Remove-Item -Path $p -Recurse -Force -EA SilentlyContinue; '
            'New-Item -Path $p -Force | Out-Null; '
            'Set-ItemProperty -Path $p -Name "a" -Value "notepad.exe\\1" -Type String -Force; '
            'Set-ItemProperty -Path $p -Name "b" -Value "calc.exe\\1" -Type String -Force; '
            'Set-ItemProperty -Path $p -Name "MRUList" -Value "a" -Type String -Force; '
            'Stop-Process -Name explorer -Force -EA SilentlyContinue; '
            'Start-Sleep -Seconds 3'
        )
        time.sleep(3)
        # Everything below is interpolated into a bash script, so everything below
        # is shell-quoted. The password lands in the file either way; the file is
        # created 0600 by tempfile and deliberately not chmod'd wider.
        q = shlex.quote
        # Part B (hypothesis, 2026-09-10 measurement behind it): negotiate NLA instead
        # of forcing it off. Drop /sec:rdp, and pass the local-account domain explicitly
        # - FreeRDP sends an empty domain otherwise, which NLA rejects for a local
        # Administrator. "." is the local-machine marker; override with cfg["win_domain"]
        # if the box needs its NetBIOS name. If this hypothesis is wrong the readback in
        # Part A turns it into a named KEYSTROKE_NOT_LANDED, not a silent MISSED.
        win_domain = cfg.get("win_domain") or "."
        # Part C (measured 2026-10-19, finding behind two use-cases stuck on
        # KEYSTROKE_NOT_LANDED for 6 and 4 nights): Part B's default NLA negotiation
        # tries Kerberos before NTLM even for a local account, and winpr has no KDC
        # for a realm named "." - "Cannot find KDC for realm \".\"" fires on every
        # connection. Reproduced live: with Kerberos left in the package list the
        # FreeRDP log never reaches a "Logon Info V2" line at all (auth never
        # completes, so the window xdotool types into has no desktop behind it, and
        # "COMPLETE" is typed into nothing - the same KEYSTROKE_NOT_LANDED/"no
        # desktop" seen on 2026-09-17, 09-21, 10-03 and 10-08). Restricting the SSPI
        # package list to NTLM only (/auth-pkg-list:!kerberos) removes the futile
        # attempt: the same measurement shows a completed "Logon Info V2
        # [INFECTED\Administrator]" within ~2s and the typed command lands in
        # RunMRU. Two live detonations confirmed this (2026-10-19).
        # The password is not in this script and not on any command line (2026-10-24): `ps` shows a
        # command line to every local user, and /p:<password> was both here and on xfreerdp3's own.
        # It rides in this process's environment as RDP_PASS (see the subprocess.run below) and
        # reaches xfreerdp3 on stdin through /from-stdin:force. Measured on the lab 2026-10-24:
        # without `:force` xfreerdp3 3.32 reads nothing from a pipe, connects without a password
        # and the NLA logon fails silently (KEYSTROKE_NOT_LANDED, "the RDP session never logged
        # in"); with `:force` the prompt runs before the connection and takes the piped line.
        script = f"""#!/bin/bash
exec > /tmp/rdp_keystroke_sim.log 2>&1
cleanup() {{ pkill -f xfreerdp 2>/dev/null || true; pkill -f openbox 2>/dev/null || true; pkill -f "Xvfb :99" 2>/dev/null || true; }}
trap cleanup EXIT
cleanup; sleep 1
Xvfb :99 -screen 0 1024x768x24 -ac &
sleep 2
export DISPLAY=:99
openbox &
sleep 1
echo "Connecting RDP..."
printf '%s\\n' "$RDP_PASS" | xfreerdp3 /v:{q(cfg['win_host'])} /u:{q(cfg['win_user'])} /d:{q(win_domain)} /from-stdin:force /auth-pkg-list:!kerberos /cert:ignore /size:800x600 /log-level:ERROR &
RDPPID=$!
sleep 8
if ! kill -0 $RDPPID 2>/dev/null; then echo "FAIL: RDP disconnected"; exit 1; fi
WID=$(xdotool search --pid $RDPPID 2>/dev/null | head -1)
if [ -z "$WID" ]; then echo "NO_WINDOW: no xfreerdp window for pid $RDPPID"; kill $RDPPID 2>/dev/null; exit 2; fi
if xdotool windowfocus "$WID"; then echo "FOCUS_OK"; else echo "FOCUS_FAIL: xdotool windowfocus $WID"; fi
xdotool windowactivate "$WID" 2>/dev/null; sleep 1
echo "Win+R..."
if ! xdotool key super+r; then echo "XDOTOOL_FAIL: super+r"; kill $RDPPID 2>/dev/null; exit 3; fi
sleep 2
echo "Typing keystroke..."
if ! xdotool type --delay 80 -- {q(keystroke)}; then echo "XDOTOOL_FAIL: type"; kill $RDPPID 2>/dev/null; exit 3; fi
sleep 1
echo "Enter..."
if ! xdotool key Return; then echo "XDOTOOL_FAIL: Return"; kill $RDPPID 2>/dev/null; exit 3; fi
sleep 3
echo "COMPLETE"
kill $RDPPID 2>/dev/null; sleep 2
"""
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix="_rdp_keystroke.sh", delete=False)
        tmp.write(script)
        tmp.close()
        script_path = tmp.name
        try:
            subprocess.run(["bash", script_path], capture_output=True, timeout=50,
                           env={**os.environ, "RDP_PASS": cfg["win_pass"]})
        finally:
            os.unlink(script_path)
        end = now_iso()
        log_content = ""
        try:
            with open("/tmp/rdp_keystroke_sim.log") as f:
                log_content = f.read()
        except Exception:
            pass
        # Part A: prove the keystroke landed before tearing RDP down. The generated
        # bash echoes COMPLETE whether or not a keystroke reached anything, so COMPLETE
        # is not evidence. A readback of the Administrator RunMRU hive is: if the RDP
        # session logged in and the Run dialog took the command, explorer.exe records
        # it there (same hive the pre-seed wrote, same account this WinRM session runs
        # as). Read it while the box is still in the attack state, before teardown.
        values = _runmru_values(session)
        # Teardown: close RDP back off, remove the firewall rule, and log off the
        # session this detonation just created.
        #
        # Part D (measured 2026-10-19, same investigation as the auth-pkg-list fix
        # above): `kill $RDPPID` only ends the LOCAL xfreerdp3 client - it never asks
        # the server to log the session off, so every detonation (successful or not)
        # left a disconnected session behind ("query user" showed Administrator /
        # Disc after this run). Reproduced live: replaying the SAME use-case against
        # one of those leftover sessions got ERRINFO_LOGOFF_BY_USER and "FAIL: RDP
        # disconnected" within ~1.3s of connecting - a second, independent way to
        # reach KEYSTROKE_NOT_LANDED/"no desktop" on the NEXT night this use-case is
        # selected, since disconnected sessions are never logged off by anything
        # else either. `query user`'s columns shift when SESSIONNAME is blank (the
        # disconnected case), so the id is read as "the number right before Disc",
        # not a fixed column.
        session.run_ps(
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            '-Name "fDenyTSConnections" -Value 1 -Type DWord -Force; '
            'netsh advfirewall firewall delete rule name="P2A-RDP-Test" 2>$null; '
            '$qu = query user 2>$null; foreach ($ln in $qu) { '
            'if ($ln -match "\\s(\\d+)\\s+Disc\\b") { logoff $Matches[1] 2>$null } }'
        )
        if _keystroke_landed(values or [], keystroke):
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                               op_id="rdp-keystroke",
                               output=_redact(f"RDP Win+R typed via explorer.exe, confirmed in RunMRU: {keystroke}", cfg))
        # No new RunMRU value for the keystroke: the detonation did not happen, however
        # cleanly the bash log reads. Fail named so this reads as a broken test, not a
        # detection gap. The log tail is the generated script's stderr and bash echoes a
        # failing line verbatim - which is how the RDP password would reach the results
        # file - so redact it before it is stored, unconditionally.
        reason = _not_landed_reason(values, keystroke, log_content)
        return make_result(usecase, f"KEYSTROKE_NOT_LANDED: {reason}", False,
                           attack_start=start, attack_end=end,
                           output=_redact(log_content, cfg)[-500:])
    except subprocess.TimeoutExpired:
        return make_result(usecase, "TIMEOUT", False, attack_start=start, attack_end=now_iso())
    except Exception as e:
        return make_result(usecase, f"ERROR: {_redact(str(e), cfg)}", False, attack_start=start, attack_end=now_iso())
