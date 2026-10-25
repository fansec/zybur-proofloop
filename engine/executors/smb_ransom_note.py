# rules/engine/executors/smb_ransom_note.py
"""DIRECT_SMB_RANSOM_NOTE: write one ransom-note name NOTE_RUNS times over SMB from a unique source IP.

The target is an EQL `sequence by host.id, file.name with
maxspan=1m [file where ...] with runs=3`: the SAME file.name created three times in
one minute by System (process.pid 4, the SMB server) under C:\\Users\\, by a user
whose SID is S-1-5-21-*. It no longer has an inbound SMB connection stage. The old
payload wrote four different names once each, which can never satisfy it (triage
n=66, 2026-10-14).

So this writes README.txt into NOTE_RUNS fresh sibling folders in one smbclient
call, the way real ransomware drops one note name into every folder it touches.
Each put is a creation of a new file: a second put over the same path would be an
overwrite, and the rule counts only event.action == "creation". The folders carry
a per-run token and the whole tree sits under PARENT, which this executor owns and
removes before and after, and which reconcile.MANIFEST also probes.
"""
import os
import secrets
import tempfile
import time

from executors.registry import register
from executors._net import smb_client_from, now_iso
from result import make_result

NOTE_NAME = "README.txt"
# The rule's `with runs=3`. test_smb_ransom_note reads the exported rule and fails
# if the pack ever asks for more.
NOTE_RUNS = 3
REMOTE_PARENT = r"Users\Administrator\Desktop\ransom_note_test"
PARENT = "C:\\" + REMOTE_PARENT
COUNT_MARKER = "ZYBUR_RANSOM_NOTES:"
CLEANUP_MARKER = "ZYBUR_RANSOM_NOTE_CLEANUP_OK"
PROBE_MARKER = "ZYBUR_RANSOM_NOTE_PROBE_CLEAN"
# Added 2026-10-14: the old cleanup was one best-effort Remove-Item that nothing
# checked. Same discipline as executors/ad_network.py: cleanup in a fresh session,
# absence proven from another, bounded retries, and a residue fails the run.
CLEANUP_ATTEMPTS = 3
CLEANUP_RETRY_DELAY_S = 1.0
CONTENT = ("YOUR FILES HAVE BEEN ENCRYPTED\n"
           "This is a DETECTION TEST - Pay 1 BTC to recover\n"
           "Contact: attacker@evil.com\n") * 12000  # ~360KB per note


def _text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def note_folders(token):
    """The NOTE_RUNS fresh folders, relative to C$."""
    return [rf"{REMOTE_PARENT}\{token}-{i}" for i in range(1, NOTE_RUNS + 1)]


def note_paths(token):
    """The NOTE_RUNS note paths relative to C$, one per fresh folder."""
    return [rf"{folder}\{NOTE_NAME}" for folder in note_folders(token)]


def build_smb_commands(local_path, token):
    """One smbclient -c string: make PARENT, then a folder and one put per note."""
    cmds = [f'mkdir "{REMOTE_PARENT}"']
    for folder, remote in zip(note_folders(token), note_paths(token)):
        cmds.append(f'mkdir "{folder}"')
        cmds.append(f'put {local_path} "{remote}"')
    return "; ".join(cmds)


def build_scripts(token):
    """(count, cleanup, probe) PowerShell for one run."""
    quoted = ",".join(f"'C:\\{p}'" for p in note_paths(token))
    count = f"""$ErrorActionPreference = 'Stop'
$notes = @({quoted})
$found = @($notes | Where-Object {{ Test-Path -LiteralPath $_ -PathType Leaf }})
Write-Output ('{COUNT_MARKER}' + $found.Count)
""".strip()
    cleanup = f"""$ErrorActionPreference = 'Stop'
$p = '{PARENT}'
if (Test-Path -LiteralPath $p) {{ Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop }}
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '{PARENT}') {{ Write-Output 'ZYBUR_RANSOM_NOTE_RESIDUAL:{PARENT}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return count, cleanup, probe


def clean_until_proven(session_factory, cleanup_ps, probe_ps, sleep_fn):
    """Remove PARENT and prove it gone, each in a fresh session. None or the reason."""
    errors = []
    for attempt in range(1, CLEANUP_ATTEMPTS + 1):
        errors = []
        try:
            response = session_factory().run_ps(cleanup_ps)
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
                errors.append(f"note cleanup was not proven: {stderr or 'no cleanup marker'}")
        except Exception as exc:
            errors.append(f"note cleanup failed: {type(exc).__name__}: {exc}")
        try:
            response = session_factory().run_ps(probe_ps)
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            if getattr(response, "status_code", 1) != 0 or stdout.strip() != PROBE_MARKER:
                errors.append(f"note cleanup probe found residual state: {stderr or stdout or 'empty response'}")
        except Exception as exc:
            errors.append(f"note cleanup probe failed: {type(exc).__name__}: {exc}")
        if not errors:
            return None
        if attempt < CLEANUP_ATTEMPTS:
            sleep_fn(CLEANUP_RETRY_DELAY_S)
    return (f"{PARENT} not proven removed after {CLEANUP_ATTEMPTS} attempts: "
            + "; ".join(errors))


@register("smb_ransom_note")
def smb_ransom_note(usecase, ctx, token=None, sleep_fn=None):
    # time.sleep is looked up per call, not bound as a default, so a test that
    # patches time.sleep (test_executors_direct_wiring) never waits for real.
    sleep_fn = sleep_fn or time.sleep
    start = now_iso()
    if not ctx.winrm_factory:
        return make_result(usecase, "ERROR: smb_ransom_note needs WinRM to clear and prove its folder",
                           False, attack_start=start, attack_end=now_iso())
    token = token or secrets.token_hex(4)
    count_ps, cleanup_ps, probe_ps = build_scripts(token)
    session = ctx.winrm_factory()
    source_ip = ctx.dedup.allocate(usecase["id"]) if ctx.dedup else None
    fw = ctx.firewall.open(session, "smb_ransom_note", ctx.cfg, remoteip=source_ip) if ctx.firewall else []
    cfg = ctx.cfg
    try:
        # A folder left by an earlier run would turn this run's creations into
        # overwrites, so clear it first and write nothing unless that is proven.
        reason = clean_until_proven(ctx.winrm_factory, cleanup_ps, probe_ps, sleep_fn)
        if reason:
            return make_result(usecase, f"ERROR: pre-run {reason}", False,
                               attack_start=start, attack_end=now_iso())
        status, end, landed = None, None, 0
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=f"_{NOTE_NAME}", delete=False)
        try:
            tmp.write(CONTENT)
            tmp.close()
            rc, stdout, stderr = smb_client_from(cfg, build_smb_commands(tmp.name, token),
                                                 source_ip=source_ip)
            end = now_iso()
            output = stdout + stderr
            if rc != 0 and "NT_STATUS" in output:
                status = f"SMB_ERROR: {output[:150]}"
            else:
                response = session.run_ps(count_ps)
                text = _text(response, "std_out")
                line = next((x for x in text.splitlines() if x.startswith(COUNT_MARKER)), "")
                landed = int(line[len(COUNT_MARKER):]) if line[len(COUNT_MARKER):].isdigit() else 0
                if landed != NOTE_RUNS:
                    status = (f"ERROR: {landed} of {NOTE_RUNS} {NOTE_NAME} creations landed: "
                              f"{(output or text or 'no output')[:150]}")
                else:
                    # Unchanged from the original payload: 15 s with the notes on
                    # disk before they are removed.
                    sleep_fn(15)
        except Exception as exc:
            status = f"ERROR: {type(exc).__name__}: {exc}"
            end = end or now_iso()
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        # Every path that may have written a note reaches this cleanup.
        reason = clean_until_proven(ctx.winrm_factory, cleanup_ps, probe_ps, sleep_fn)
        if reason:
            return make_result(usecase, f"ERROR: {reason}", False, attack_start=start, attack_end=end)
        if status:
            return make_result(usecase, status, False, attack_start=start, attack_end=end)
        src_tag = f" [src={source_ip}]" if source_ip else ""
        return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                           op_id="direct-smb-ransom",
                           output=(f"{NOTE_RUNS} creations of {NOTE_NAME} in fresh folders under "
                                   f"{PARENT}, ~{len(CONTENT) * NOTE_RUNS // 1024}KB total; "
                                   f"cleanup proven{src_tag}"))
    except Exception as e:
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall:
            ctx.firewall.close(session, fw)
