# rules/engine/executors/winrm_command.py
"""Generic direct-from-attacker WinRM command executor."""
import secrets
from datetime import datetime, timezone
from executors.registry import register
from result import make_result
from config import subst
from cmdline import MAX_RUN_PS_CMDLINE, run_ps_cmdline_len, run_cmd_cmdline_len

def _now():
    return datetime.now(timezone.utc).isoformat()

@register("winrm_command")
def winrm_command(usecase, ctx):
    p = usecase["params"]
    session = ctx.winrm_factory()
    # {{NONCE}}, when a use-case's command asks for it: generated HERE, in Python,
    # before the command string is ever built - never cmd.exe's own %RANDOM%, which
    # is a RUNTIME expansion performed by whichever shell actually parses the text.
    # WinRS wraps every run_cmd in its own outer `cmd.exe /C` (cmdline.py), and that
    # outer process's own command line is the literal text WinRS was handed -
    # %RANDOM% unexpanded - while the INNER cmd.exe it then spawns parses and
    # expands %RANDOM% for real. Two process-creation events, two different
    # values, and the rule's `process.args:zybur-proofloop-canary-*` query matched both
    # (C-S5 chain-proof assessment, 2026-10-19; measured WinRS behaviour in
    # cmdline.py). Templating a value THIS code already generated removes the
    # ambiguity: there is nothing left for any shell to expand differently, so
    # every process-creation event this command causes carries the identical,
    # already-known literal.
    raw_command = p["command"]
    nonce = secrets.token_hex(4) if "{{NONCE}}" in raw_command else None
    subst_cfg = dict(ctx.cfg or {})
    if nonce is not None:
        subst_cfg["nonce"] = nonce
    command = subst(raw_command, subst_cfg)
    start = _now()
    # cmd.exe refuses a command string over 8191 characters and the call still
    # returns, so this would have read as executed while nothing ran (the BITS
    # payload, 2026-10-14). Refuse it here, loudly, before anything is sent.
    length = (run_ps_cmdline_len if p.get("shell") == "psh" else run_cmd_cmdline_len)(command)
    if length > MAX_RUN_PS_CMDLINE:
        return make_result(usecase, f"ERROR: command is {length} characters on the cmd.exe command line, "
                           f"over {MAX_RUN_PS_CMDLINE}; it would never run", False,
                           attack_start=start, attack_end=_now(), nonce=nonce)
    try:
        if p.get("shell") == "psh":
            r = session.run_ps(command)
        else:
            r = session.run_cmd("cmd", ["/c", command])
        end = _now()
        out = (r.std_out or b"").decode("utf-8", "replace").strip()
        if r.status_code != 0 and not out:
            # Failed and printed nothing. That is either a command refused before
            # PowerShell started (2026-10-14: certutil on DC1, Microsoft Defender
            # Antivirus) or one stopped part-way after its attack step had happened
            # (the startup-shortcut case the same night: killed before its first
            # Write-Host, yet DETECTED). Only the verifier can tell them apart, so it
            # stays executed, and the status says what was seen instead of a bare
            # EXECUTED.
            err = (getattr(r, "std_err", b"") or b"").decode("utf-8", "replace").strip()
            first = err.splitlines()[0][:160] if err else "no stderr"
            result = make_result(usecase, f"EXECUTED: exit {r.status_code} with no output ({first})",
                                 True, attack_start=start, attack_end=end, output=err[:2000], nonce=nonce)
        else:
            result = make_result(usecase, "SUCCESS" if r.status_code == 0 else "EXECUTED",
                                 True, attack_start=start, attack_end=end, output=out, nonce=nonce)
    except Exception as e:
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=_now(), nonce=nonce)
    # Best-effort per-run cleanup in the SAME shell as the attack. Never fails the run.
    # subst_cfg, not a bare ctx.cfg: a use-case whose cleanup also carries {{NONCE}}
    # (none does today) must clean up the exact run it attacked, not a fresh one.
    cleanup = subst(usecase.get("cleanup") or "", subst_cfg)
    if cleanup.strip():
        try:
            if p.get("shell") == "psh":
                session.run_ps(cleanup)
            else:
                session.run_cmd("cmd", ["/c", cleanup])
        except Exception:
            pass
    return result
