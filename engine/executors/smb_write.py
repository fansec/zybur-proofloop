# rules/engine/executors/smb_write.py
"""DIRECT_SMB: write a file to the Startup folder via SMB (shows as pid 4 System)."""
import os, tempfile, time, subprocess
from executors.registry import register
from executors._net import smb_client, now_iso
from result import make_result

@register("smb_write")
def smb_write(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    fw = ctx.firewall.open(session, "smb_write", ctx.cfg) if (ctx.firewall and session) else []
    cfg = ctx.cfg
    start = now_iso()
    try:
        r = subprocess.run(
            ["timeout", "5", "bash", "-c", f"echo > /dev/tcp/{cfg['win_host']}/445"],
            capture_output=True, timeout=10,
        )
        if r.returncode == 0:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False)
            tmp.write("@echo off\r\necho LATERAL_MOVEMENT_STARTUP_TEST\r\n")
            tmp.close()
            remote_path = r"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\test_persistence.bat"
            smb_client(cfg, f'put {tmp.name} "{remote_path}"')
            os.unlink(tmp.name)
        else:
            r = session.run_cmd('cmd', ['/c',
                f'echo @echo off > C:\\Windows\\Temp\\test_startup.bat && '
                f'echo echo LATERAL_MOVEMENT_STARTUP_TEST >> C:\\Windows\\Temp\\test_startup.bat && '
                f'copy /Y C:\\Windows\\Temp\\test_startup.bat '
                f'"\\\\localhost\\C$\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test_persistence.bat" && '
                f'del C:\\Windows\\Temp\\test_startup.bat'
            ])
            output = r.std_out.decode("utf-8", errors="replace").strip()
            if r.status_code != 0:
                return make_result(usecase, f"COPY_FAIL: {output[:100]}", False,
                                   attack_start=start, attack_end=now_iso())
        end = now_iso()
        time.sleep(15)
        if session:
            session.run_cmd('cmd', ['/c',
                'del /f "\\\\localhost\\C$\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test_persistence.bat"'
            ])
        return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end, op_id="direct-smb")
    except Exception as e:
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall and session:
            ctx.firewall.close(session, fw)
