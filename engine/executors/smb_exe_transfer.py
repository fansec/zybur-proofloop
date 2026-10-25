# rules/engine/executors/smb_exe_transfer.py
"""DIRECT_SMB_EXE: transfer a >1MB .exe via SMB from a unique source IP."""
import os, tempfile, time
from executors.registry import register
from executors._net import smb_client_from, now_iso
from result import make_result

@register("smb_exe_transfer")
def smb_exe_transfer(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    source_ip = ctx.dedup.allocate(usecase["id"]) if ctx.dedup else None
    fw = ctx.firewall.open(session, "smb_exe_transfer", ctx.cfg, remoteip=source_ip) if (ctx.firewall and session) else []
    cfg = ctx.cfg
    start = now_iso()
    try:
        pe_size = 1024 * 1100  # 1.1MB - exceeds the 1MB dedup byte threshold
        tmp = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        tmp.write(b"MZ" + os.urandom(pe_size - 2))
        tmp.close()
        rc, stdout, stderr = smb_client_from(
            cfg, f'put {tmp.name} "Windows\\Temp\\staged_tool_test.exe"', source_ip=source_ip)
        os.unlink(tmp.name)
        end = now_iso()
        output = stdout + stderr
        if rc != 0 and "NT_STATUS" in output:
            return make_result(usecase, f"SMB_ERROR: {output[:150]}", False,
                               attack_start=start, attack_end=end)
        src_tag = f" [src={source_ip}]" if source_ip else ""
        time.sleep(15)
        if session:
            session.run_cmd('cmd', ['/c', 'del /f C:\\Windows\\Temp\\staged_tool_test.exe 2>nul'])
        return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                           op_id="direct-smb-exe", output=f"{pe_size//1024}KB PE file{src_tag}")
    except Exception as e:
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall and session:
            ctx.firewall.close(session, fw)
