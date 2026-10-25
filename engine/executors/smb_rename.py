# rules/engine/executors/smb_rename.py
"""DIRECT_SMB_RENAME: create files then rename them .encrypted via SMB (ransomware)."""
import time
from executors.registry import register
from executors._net import smb_client_from, now_iso
from result import make_result

@register("smb_rename")
def smb_rename(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    source_ip = ctx.dedup.allocate(usecase["id"]) if ctx.dedup else None
    fw = ctx.firewall.open(session, "smb_rename", ctx.cfg, remoteip=source_ip) if (ctx.firewall and session) else []
    cfg = ctx.cfg
    start = now_iso()
    try:
        remote_dir = r"C:\Users\Administrator\Desktop\smb_rename_test"
        doc_names = [f"document{i}.docx" for i in range(1, 8)]
        ps_create = f'New-Item -Path "{remote_dir}" -ItemType Directory -Force | Out-Null; '
        for doc in doc_names:
            ps_create += (
                f'$b = New-Object byte[] 4096; '
                f'(New-Object Random).NextBytes($b); '
                f'[IO.File]::WriteAllBytes("{remote_dir}\\{doc}", $b); '
            )
        ps_create += f'Write-Host "Created {len(doc_names)} files"'
        r = session.run_ps(ps_create)
        out = r.std_out.decode("utf-8", errors="replace").strip()
        if "Created" not in out:
            return make_result(usecase, f"FILE_CREATE_FAIL: {out[:100]}", False,
                               attack_start=start, attack_end=now_iso())
        time.sleep(2)
        smb_remote_dir = r"Users\Administrator\Desktop\smb_rename_test"
        rename_cmds = [f'rename "{smb_remote_dir}\\{doc}" "{smb_remote_dir}\\{doc}.encrypted"' for doc in doc_names]
        rc, stdout, stderr = smb_client_from(cfg, "; ".join(rename_cmds), source_ip=source_ip)
        end = now_iso()
        output = stdout + stderr
        if "NT_STATUS" in output:
            return make_result(usecase, f"SMB_RENAME_FAIL: {output[:150]}", False,
                               attack_start=start, attack_end=end)
        src_tag = f" [src={source_ip}]" if source_ip else ""
        time.sleep(15)
        session.run_ps(f'Remove-Item -Path "{remote_dir}" -Recurse -Force -EA SilentlyContinue')
        return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                           op_id="direct-smb-rename", output=f"{len(doc_names)} files renamed{src_tag}")
    except Exception as e:
        return make_result(usecase, f"ERROR: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall and session:
            ctx.firewall.close(session, fw)
