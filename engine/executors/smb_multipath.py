"""Cleanup-proven SMB multipath note validation.

The operation writes the same harmless text filename to three token-owned paths
over SMB.  That produces the pid 4 file events used by the ransomware-note
aggregation without encrypting, renaming, or touching any pre-existing file.
"""
import io
import hashlib
import os
import re
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone

from executors.registry import register
from result import make_result


OPERATIONS = {"multipath_note", "remote_execute"}
NIGHTLY_SAFE_OPERATIONS = set(OPERATIONS)
ATTACK_MARKER = "ZYBUR_SMB_MULTIPATH_ATTACK_EXECUTED"
CLEANUP_MARKER = "ZYBUR_SMB_MULTIPATH_CLEANUP_OK"
PROBE_MARKER = "ZYBUR_SMB_MULTIPATH_PROBE_CLEAN"
_TOKEN = re.compile(r"^[0-9a-f]{8}$")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def _paths(token):
    filename = f"README-Zybur-{token}.txt"
    roots = [rf"C:\ZyburNote-{token}-{i}" for i in range(1, 4)]
    return filename, roots


def build_scripts(token):
    if not _TOKEN.fullmatch(str(token or "")):
        raise ValueError("SMB multipath token must be exactly eight lowercase hex characters")
    filename, roots = _paths(token)
    owner = f"Zybur SMB note validation:{token}"
    quoted = ",".join(f"'{root}'" for root in roots)
    common = f"""$ErrorActionPreference = 'Stop'
$roots = @({quoted})
$filename = '{filename}'
$owner = '{owner}'
function Remove-OwnedRoots {{
  foreach ($root in $roots) {{
    if (Test-Path -LiteralPath $root) {{
      $note = Join-Path $root $filename
      if (-not (Test-Path -LiteralPath $note)) {{ throw 'refusing to remove an SMB note directory without its owner file' }}
      $actual = Get-Content -LiteralPath $note -Raw -ErrorAction Stop
      if ($actual -ne $owner) {{ throw 'refusing to remove an SMB note directory with different content' }}
      Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }}
  }}
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedRoots
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
$roots = @({quoted})
$found = @($roots | Where-Object {{ Test-Path -LiteralPath $_ }})
if ($found.Count -gt 0) {{ Write-Output 'ZYBUR_SMB_MULTIPATH_RESIDUAL:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return filename, roots, owner, cleanup, probe


def _build_noop_pe(owner):
    """Compile a marker-only Windows PE locally; return its bytes."""
    source = f'''#include <string.h>
static const char zybur_owner[] = "{owner}";
int main(void) {{ return strncmp(zybur_owner, "Zybur", 5) == 0 ? 0 : 1; }}
'''
    with tempfile.TemporaryDirectory(prefix="zybur-smb-exec-") as root:
        src = os.path.join(root, "marker.c")
        binary = os.path.join(root, "marker.exe")
        with open(src, "w", encoding="utf-8") as handle:
            handle.write(source)
        result = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-Os", "-s", "-o", binary, src],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not os.path.exists(binary):
            raise RuntimeError("MinGW failed to compile the SMB execution marker")
        with open(binary, "rb") as handle:
            return handle.read()


def build_remote_execute_scripts(token, sha256):
    if not _TOKEN.fullmatch(str(token or "")):
        raise ValueError("SMB multipath token must be exactly eight lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{64}", str(sha256 or "")):
        raise ValueError("SMB execution payload hash must be lowercase SHA-256")
    path = rf"C:\Windows\Temp\ZyburRemoteExec-{token}.exe"
    common = f"""$ErrorActionPreference = 'Stop'
$path = '{path}'
$expected = '{sha256}'
function Remove-OwnedPayload {{
  if (Test-Path -LiteralPath $path) {{
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {{ throw 'refusing to remove an SMB payload with a different hash' }}
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
if (-not (Test-Path -LiteralPath $path)) {{ throw 'SMB execution payload was not uploaded' }}
$actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($actual -ne $expected) {{ throw 'SMB execution payload hash mismatch' }}
& $path
if ($LASTEXITCODE -ne 0) {{ throw ('SMB execution marker exited ' + $LASTEXITCODE) }}
Write-Output '{ATTACK_MARKER}'
""".strip()
    cleanup = f"""{common}
Remove-OwnedPayload
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '{path}') {{ Write-Output 'ZYBUR_SMB_MULTIPATH_RESIDUAL:remote-execute:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return path, attack, cleanup, probe


def _connect(cfg, smb_cls=None):
    if smb_cls is None:
        from impacket.smbconnection import SMBConnection as smb_cls
    remote_name = cfg.get("dc_fqdn") or cfg["win_host"]
    smb = smb_cls(remote_name, cfg["win_host"], sess_port=445)
    smb.login(cfg["win_user"], cfg["win_pass"], cfg.get("dc_domain") or "")
    return smb


def run_smb_multipath(cfg, operation, session_factory, token=None, smb_factory=_connect):
    if cfg.get("target") != "domain_controller":
        raise ValueError("SMB multipath executor requires target: domain_controller")
    if operation not in OPERATIONS:
        raise ValueError(f"unknown SMB multipath operation {operation!r}")
    token = token or secrets.token_hex(4)
    if operation == "remote_execute":
        return run_smb_remote_execute(
            cfg, session_factory, token=token, smb_factory=smb_factory)
    filename, roots, owner, cleanup_ps, probe_ps = build_scripts(token)

    attack_error = None
    smb = None
    try:
        # A collision is removed only when its content proves ownership. A random
        # unowned collision fails closed in this first fresh session.
        response = session_factory().run_ps(cleanup_ps)
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in _text(response, "std_out"):
            raise RuntimeError(_text(response, "std_err") or "pre-cleanup was not proven")
        smb = smb_factory(cfg)
        payload = owner.encode("utf-8")
        for root in roots:
            remote_root = root[3:]
            remote_file = remote_root + "\\" + filename
            smb.createDirectory("C$", remote_root)
            stream = io.BytesIO(payload)
            smb.putFile("C$", remote_file, stream.read)
    except Exception as exc:
        attack_error = f"SMB multipath write failed: {type(exc).__name__}: {exc}"
    finally:
        if smb is not None:
            try:
                smb.logoff()
            except Exception:
                pass

    errors = []
    try:
        response = session_factory().run_ps(cleanup_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
            errors.append(f"SMB note cleanup was not proven: {stderr or 'no cleanup marker'}")
    except Exception as exc:
        errors.append(f"SMB note cleanup failed: {type(exc).__name__}: {exc}")
    try:
        response = session_factory().run_ps(probe_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or stdout.strip() != PROBE_MARKER:
            errors.append(f"SMB note cleanup probe found residual state: {stderr or stdout or 'empty response'}")
    except Exception as exc:
        errors.append(f"SMB note cleanup probe failed: {type(exc).__name__}: {exc}")
    if errors:
        raise RuntimeError("; ".join(errors))
    if attack_error:
        raise RuntimeError(attack_error)
    return "three same-name SMB notes created in distinct owned paths; cleanup independently proven"


def run_smb_remote_execute(cfg, session_factory, token=None, smb_factory=_connect,
                           payload_builder=_build_noop_pe):
    if cfg.get("target") != "domain_controller":
        raise ValueError("SMB execution executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    if not _TOKEN.fullmatch(str(token or "")):
        raise ValueError("SMB multipath token must be exactly eight lowercase hex characters")
    owner = f"Zybur SMB execution validation:{token}"
    payload = payload_builder(owner)
    if not payload.startswith(b"MZ"):
        raise RuntimeError("SMB execution marker is not a Windows PE")
    digest = hashlib.sha256(payload).hexdigest()
    path, attack_ps, cleanup_ps, probe_ps = build_remote_execute_scripts(token, digest)

    attack_error = None
    smb = None
    try:
        response = session_factory().run_ps(cleanup_ps)
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in _text(response, "std_out"):
            raise RuntimeError(_text(response, "std_err") or "SMB execution pre-cleanup was not proven")
        smb = smb_factory(cfg)
        smb.putFile("C$", path[3:], io.BytesIO(payload).read)
        response = session_factory().run_ps(attack_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or ATTACK_MARKER not in stdout:
            attack_error = f"SMB execution failed: {stderr or 'no execution marker'}"
    except Exception as exc:
        attack_error = f"SMB remote execution failed: {type(exc).__name__}: {exc}"
    finally:
        if smb is not None:
            try:
                smb.logoff()
            except Exception:
                pass

    errors = []
    try:
        response = session_factory().run_ps(cleanup_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
            errors.append(f"SMB execution cleanup was not proven: {stderr or 'no cleanup marker'}")
    except Exception as exc:
        errors.append(f"SMB execution cleanup failed: {type(exc).__name__}: {exc}")
    try:
        response = session_factory().run_ps(probe_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or stdout.strip() != PROBE_MARKER:
            errors.append(f"SMB execution cleanup probe found residual state: {stderr or stdout or 'empty response'}")
    except Exception as exc:
        errors.append(f"SMB execution cleanup probe failed: {type(exc).__name__}: {exc}")
    if errors:
        raise RuntimeError("; ".join(errors))
    if attack_error:
        raise RuntimeError(attack_error)
    return "marker-only PE uploaded over SMB, executed once, and independently removed"


@register("smb_multipath")
def smb_multipath(usecase, ctx):
    start = _now()
    try:
        summary = run_smb_multipath(
            ctx.cfg or {}, (usecase.get("params") or {}).get("operation"),
            ctx.winrm_factory,
        )
        return make_result(
            usecase, "SUCCESS", True, attack_start=start, attack_end=_now(), output=summary,
        )
    except Exception as exc:
        msg = str(exc)
        password = str((ctx.cfg or {}).get("win_pass") or "")
        if password:
            msg = msg.replace(password, "[REDACTED]")
        return make_result(
            usecase, f"ERROR: {type(exc).__name__}: {msg}", False,
            attack_start=start, attack_end=_now(),
        )
