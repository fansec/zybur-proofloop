"""Reversible Active Directory mutations for unattended detection validation.

Only the operations in ``OPERATIONS`` can run.  Each one creates a disabled,
uniquely named temporary object (or a uniquely named documentation-address DNS
record), performs one bounded change, and removes it in a PowerShell ``finally``.
The executor then retries that exact cleanup through a fresh WinRM session and
uses another fresh session to prove the object is absent before it reports
SUCCESS.  A command string from YAML is deliberately never accepted here.
"""
import re
import secrets
from datetime import datetime, timezone

from executors.registry import register
from result import make_result


ATTACK_MARKER = "ZYBUR_AD_ATTACK_EXECUTED"
CLEANUP_MARKER = "ZYBUR_AD_CLEANUP_OK"
PROBE_MARKER = "ZYBUR_AD_PROBE_CLEAN"
_TOKEN = re.compile(r"^[0-9a-f]{8}$")

# Public so lint/tests can bind the registry values to the executor's closed set.
OPERATIONS = {
    "password_never_expires",
    "preauth_disabled",
    "user_spn_added",
    "computer_dns_mismatch",
    "computer_sam_without_dollar",
    "dns_record_created",
    "dns_wpad_created",
    "dns_wildcard_created",
    "dns_spn_coercion_created",
    "dns_zone_export",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _response_text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def _object_spec(operation, token):
    if operation == "password_never_expires":
        return "user", f"zv-ne-{token}", (
            "Set-ADUser -Identity $obj -PasswordNeverExpires $true -ErrorAction Stop"
        )
    if operation == "preauth_disabled":
        return "user", f"zv-pa-{token}", (
            "Set-ADAccountControl -Identity $obj -DoesNotRequirePreAuth $true -ErrorAction Stop"
        )
    if operation == "user_spn_added":
        return "user", f"zv-spn-{token}", (
            "$aclPath = 'AD:' + $obj.DistinguishedName\n"
            "$acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop\n"
            "$sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')\n"
            "$auditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(\n"
            "  $sid, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,\n"
            "  [System.Security.AccessControl.AuditFlags]::Success)\n"
            "$acl.AddAuditRule($auditRule)\n"
            "Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop\n"
            "$dnsRoot = (Get-ADDomain -ErrorAction Stop).DNSRoot\n"
            "$spn = 'http/' + $name + '.' + $dnsRoot\n"
            "Set-ADUser -Identity $obj -Add @{servicePrincipalName=$spn} -ErrorAction Stop"
        )
    if operation == "computer_dns_mismatch":
        return "computer", f"ZVDNS{token}", (
            "$dnsRoot = (Get-ADDomain -ErrorAction Stop).DNSRoot\n"
            "$mismatch = 'unrelated-' + $token + '.' + $dnsRoot\n"
            "Set-ADComputer -Identity $obj -DNSHostName $mismatch -ErrorAction Stop"
        )
    if operation == "computer_sam_without_dollar":
        return "computer", f"ZVSAM{token}", (
            "$newSam = 'ZVUSR' + $token\n"
            "Set-ADObject -Identity $obj.DistinguishedName "
            "-Replace @{sAMAccountName=$newSam} -ErrorAction Stop"
        )
    raise ValueError(f"operation {operation!r} is not an AD object operation")


def _object_helpers(kind, name, owner):
    noun = "User" if kind == "user" else "Computer"
    return f"""
function Remove-OwnedObject {{
  $candidate = Get-AD{noun} -LDAPFilter '(cn={name})' -Properties Description -ErrorAction Stop
  if ($null -ne $candidate) {{
    if ($candidate.Description -ne '{owner}') {{
      throw 'refusing to touch a pre-existing AD object with the validation name'
    }}
    Remove-AD{noun} -Identity $candidate -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()


def _object_attack_ps(operation, token):
    kind, name, action = _object_spec(operation, token)
    owner = f"Zybur nightly detection validation:{operation}:{token}"
    create = (
        f"$obj = New-ADUser -Name $name -SamAccountName $name -Description $owner "
        "-Enabled $false -PassThru -ErrorAction Stop"
        if kind == "user" else
        "$obj = New-ADComputer -Name $name -SamAccountName ($name + '$') "
        "-Description $owner -Enabled $false -PassThru -ErrorAction Stop"
    )
    helpers = _object_helpers(kind, name, owner)
    return f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$name = '{name}'
$token = '{token}'
$owner = '{owner}'
{helpers}
Remove-OwnedObject
{create}
try {{
  {action}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedObject
}}
""".strip()


def _object_cleanup_ps(operation, token):
    kind, name, _ = _object_spec(operation, token)
    owner = f"Zybur nightly detection validation:{operation}:{token}"
    helpers = _object_helpers(kind, name, owner)
    return f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
{helpers}
Remove-OwnedObject
Write-Output '{CLEANUP_MARKER}'
""".strip()


def _object_probe_ps(operation, token):
    kind, name, _ = _object_spec(operation, token)
    noun = "User" if kind == "user" else "Computer"
    return f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$candidate = Get-AD{noun} -LDAPFilter '(cn={name})' -ErrorAction Stop
if ($null -ne $candidate) {{
  Write-Output 'ZYBUR_AD_RESIDUAL:{kind}:{name}'
}} else {{
  Write-Output '{PROBE_MARKER}'
}}
""".strip()


def _dns_scripts(operation, token):
    # A reserved .test zone keeps the record non-routable. DNS Server returns
    # WIN32 123 for the earlier hyphenated .invalid spelling on Server 2022.
    zone = f"zv{token}.test"
    record_names = {
        "dns_record_created": "probe",
        "dns_wpad_created": "wpad",
        "dns_wildcard_created": "*",
        # The rule only requires UWhRC, then BAAAA, inside a MicrosoftDNS DN.
        # Keep the label short and syntactically ordinary; this is an isolated
        # reserved .test zone and never resolves outside the lab.
        "dns_spn_coercion_created": f"UWhRCzv{token}BAAAA",
    }
    record_name = record_names[operation]
    owner = f"Zybur DNS record validation:{operation}:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module DnsServer -ErrorAction Stop
$zone = '{zone}'
$owner = '{owner}'
function Assert-OwnedZone {{
  $records = @(Get-DnsServerResourceRecord -ZoneName $zone -Name '_zybur_owner' -RRType TXT -ErrorAction Stop)
  $text = @($records | ForEach-Object {{ $_.RecordData.DescriptiveText }}) -join ''
  if ($text -notlike ('*' + $owner + '*')) {{
    throw 'refusing to remove a DNS zone without its owner marker'
  }}
}}
function Remove-OwnedZone {{
  $zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object {{ $_.ZoneName -eq $zone }})
  if ($zones.Count -gt 0) {{
    Assert-OwnedZone
    Remove-DnsServerZone -Name $zone -Force -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedZone
$createdHere = $false
$ownershipMarked = $false
try {{
  Add-DnsServerPrimaryZone -Name $zone -ReplicationScope Domain -ErrorAction Stop | Out-Null
  $createdHere = $true
  Add-DnsServerResourceRecord -ZoneName $zone -Txt -Name '_zybur_owner' -DescriptiveText $owner -ErrorAction Stop | Out-Null
  Assert-OwnedZone
  $ownershipMarked = $true
  $domain = Get-ADDomain -ErrorAction Stop
  $base = 'CN=MicrosoftDNS,DC=DomainDnsZones,' + $domain.DistinguishedName
  $zoneObject = Get-ADObject -SearchBase $base -LDAPFilter ('(name=' + $zone + ')') -ErrorAction Stop
  if ($null -eq $zoneObject) {{ throw 'temporary AD-integrated DNS zone was not found in AD' }}
  $aclPath = 'AD:' + $zoneObject.DistinguishedName
  $acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop
  $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $auditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
    $sid, [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
    [System.Security.AccessControl.AuditFlags]::Success)
  $acl.AddAuditRule($auditRule)
  Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
  Add-DnsServerResourceRecordA -ZoneName $zone -Name '{record_name}' -IPv4Address '192.0.2.1' -ErrorAction Stop | Out-Null
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  if ($ownershipMarked) {{
    Remove-OwnedZone
  }} elseif ($createdHere) {{
    # The current session proved the name absent and then created this zone.  This
    # narrow fallback handles failure before durable TXT ownership is verified;
    # every later/fresh-session removal still requires that marker.
    $zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object {{ $_.ZoneName -eq $zone }})
    if ($zones.Count -gt 0) {{
      Remove-DnsServerZone -Name $zone -Force -ErrorAction Stop
    }}
  }}
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedZone
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""{common}
$zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object {{ $_.ZoneName -eq $zone }})
if ($zones.Count -gt 0) {{
  Write-Output 'ZYBUR_AD_RESIDUAL:dns-zone:{zone}'
}} else {{
  Write-Output '{PROBE_MARKER}'
}}
""".strip()
    return attack, cleanup, probe


def _dns_export_scripts(token):
    """Have the real DNS service export a disposable zone to a unique .txt file.

    Export-DnsServerZone asks dns.exe to create the file, which is the exact
    process relationship the target rule consumes. The zone carries an owner TXT
    record and the exported file must contain that owner before either is removed.
    """
    zone = f"zvexport{token}.test"
    filename = f"ZyburValidation-{token}.txt"
    path = rf"C:\Windows\System32\dns\{filename}"
    owner = f"Zybur DNS export validation:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module DnsServer -ErrorAction Stop
$zone = '{zone}'
$filename = '{filename}'
$path = '{path}'
$owner = '{owner}'
function Assert-OwnedZone {{
  $records = @(Get-DnsServerResourceRecord -ZoneName $zone -Name '_zybur_owner' -RRType TXT -ErrorAction Stop)
  $text = @($records | ForEach-Object {{ $_.RecordData.DescriptiveText }}) -join ''
  if ($text -notlike ('*' + $owner + '*')) {{ throw 'refusing to remove a DNS zone without its owner marker' }}
}}
function Remove-OwnedArtifacts {{
  $zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object {{ $_.ZoneName -eq $zone }})
  if ($zones.Count -gt 0) {{
    Assert-OwnedZone
    Remove-DnsServerZone -Name $zone -Force -ErrorAction Stop
  }}
  if (Test-Path -LiteralPath $path) {{
    $actual = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if ($actual -notlike ('*' + $owner + '*')) {{ throw 'refusing to remove a DNS export without its owner marker' }}
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedArtifacts
try {{
  Add-DnsServerPrimaryZone -Name $zone -ReplicationScope Domain -ErrorAction Stop | Out-Null
  Add-DnsServerResourceRecord -ZoneName $zone -Txt -Name '_zybur_owner' -DescriptiveText $owner -ErrorAction Stop | Out-Null
  Export-DnsServerZone -Name $zone -FileName $filename -ErrorAction Stop
  if (-not (Test-Path -LiteralPath $path)) {{ throw 'DNS service did not create the zone export' }}
  if ((Get-Content -LiteralPath $path -Raw -ErrorAction Stop) -notlike ('*' + $owner + '*')) {{ throw 'DNS export did not retain the owner marker' }}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedArtifacts
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedArtifacts
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module DnsServer -ErrorAction Stop
$zone = '{zone}'
$path = '{path}'
$zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object {{ $_.ZoneName -eq $zone }})
if ($zones.Count -gt 0 -or (Test-Path -LiteralPath $path)) {{ Write-Output 'ZYBUR_AD_RESIDUAL:dns-export:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def build_scripts(operation, token):
    """Return (attack, cleanup, probe) for one validated closed-set operation."""
    if operation not in OPERATIONS:
        raise ValueError(f"unknown reversible AD operation {operation!r}")
    if not _TOKEN.fullmatch(str(token or "")):
        raise ValueError("AD validation token must be exactly eight lowercase hex characters")
    if operation == "dns_zone_export":
        return _dns_export_scripts(token)
    if operation.startswith("dns_"):
        return _dns_scripts(operation, token)
    return (_object_attack_ps(operation, token),
            _object_cleanup_ps(operation, token),
            _object_probe_ps(operation, token))


def _run_ps(session_factory, script):
    return session_factory().run_ps(script)


def run_ad_reversible(cfg, operation, session_factory, token=None):
    """Run one mutation and return only a non-sensitive summary.

    Cleanup and its proof run regardless of attack transport/exit status.  Any
    cleanup uncertainty wins over the attack result and prevents SUCCESS.
    """
    if cfg.get("target") != "domain_controller":
        raise ValueError("reversible AD executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    attack_ps, cleanup_ps, probe_ps = build_scripts(operation, token)

    attack_error = None
    try:
        response = _run_ps(session_factory, attack_ps)
        stdout = _response_text(response, "std_out")
        stderr = _response_text(response, "std_err")
        if getattr(response, "status_code", 1) != 0:
            attack_error = f"AD mutation exited {response.status_code}: {stderr or 'no error text'}"
        elif ATTACK_MARKER not in stdout:
            attack_error = "AD mutation returned no execution marker"
    except Exception as exc:
        attack_error = f"AD mutation transport failed: {type(exc).__name__}: {exc}"

    cleanup_error = None
    try:
        response = _run_ps(session_factory, cleanup_ps)
        stdout = _response_text(response, "std_out")
        stderr = _response_text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
            cleanup_error = (f"cleanup command was not proven: "
                             f"{stderr or 'no cleanup marker'}")
    except Exception as exc:
        cleanup_error = f"cleanup transport failed: {type(exc).__name__}: {exc}"

    probe_error = None
    try:
        response = _run_ps(session_factory, probe_ps)
        stdout = _response_text(response, "std_out")
        stderr = _response_text(response, "std_err")
        if getattr(response, "status_code", 1) != 0:
            probe_error = f"cleanup probe exited {response.status_code}: {stderr or 'no error text'}"
        elif stdout.strip() != PROBE_MARKER:
            probe_error = f"cleanup probe found residual state: {stdout or 'empty response'}"
    except Exception as exc:
        probe_error = f"cleanup probe failed: {type(exc).__name__}: {exc}"

    if cleanup_error or probe_error:
        raise RuntimeError("; ".join(x for x in (cleanup_error, probe_error) if x))
    if attack_error:
        raise RuntimeError(attack_error)
    return f"{operation} completed on a disposable AD object; cleanup independently proven"


@register("ad_reversible")
def ad_reversible(usecase, ctx):
    start = _now()
    try:
        summary = run_ad_reversible(
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
