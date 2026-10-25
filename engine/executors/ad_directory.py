"""Closed-set reversible directory operations for DC detection validation.

This executor never accepts a command from YAML. Every operation owns randomly
named disposable state (or one exact marker on a protected object), cleans in a
PowerShell finally block, retries cleanup in a fresh WinRM session, and proves
the expected clean state from a third session before reporting success.
"""
import base64
import hashlib
import re
import secrets
from datetime import datetime, timezone

from executors.registry import register
from result import make_result


ATTACK_MARKER = "ZYBUR_AD_DIRECTORY_ATTACK_EXECUTED"
CLEANUP_MARKER = "ZYBUR_AD_DIRECTORY_CLEANUP_OK"
PROBE_MARKER = "ZYBUR_AD_DIRECTORY_PROBE_CLEAN"
_TOKEN = re.compile(r"^[0-9a-f]{8}$")

OPERATIONS = {
    "user_delegation_krbtgt",
    "privileged_group_member_added",
    "shadow_credential_added",
    "mspki_credentials_added",
    "sensitive_attribute_read",
    "bulk_attribute_read",
    "writedac_access",
    "replication_rights_added",
    "gpo_group_privilege",
    "gpo_scheduled_task",
    "gpo_startup_script",
    "system_group_member_added",
    "adminsdholder_reference_added",
    "dsheuristics_exclusion_added",
    "local_kerberos_service_created",
    "delegation_privilege_assigned",
    "remote_password_reset",
    "secondary_logon",
    "advapi_newcredentials",
}

# These operations touch only disabled/unlinked disposable objects. Excluded
# operations remain attended even after cleanup proof because they
# briefly touch a real protected/configuration object.
NIGHTLY_SAFE_OPERATIONS = {
    "user_delegation_krbtgt",
    "privileged_group_member_added",
    "shadow_credential_added",
    "mspki_credentials_added",
    "sensitive_attribute_read",
    "bulk_attribute_read",
    "writedac_access",
    "replication_rights_added",
    "gpo_group_privilege",
    "gpo_scheduled_task",
    "gpo_startup_script",
    "system_group_member_added",
    "local_kerberos_service_created",
    "remote_password_reset",
    "secondary_logon",
    "advapi_newcredentials",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _response_text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def _user_helpers(name, owner):
    return f"""
function Get-OwnedUser {{
  $candidate = Get-ADUser -LDAPFilter '(cn={name})' -Properties Description -ErrorAction Stop
  if ($null -ne $candidate -and $candidate.Description -ne '{owner}') {{
    throw 'refusing to touch a pre-existing AD user with the validation name'
  }}
  return $candidate
}}
function Remove-OwnedUser {{
  $candidate = Get-OwnedUser
  if ($null -ne $candidate) {{
    Remove-ADUser -Identity $candidate -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()


def _add_write_audit():
    return """
$aclPath = 'AD:' + $u.DistinguishedName
$acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop
$world = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$audit = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
  $world, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
  [System.Security.AccessControl.AuditFlags]::Success)
$acl.AddAuditRule($audit)
Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
""".strip()


def _user_action(operation):
    if operation == "user_delegation_krbtgt":
        return """
$dnsRoot = (Get-ADDomain -ErrorAction Stop).DNSRoot
Set-ADUser -Identity $u -Add @{'msDS-AllowedToDelegateTo'=('krbtgt/' + $dnsRoot)} -ErrorAction Stop
""".strip()
    if operation == "shadow_credential_added":
        return f"""
{_add_write_audit()}
$hex = '00020000' + ('0' * 820)
$value = 'B:828:' + $hex + ':' + $u.DistinguishedName
Set-ADObject -Identity $u -Add @{{'msDS-KeyCredentialLink'=$value}} -ErrorAction Stop
""".strip()
    if operation == "mspki_credentials_added":
        return f"""
{_add_write_audit()}
$value = 'B:8:00000000:' + $u.DistinguishedName
Set-ADObject -Identity $u -Add @{{'msPKIAccountCredentials'=$value}} -ErrorAction Stop
""".strip()
    if operation == "sensitive_attribute_read":
        return """
$schema = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
$attr = Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=msPKIAccountCredentials)' -Properties schemaIDGUID -ErrorAction Stop
$guid = [guid]$attr.schemaIDGUID
$aclPath = 'AD:' + $u.DistinguishedName
$acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop
$world = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$audit = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
  $world, [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
  [System.Security.AccessControl.AuditFlags]::Success, $guid)
$acl.AddAuditRule($audit)
Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
$value = 'B:8:00000000:' + $u.DistinguishedName
Set-ADObject -Identity $u -Add @{'msPKIAccountCredentials'=$value} -ErrorAction Stop
$null = Get-ADUser -Identity $u -Properties msPKIAccountCredentials -ErrorAction Stop
""".strip()
    if operation == "bulk_attribute_read":
        return """
$aclPath = 'AD:' + $u.DistinguishedName
$acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop
$world = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$audit = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
  $world, [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
  [System.Security.AccessControl.AuditFlags]::Success)
$acl.AddAuditRule($audit)
Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
$null = Get-ADUser -Identity $u -Properties * -ErrorAction Stop
""".strip()
    if operation == "writedac_access":
        return """
$aclPath = 'AD:' + $u.DistinguishedName
$acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop
$world = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$audit = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
  $world, [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
  [System.Security.AccessControl.AuditFlags]::Success)
$acl.AddAuditRule($audit)
Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
$changed = Get-Acl -Path $aclPath -ErrorAction Stop
$allow = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $world, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
  [System.Security.AccessControl.AccessControlType]::Allow)
$changed.AddAccessRule($allow)
Set-Acl -Path $aclPath -AclObject $changed -ErrorAction Stop
""".strip()
    raise ValueError(f"operation {operation!r} is not a disposable-user operation")


def _user_scripts(operation, token):
    prefixes = {
        "user_delegation_krbtgt": "del",
        "shadow_credential_added": "key",
        "mspki_credentials_added": "pki",
        "sensitive_attribute_read": "sar",
        "bulk_attribute_read": "bar",
        "writedac_access": "dac",
    }
    name = f"zv-{prefixes[operation]}-{token}"
    owner = f"Zybur AD validation:{operation}:{token}"
    helpers = _user_helpers(name, owner)
    action = _user_action(operation)
    attack = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
{helpers}
Remove-OwnedUser
$u = New-ADUser -Name '{name}' -SamAccountName '{name}' -Description '{owner}' -Enabled $false -PassThru -ErrorAction Stop
try {{
  {action}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedUser
}}
""".strip()
    cleanup = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
{helpers}
Remove-OwnedUser
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$candidate = Get-ADUser -LDAPFilter '(cn={name})' -ErrorAction Stop
if ($null -ne $candidate) {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:user:{name}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _privileged_group_scripts(token):
    """Use the rule's Admin* name branch without touching a real privileged group."""
    uname = f"zv-grp-{token}"
    gname = f"AdminZV{token}"
    owner = f"Zybur AD validation:privileged_group_member_added:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$owner = '{owner}'
function Remove-OwnedState {{
  $group = Get-ADGroup -LDAPFilter '(cn={gname})' -Properties Description -ErrorAction Stop
  if ($null -ne $group) {{
    if ($group.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation group' }}
    Remove-ADGroup -Identity $group -Confirm:$false -ErrorAction Stop
  }}
  $user = Get-ADUser -LDAPFilter '(cn={uname})' -Properties Description -ErrorAction Stop
  if ($null -ne $user) {{
    if ($user.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
    Remove-ADUser -Identity $user -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedState
$u = New-ADUser -Name '{uname}' -SamAccountName '{uname}' -Description $owner -Enabled $false -PassThru -ErrorAction Stop
$g = New-ADGroup -Name '{gname}' -SamAccountName '{gname}' -GroupCategory Security -GroupScope Global -Description $owner -PassThru -ErrorAction Stop
try {{
  Add-ADGroupMember -Identity $g -Members $u -ErrorAction Stop
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedState
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedState
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$group = Get-ADGroup -LDAPFilter '(cn={gname})' -ErrorAction Stop
$user = Get-ADUser -LDAPFilter '(cn={uname})' -ErrorAction Stop
if ($null -ne $group -or $null -ne $user) {{
  Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:privileged-group:{token}'
}} else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _gpo_scripts(operation, token):
    values = {
        "gpo_group_privilege": "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
        "gpo_scheduled_task": "[{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}{AADCED64-746C-4633-A97C-D61349046527}]",
        "gpo_startup_script": "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]",
    }
    name = f"zv-gpo-{token}"
    owner = f"Zybur AD validation:{operation}:{token}"
    guid = f"{{00000000-0000-0000-0000-{token}0000}}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -ErrorAction Stop
$path = 'CN=Policies,CN=System,' + $domain.DistinguishedName
$displayName = '{name}'
$owner = '{owner}'
$guid = '{guid}'
function Get-OwnedGpo {{
  $candidate = Get-ADObject -SearchBase $path -LDAPFilter '(displayName={name})' -Properties description -ErrorAction Stop
  if ($null -ne $candidate -and $candidate.description -ne $owner) {{
    throw 'refusing to touch a pre-existing GPO object with the validation name'
  }}
  return $candidate
}}
function Remove-OwnedGpo {{
  $candidate = Get-OwnedGpo
  if ($null -ne $candidate) {{ Remove-ADObject -Identity $candidate -Recursive -Confirm:$false -ErrorAction Stop }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedGpo
$gpo = New-ADObject -Type groupPolicyContainer -Name $guid -Path $path -OtherAttributes @{{
  displayName=$displayName; description=$owner; flags=0; versionNumber=0;
  gPCFileSysPath=('\\\\' + $domain.DNSRoot + '\\SYSVOL\\' + $domain.DNSRoot + '\\Policies\\' + $guid)
}} -PassThru -ErrorAction Stop
try {{
  $aclPath = 'AD:' + $gpo.DistinguishedName
  $acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop
  $world = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $audit = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
    $world, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AuditFlags]::Success)
  $acl.AddAuditRule($audit)
  Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
  Set-ADObject -Identity $gpo -Replace @{{gPCMachineExtensionNames='{values[operation]}'}} -ErrorAction Stop
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedGpo
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedGpo
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""{common}
if ($null -ne (Get-OwnedGpo)) {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:gpo:{name}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _system_group_scripts(token):
    uname = f"zv-sys-{token}"
    gname = f"ZVGRP{token}"
    task = f"ZyburAdValidation-{token}"
    owner = f"Zybur AD validation:system_group_member_added:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$uname = '{uname}'
$gname = '{gname}'
$task = '{task}'
$owner = '{owner}'
function Remove-OwnedState {{
  $scheduled = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
  if ($null -ne $scheduled) {{ Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop }}
  $group = Get-ADGroup -LDAPFilter '(cn={gname})' -Properties Description -ErrorAction Stop
  if ($null -ne $group) {{
    if ($group.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation group' }}
    Remove-ADGroup -Identity $group -Confirm:$false -ErrorAction Stop
  }}
  $user = Get-ADUser -LDAPFilter '(cn={uname})' -Properties Description -ErrorAction Stop
  if ($null -ne $user) {{
    if ($user.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
    Remove-ADUser -Identity $user -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedState
$u = New-ADUser -Name $uname -SamAccountName $uname -Description $owner -Enabled $false -PassThru -ErrorAction Stop
$g = New-ADGroup -Name $gname -SamAccountName $gname -GroupCategory Security -GroupScope Global -Description $owner -PassThru -ErrorAction Stop
try {{
  $payload = "Import-Module ActiveDirectory; Add-ADGroupMember -Identity '$gname' -Members '$uname' -ErrorAction Stop"
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand ' + $encoded)
  Register-ScheduledTask -TaskName $task -Action $action -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
  Start-ScheduledTask -TaskName $task -ErrorAction Stop
  $added = $false
  for ($i = 0; $i -lt 30; $i++) {{
    if (Get-ADGroupMember -Identity $gname -ErrorAction Stop | Where-Object SamAccountName -eq $uname) {{ $added = $true; break }}
    Start-Sleep -Seconds 1
  }}
  if (-not $added) {{ throw 'SYSTEM task did not add the disposable member' }}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedState
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedState
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$task = Get-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue
$group = Get-ADGroup -LDAPFilter '(cn={gname})' -ErrorAction Stop
$user = Get-ADUser -LDAPFilter '(cn={uname})' -ErrorAction Stop
if ($null -ne $task -or $null -ne $group -or $null -ne $user) {{
  Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:system-group:{token}'
}} else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _replication_scripts(token):
    uname = f"zv-rep-{token}"
    ouname = f"ZVREP{token}"
    owner = f"Zybur AD validation:replication_rights_added:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -ErrorAction Stop
$owner = '{owner}'
function Remove-OwnedState {{
  $ou = Get-ADOrganizationalUnit -LDAPFilter '(ou={ouname})' -Properties Description -ErrorAction Stop
  if ($null -ne $ou) {{
    if ($ou.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation OU' }}
    Set-ADOrganizationalUnit -Identity $ou -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
    Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false -ErrorAction Stop
  }}
  $user = Get-ADUser -LDAPFilter '(cn={uname})' -Properties Description -ErrorAction Stop
  if ($null -ne $user) {{
    if ($user.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
    Remove-ADUser -Identity $user -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedState
$u = New-ADUser -Name '{uname}' -SamAccountName '{uname}' -Description $owner -Enabled $false -PassThru -ErrorAction Stop
$ou = New-ADOrganizationalUnit -Name '{ouname}' -Description $owner -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Stop
try {{
  $path = 'AD:' + $ou.DistinguishedName
  $acl = Get-Acl -Path $path -Audit -ErrorAction Stop
  $world = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $audit = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
    $world, [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.Security.AccessControl.AuditFlags]::Success)
  $acl.AddAuditRule($audit)
  Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
  $changed = Get-Acl -Path $path -ErrorAction Stop
  foreach ($right in @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
    '89e95b76-444d-4c62-991a-0facbeda640c')) {{
    $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
      $u.SID, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
      [System.Security.AccessControl.AccessControlType]::Allow, [guid]$right)
    $changed.AddAccessRule($ace)
  }}
  Set-Acl -Path $path -AclObject $changed -ErrorAction Stop
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedState
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedState
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$ou = Get-ADOrganizationalUnit -LDAPFilter '(ou={ouname})' -ErrorAction Stop
$user = Get-ADUser -LDAPFilter '(cn={uname})' -ErrorAction Stop
if ($null -ne $ou -or $null -ne $user) {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:replication:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _adminsdholder_scripts(token):
    uname = f"zv-ash-{token}"
    owner = f"Zybur AD validation:adminsdholder_reference_added:{token}"
    marker = f"Zybur AD validation AdminSDHolder marker {token}"
    base = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -ErrorAction Stop
$targetDn = 'CN=AdminSDHolder,CN=System,' + $domain.DistinguishedName
$owner = '{owner}'
$schema = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
$description = Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=description)' -Properties schemaIDGUID -ErrorAction Stop
$propertyGuid = [guid]$description.schemaIDGUID
$subjectSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
function Audit-Rule {{
  return [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
    $subjectSid, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AuditFlags]::Success, $propertyGuid)
}}
function Remove-OwnedState {{
  $u = Get-ADUser -LDAPFilter '(cn={uname})' -Properties Description -ErrorAction Stop
  if ($null -ne $u) {{
    if ($u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
    $target = Get-ADObject -Identity $targetDn -Properties description -ErrorAction Stop
    if (@($target.description) -contains '{marker}') {{
      Set-ADObject -Identity $target -Remove @{{description='{marker}'}} -ErrorAction Stop
    }}
    $aclPath = 'AD:' + $targetDn
    $acl = Get-Acl -Path $aclPath -Audit -ErrorAction Stop
    $acl.RemoveAuditRuleSpecific((Audit-Rule))
    Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
    Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{base}
Remove-OwnedState
$u = New-ADUser -Name '{uname}' -SamAccountName '{uname}' -Description $owner -Enabled $false -PassThru -ErrorAction Stop
try {{
  $path = 'AD:' + $targetDn
  $acl = Get-Acl -Path $path -Audit -ErrorAction Stop
  $equivalent = @($acl.Audit | Where-Object {{
    $_.IdentityReference -eq $subjectSid -and $_.ObjectType -eq $propertyGuid -and
    ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
  }})
  if ($equivalent.Count -gt 0) {{ throw 'the exact AdminSDHolder audit ACE already exists' }}
  $acl.AddAuditRule((Audit-Rule))
  Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
  Set-ADObject -Identity $targetDn -Add @{{description='{marker}'}} -ErrorAction Stop
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedState
}}
""".strip()
    cleanup = f"""{base}
Remove-OwnedState
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""{base}
$path = 'AD:' + $targetDn
$target = Get-ADObject -Identity $targetDn -Properties description -ErrorAction Stop
$acl = Get-Acl -Path $path -Audit -ErrorAction Stop
$audit = @($acl.Audit | Where-Object {{ $_.IdentityReference -eq $subjectSid -and $_.ObjectType -eq $propertyGuid }})
$u = Get-ADUser -LDAPFilter '(cn={uname})' -ErrorAction Stop
if ((@($target.description) -contains '{marker}') -or $audit.Count -gt 0 -or $null -ne $u) {{
  Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:adminsdholder:{token}'
}} else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _dsheuristics_scripts(token):
    # Character 10 is the mandatory positional sentinel "1" for any value of
    # length >=10; character 16 is the SDProp exclusion nibble the rule detects.
    marker = "0000000001000001"
    uname = f"zv-dsh-{token}"
    owner = f"Zybur AD validation:dsheuristics_exclusion_added:{token}"
    base = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$root = Get-ADRootDSE -ErrorAction Stop
$targetDn = 'CN=Directory Service,CN=Windows NT,CN=Services,' + $root.configurationNamingContext
$marker = '{marker}'
$owner = '{owner}'
$schema = $root.schemaNamingContext
$attr = Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=dSHeuristics)' -Properties schemaIDGUID -ErrorAction Stop
$propertyGuid = [guid]$attr.schemaIDGUID
$subjectSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
function Audit-Rule {{
  return [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
    $subjectSid, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AuditFlags]::Success, $propertyGuid)
}}
function Remove-OwnedState {{
  $u = Get-ADUser -LDAPFilter '(cn={uname})' -Properties Description -ErrorAction Stop
  if ($null -ne $u) {{
    if ($u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
    $target = Get-ADObject -Identity $targetDn -Properties dSHeuristics -ErrorAction Stop
    if ($target.dSHeuristics -eq $marker) {{
      Set-ADObject -Identity $target -Clear dSHeuristics -ErrorAction Stop
    }}
    $path = 'AD:' + $targetDn
    $acl = Get-Acl -Path $path -Audit -ErrorAction Stop
    $acl.RemoveAuditRuleSpecific((Audit-Rule))
    Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
    Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{base}
$before = Get-ADObject -Identity $targetDn -Properties dSHeuristics -ErrorAction Stop
if ($null -ne $before.dSHeuristics) {{ throw 'dSHeuristics is already configured; refusing to overwrite it' }}
$path = 'AD:' + $targetDn
$beforeAcl = Get-Acl -Path $path -Audit -ErrorAction Stop
$equivalent = @($beforeAcl.Audit | Where-Object {{
  $_.IdentityReference -eq $subjectSid -and $_.ObjectType -eq $propertyGuid -and
  ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
}})
if ($equivalent.Count -gt 0) {{ throw 'the exact dSHeuristics audit ACE already exists' }}
$u = New-ADUser -Name '{uname}' -SamAccountName '{uname}' -Description $owner -Enabled $false -PassThru -ErrorAction Stop
try {{
  $acl = Get-Acl -Path $path -Audit -ErrorAction Stop
  $acl.AddAuditRule((Audit-Rule))
  Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
  Set-ADObject -Identity $targetDn -Add @{{dSHeuristics=$marker}} -ErrorAction Stop
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedState
}}
""".strip()
    cleanup = f"""{base}
Remove-OwnedState
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""{base}
$target = Get-ADObject -Identity $targetDn -Properties dSHeuristics -ErrorAction Stop
$path = 'AD:' + $targetDn
$acl = Get-Acl -Path $path -Audit -ErrorAction Stop
$audit = @($acl.Audit | Where-Object {{ $_.IdentityReference -eq $subjectSid -and $_.ObjectType -eq $propertyGuid }})
$u = Get-ADUser -LDAPFilter '(cn={uname})' -ErrorAction Stop
if ($null -ne $target.dSHeuristics -or $audit.Count -gt 0 -or $null -ne $u) {{
  Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:dsheuristics:{token}'
}} else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _local_service_scripts(token):
    service = f"ZVSvc{token}"
    binary = r"C:\Windows\System32\cmd.exe /c exit 0"
    common = f"""$ErrorActionPreference = 'Stop'
$service = '{service}'
$binary = '{binary}'
function Remove-OwnedService {{
  $candidate = Get-CimInstance Win32_Service -Filter ("Name='" + $service + "'") -ErrorAction Stop
  if ($null -ne $candidate) {{
    if ($candidate.PathName -ne $binary) {{ throw 'refusing to touch a pre-existing service with the validation name' }}
    & sc.exe delete $service | Out-Null
    for ($i = 0; $i -lt 20; $i++) {{
      if ($null -eq (Get-CimInstance Win32_Service -Filter ("Name='" + $service + "'") -ErrorAction Stop)) {{ break }}
      Start-Sleep -Milliseconds 250
    }}
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedService
$fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
$secret = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{ZYBUR_DC_PASS_B64}}}}'))
$secure = ConvertTo-SecureString $secret -AsPlainText -Force
$credential = [Management.Automation.PSCredential]::new('{{{{ZYBUR_DC_LOGON}}}}', $secure)
$nested = $null
try {{
  $nested = New-PSSession -ComputerName $fqdn -Authentication Kerberos -Credential $credential -ErrorAction Stop
  $output = Invoke-Command -Session $nested -ArgumentList $service,$binary -ErrorAction Stop -ScriptBlock {{
    param($serviceName,$binaryPath)
    & sc.exe create $serviceName binPath= $binaryPath start= demand 2>&1
    if ($LASTEXITCODE -ne 0) {{ throw ('service create failed: ' + ($input -join ' ')) }}
  }}
  if ($null -eq (Get-CimInstance Win32_Service -Filter ("Name='" + $service + "'") -ErrorAction Stop)) {{
    throw 'service creation was not observable'
  }}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  if ($null -ne $nested) {{ Remove-PSSession -Session $nested -ErrorAction SilentlyContinue }}
  $secret = $null
  Remove-OwnedService
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedService
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
$candidate = Get-CimInstance Win32_Service -Filter "Name='{service}'" -ErrorAction Stop
if ($null -ne $candidate) {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:service:{service}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _lsa_rights_source():
    return r"""using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class ZyburLsaRights {
  [StructLayout(LayoutKind.Sequential)]
  private struct LSA_OBJECT_ATTRIBUTES {
    public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
    public uint Attributes; public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct LSA_UNICODE_STRING {
    public ushort Length; public ushort MaximumLength; public IntPtr Buffer;
  }
  [DllImport("advapi32.dll")]
  private static extern uint LsaOpenPolicy(IntPtr systemName,
    ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr handle);
  [DllImport("advapi32.dll")]
  private static extern uint LsaAddAccountRights(IntPtr handle, IntPtr sid,
    LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")]
  private static extern uint LsaRemoveAccountRights(IntPtr handle, IntPtr sid,
    [MarshalAs(UnmanagedType.U1)] bool all, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")]
  private static extern uint LsaEnumerateAccountRights(IntPtr handle, IntPtr sid,
    out IntPtr rights, out uint count);
  [DllImport("advapi32.dll")]
  private static extern uint LsaClose(IntPtr handle);
  [DllImport("advapi32.dll")]
  private static extern uint LsaFreeMemory(IntPtr buffer);
  [DllImport("advapi32.dll")]
  private static extern uint LsaNtStatusToWinError(uint status);

  private static void Check(uint status) {
    if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
  }
  private static IntPtr Open() {
    var oa = new LSA_OBJECT_ATTRIBUTES(); IntPtr handle;
    Check(LsaOpenPolicy(IntPtr.Zero, ref oa, 0x810, out handle)); return handle;
  }
  private static IntPtr Sid(string text, out GCHandle pin) {
    var sid = new SecurityIdentifier(text); var bytes = new byte[sid.BinaryLength];
    sid.GetBinaryForm(bytes, 0); pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
    return pin.AddrOfPinnedObject();
  }
  private static LSA_UNICODE_STRING[] Right(string value, out IntPtr buffer) {
    buffer = Marshal.StringToHGlobalUni(value);
    return new[] { new LSA_UNICODE_STRING {
      Buffer=buffer, Length=(ushort)(value.Length*2),
      MaximumLength=(ushort)((value.Length+1)*2) } };
  }
  public static void Add(string sidText, string right) {
    IntPtr policy=IntPtr.Zero, buffer=IntPtr.Zero; GCHandle pin=default(GCHandle);
    try { policy=Open(); var sid=Sid(sidText,out pin); var r=Right(right,out buffer);
      Check(LsaAddAccountRights(policy,sid,r,1)); }
    finally { if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
      if(pin.IsAllocated) pin.Free(); if(policy!=IntPtr.Zero) LsaClose(policy); }
  }
  public static void Remove(string sidText, string right) {
    IntPtr policy=IntPtr.Zero, buffer=IntPtr.Zero; GCHandle pin=default(GCHandle);
    try { policy=Open(); var sid=Sid(sidText,out pin); var r=Right(right,out buffer);
      uint status=LsaRemoveAccountRights(policy,sid,false,r,1);
      if(status!=0 && status!=0xC0000034u) Check(status); }
    finally { if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
      if(pin.IsAllocated) pin.Free(); if(policy!=IntPtr.Zero) LsaClose(policy); }
  }
  public static bool Has(string sidText, string wanted) {
    IntPtr policy=IntPtr.Zero, values=IntPtr.Zero; GCHandle pin=default(GCHandle);
    try { policy=Open(); var sid=Sid(sidText,out pin); uint count;
      uint status=LsaEnumerateAccountRights(policy,sid,out values,out count);
      if(status==0xC0000034u) return false; Check(status);
      int size=Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
      for(int i=0;i<count;i++) { var p=IntPtr.Add(values,i*size);
        var u=(LSA_UNICODE_STRING)Marshal.PtrToStructure(p,typeof(LSA_UNICODE_STRING));
        string value=Marshal.PtrToStringUni(u.Buffer,u.Length/2);
        if(String.Equals(value,wanted,StringComparison.OrdinalIgnoreCase)) return true; }
      return false;
    } finally { if(values!=IntPtr.Zero) LsaFreeMemory(values);
      if(pin.IsAllocated) pin.Free(); if(policy!=IntPtr.Zero) LsaClose(policy); }
  }
}"""


def _lsa_source_path(token):
    return rf"C:\Windows\Temp\ZyburLsaRights-{token}.cs"


def _lsa_loader(token):
    path = _lsa_source_path(token)
    return f"""if (-not ('ZyburLsaRights' -as [type])) {{
  Add-Type -Path '{path}' -ErrorAction Stop
}}"""


def _delegation_privilege_scripts(token):
    name = f"zv-lsa-{token}"
    owner = f"Zybur AD validation:delegation_privilege_assigned:{token}"
    source_path = _lsa_source_path(token)
    loader = _lsa_loader(token)
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$right = 'SeEnableDelegationPrivilege'
$owner = '{owner}'
function Get-OwnedUser {{
  $u = Get-ADUser -LDAPFilter '(cn={name})' -Properties Description -ErrorAction Stop
  if ($null -ne $u -and $u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
  return $u
}}
""".strip()
    attack = f"""{common}
if ($null -ne (Get-OwnedUser)) {{ throw 'delegation-right validation user unexpectedly already exists' }}
$u = New-ADUser -Name '{name}' -SamAccountName '{name}' -Description $owner -Enabled $false -PassThru -ErrorAction Stop
try {{
  {loader}
  [ZyburLsaRights]::Add($u.SID.Value, $right)
  if (-not [ZyburLsaRights]::Has($u.SID.Value, $right)) {{ throw 'account-right assignment was not observable' }}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  if ('ZyburLsaRights' -as [type]) {{
    [ZyburLsaRights]::Remove($u.SID.Value, $right)
    if ([ZyburLsaRights]::Has($u.SID.Value, $right)) {{ throw 'account-right removal was not proven' }}
  }}
  Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop
}}
""".strip()
    cleanup = f"""{common}
$u = Get-OwnedUser
try {{
  if ($null -ne $u) {{
    {loader}
    [ZyburLsaRights]::Remove($u.SID.Value, $right)
    if ([ZyburLsaRights]::Has($u.SID.Value, $right)) {{ throw 'account-right removal was not proven' }}
    Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop
  }}
}} finally {{
  Remove-Item -LiteralPath '{source_path}' -Force -ErrorAction SilentlyContinue
}}
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$u = Get-ADUser -LDAPFilter '(cn={name})' -ErrorAction Stop
if ($null -ne $u -or (Test-Path -LiteralPath '{source_path}')) {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:lsa-state:{name}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _password_reset_scripts(token):
    name = f"zv-Admin-{token}"
    owner = f"Zybur AD validation:remote_password_reset:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$name = '{name}'
$owner = '{owner}'
function Get-OwnedUser {{
  $u = Get-ADUser -LDAPFilter '(cn={name})' -Properties Description -ErrorAction Stop
  if ($null -ne $u -and $u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing validation user' }}
  return $u
}}
function Remove-OwnedUser {{
  $u = Get-OwnedUser
  if ($null -ne $u) {{ Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedUser
$initial = ConvertTo-SecureString 'Zybur!Initial-{token}-9aA' -AsPlainText -Force
$updated = ConvertTo-SecureString 'Zybur!Updated-{token}-9aA' -AsPlainText -Force
$u = New-ADUser -Name $name -SamAccountName $name -Description $owner -Enabled $false -AccountPassword $initial -PassThru -ErrorAction Stop
try {{
  Set-ADAccountPassword -Identity $u -Reset -NewPassword $updated -ErrorAction Stop
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedUser
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedUser
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$u = Get-ADUser -LDAPFilter '(cn={name})' -ErrorAction Stop
if ($null -ne $u) {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:password-reset:{name}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _secondary_logon_source():
    return r'''using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class ZyburSecondaryLogon {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  struct STARTUPINFO {
    public int cb; public string reserved; public string desktop; public string title;
    public int x; public int y; public int xSize; public int ySize;
    public int xChars; public int yChars; public int fill; public int flags;
    public short show; public short reserved2; public IntPtr reservedPtr;
    public IntPtr stdIn; public IntPtr stdOut; public IntPtr stdErr;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct PROCESS_INFORMATION {
    public IntPtr process; public IntPtr thread; public uint processId; public uint threadId;
  }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CreateProcessWithLogonW(string user, string domain, string password,
    int logonFlags, string application, StringBuilder commandLine, int creationFlags,
    IntPtr environment, string currentDirectory, ref STARTUPINFO startup,
    out PROCESS_INFORMATION information);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr handle, uint exitCode);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool LogonUser(string user, string domain, string password,
    int logonType, int logonProvider, out IntPtr token);
  public static int Run(string domain, string user, string password, string marker) {
    var startup=new STARTUPINFO(); startup.cb=Marshal.SizeOf(startup);
    var command=new StringBuilder("cmd.exe /d /c \"echo "+marker+" >nul\"");
    PROCESS_INFORMATION info;
    if(!CreateProcessWithLogonW(user,domain,password,2,
      @"C:\Windows\System32\cmd.exe",command,0x08000000,IntPtr.Zero,
      @"C:\Windows\System32",ref startup,out info)) throw new Win32Exception();
    try {
      uint waited=WaitForSingleObject(info.process,10000);
      if(waited==258) { TerminateProcess(info.process,1); throw new TimeoutException("secondary-logon child did not exit"); }
      return (int)info.processId;
    } finally { CloseHandle(info.thread); CloseHandle(info.process); }
  }
  public static void LogonOnly(string domain, string user, string password) {
    IntPtr token;
    if(!LogonUser(user,domain,password,9,3,out token)) throw new Win32Exception();
    CloseHandle(token);
  }
}'''


def _secondary_source_path(token):
    return rf"C:\Windows\Temp\ZyburSecondaryLogon-{token}.cs"


def _secondary_logon_scripts(token):
    marker = f"ZYBUR_SECLOGON_{token}"
    source_path = _secondary_source_path(token)
    common = f"""$ErrorActionPreference = 'Stop'
$marker = '{marker}'
function Stop-OwnedProcess {{
  $owned = @(Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction Stop | Where-Object {{ $_.CommandLine -like ('*' + $marker + '*') }})
  foreach ($p in $owned) {{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }}
}}
""".strip()
    attack = f"""{common}
Stop-OwnedProcess
Add-Type -Path '{source_path}' -ErrorAction Stop
$domain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{ZYBUR_DC_DOMAIN_B64}}}}'))
$user = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{ZYBUR_DC_USER_B64}}}}'))
$password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{ZYBUR_DC_PASS_B64}}}}'))
$child = [ZyburSecondaryLogon]::Run($domain, $user, $password, $marker)
$password = $null
if ($null -ne (Get-Process -Id $child -ErrorAction SilentlyContinue)) {{ throw 'secondary-logon child remains running' }}
Write-Output '{ATTACK_MARKER}'
""".strip()
    cleanup = f"""{common}
Stop-OwnedProcess
Remove-Item -LiteralPath '{source_path}' -Force -ErrorAction SilentlyContinue
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
$owned = @(Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction Stop | Where-Object {{ $_.CommandLine -like '*{marker}*' }})
if ($owned.Count -gt 0 -or (Test-Path -LiteralPath '{source_path}')) {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:secondary-logon:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _advapi_newcredentials_scripts(token):
    source_path = _secondary_source_path(token)
    attack = f"""$ErrorActionPreference = 'Stop'
Add-Type -Path '{source_path}' -ErrorAction Stop
$domain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{ZYBUR_DC_DOMAIN_B64}}}}'))
$user = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{ZYBUR_DC_USER_B64}}}}'))
$password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{{{ZYBUR_DC_PASS_B64}}}}'))
[ZyburSecondaryLogon]::LogonOnly($domain, $user, $password)
$password = $null
Write-Output '{ATTACK_MARKER}'
""".strip()
    cleanup = f"""$ErrorActionPreference = 'Stop'
Remove-Item -LiteralPath '{source_path}' -Force -ErrorAction SilentlyContinue
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '{source_path}') {{ Write-Output 'ZYBUR_AD_DIRECTORY_RESIDUAL:advapi-newcredentials:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def build_scripts(operation, token):
    if operation not in OPERATIONS:
        raise ValueError(f"unknown managed AD operation {operation!r}")
    if not _TOKEN.fullmatch(str(token or "")):
        raise ValueError("AD validation token must be exactly eight lowercase hex characters")
    if operation in {
        "user_delegation_krbtgt",
        "shadow_credential_added", "mspki_credentials_added",
        "sensitive_attribute_read", "bulk_attribute_read", "writedac_access",
    }:
        return _user_scripts(operation, token)
    if operation == "privileged_group_member_added":
        return _privileged_group_scripts(token)
    if operation.startswith("gpo_"):
        return _gpo_scripts(operation, token)
    if operation == "system_group_member_added":
        return _system_group_scripts(token)
    if operation == "replication_rights_added":
        return _replication_scripts(token)
    if operation == "adminsdholder_reference_added":
        return _adminsdholder_scripts(token)
    if operation == "dsheuristics_exclusion_added":
        return _dsheuristics_scripts(token)
    if operation == "local_kerberos_service_created":
        return _local_service_scripts(token)
    if operation == "delegation_privilege_assigned":
        return _delegation_privilege_scripts(token)
    if operation == "remote_password_reset":
        return _password_reset_scripts(token)
    if operation == "secondary_logon":
        return _secondary_logon_scripts(token)
    if operation == "advapi_newcredentials":
        return _advapi_newcredentials_scripts(token)
    raise AssertionError(f"no script builder for {operation}")


def _run_ps(session_factory, script):
    return session_factory().run_ps(script)


def _stage_lsa_source(session_factory, token):
    """Stage the fixed C# helper in bounded WinRM commands and verify its hash."""
    raw = _lsa_rights_source().encode("utf-8")
    expected = hashlib.sha256(raw).hexdigest().upper()
    path = _lsa_source_path(token)
    session = session_factory()
    for index in range(0, len(raw), 1800):
        encoded = base64.b64encode(raw[index:index + 1800]).decode("ascii")
        mode = "Create" if index == 0 else "Append"
        script = f"""$ErrorActionPreference='Stop'
$path='{path}'
$bytes=[Convert]::FromBase64String('{encoded}')
$stream=[IO.File]::Open($path,[IO.FileMode]::{mode},[IO.FileAccess]::Write,[IO.FileShare]::None)
try {{ $stream.Write($bytes,0,$bytes.Length) }} finally {{ $stream.Dispose() }}"""
        response = session.run_ps(script)
        if getattr(response, "status_code", 1) != 0:
            raise RuntimeError(
                "LSA helper staging failed: " +
                (_response_text(response, "std_err") or "no error text"))
    response = session.run_ps(
        f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{path}' -ErrorAction Stop).Hash")
    if (getattr(response, "status_code", 1) != 0
            or _response_text(response, "std_out").strip().upper() != expected):
        raise RuntimeError("LSA helper staging hash did not match")


def _stage_secondary_source(session_factory, token):
    """Stage the fixed secondary-logon helper without exceeding WinRM's command limit."""
    raw = _secondary_logon_source().encode("utf-8")
    expected = hashlib.sha256(raw).hexdigest().upper()
    path = _secondary_source_path(token)
    session = session_factory()
    for index in range(0, len(raw), 1800):
        encoded = base64.b64encode(raw[index:index + 1800]).decode("ascii")
        mode = "Create" if index == 0 else "Append"
        script = f"""$ErrorActionPreference='Stop'
$path='{path}'
$bytes=[Convert]::FromBase64String('{encoded}')
$stream=[IO.File]::Open($path,[IO.FileMode]::{mode},[IO.FileAccess]::Write,[IO.FileShare]::None)
try {{ $stream.Write($bytes,0,$bytes.Length) }} finally {{ $stream.Dispose() }}"""
        response = session.run_ps(script)
        if getattr(response, "status_code", 1) != 0:
            raise RuntimeError(
                "secondary-logon helper staging failed: " +
                (_response_text(response, "std_err") or "no error text"))
    response = session.run_ps(
        f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{path}' -ErrorAction Stop).Hash")
    if (getattr(response, "status_code", 1) != 0
            or _response_text(response, "std_out").strip().upper() != expected):
        raise RuntimeError("secondary-logon helper staging hash did not match")


def run_ad_directory(cfg, operation, session_factory, token=None):
    if cfg.get("target") != "domain_controller":
        raise ValueError("managed AD executor requires target: domain_controller")
    token = token or secrets.token_hex(4)
    attack_ps, cleanup_ps, probe_ps = build_scripts(operation, token)
    if operation == "local_kerberos_service_created":
        import base64 as _base64
        logon = f"{cfg.get('dc_domain') or ''}\\{cfg.get('win_user') or ''}"
        password = str(cfg.get("win_pass") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}\\[A-Za-z0-9_.@$-]{1,64}", logon):
            raise ValueError("local Kerberos service operation requires a simple domain logon")
        if not password:
            raise ValueError("local Kerberos service operation requires DC_PASS")
        attack_ps = attack_ps.replace("{{ZYBUR_DC_LOGON}}", logon).replace(
            "{{ZYBUR_DC_PASS_B64}}",
            _base64.b64encode(password.encode("utf-8")).decode("ascii"),
        )
    if operation in {"secondary_logon", "advapi_newcredentials"}:
        import base64 as _base64
        user = str(cfg.get("win_user") or "")
        domain = str(cfg.get("dc_domain") or "")
        password = str(cfg.get("win_pass") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.@$-]{1,64}", user):
            raise ValueError("secondary logon requires a simple DC user name")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", domain):
            raise ValueError("secondary logon requires a simple DC domain name")
        if not password:
            raise ValueError("secondary logon requires DC_PASS")
        replacements = {
            "{{ZYBUR_DC_USER_B64}}": _base64.b64encode(user.encode()).decode("ascii"),
            "{{ZYBUR_DC_DOMAIN_B64}}": _base64.b64encode(domain.encode()).decode("ascii"),
            "{{ZYBUR_DC_PASS_B64}}": _base64.b64encode(password.encode()).decode("ascii"),
        }
        for placeholder, value in replacements.items():
            attack_ps = attack_ps.replace(placeholder, value)

    attack_error = None
    if operation == "delegation_privilege_assigned":
        try:
            _stage_lsa_source(session_factory, token)
        except Exception as exc:
            attack_error = f"AD operation staging failed: {type(exc).__name__}: {exc}"
    elif operation in {"secondary_logon", "advapi_newcredentials"}:
        try:
            _stage_secondary_source(session_factory, token)
        except Exception as exc:
            attack_error = f"AD operation staging failed: {type(exc).__name__}: {exc}"
    if attack_error is None:
        try:
            response = _run_ps(session_factory, attack_ps)
            stdout = _response_text(response, "std_out")
            stderr = _response_text(response, "std_err")
            if getattr(response, "status_code", 1) != 0:
                attack_error = f"AD operation exited {response.status_code}: {stderr or 'no error text'}"
            elif ATTACK_MARKER not in stdout:
                attack_error = "AD operation returned no execution marker"
        except Exception as exc:
            attack_error = f"AD operation transport failed: {type(exc).__name__}: {exc}"

    cleanup_error = None
    try:
        response = _run_ps(session_factory, cleanup_ps)
        stdout = _response_text(response, "std_out")
        stderr = _response_text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
            cleanup_error = f"cleanup command was not proven: {stderr or 'no cleanup marker'}"
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
    return f"{operation} completed; cleanup independently proven"


@register("ad_directory")
def ad_directory(usecase, ctx):
    start = _now()
    try:
        summary = run_ad_directory(
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
