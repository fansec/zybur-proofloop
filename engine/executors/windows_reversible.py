"""Closed-set, cleanup-proven Windows behavior validation.

The generic WinRM executor is intentionally permissive and its cleanup is best
effort.  These operations are candidates for the unattended rotation, so they
use randomly owned state, retry cleanup in a fresh WinRM session, and prove
absence from a third session before returning success.
"""
import re
import secrets
from datetime import datetime, timezone

from executors.registry import register
from result import make_result


OPERATIONS = {
    "endpoint_behavior_alert",
    "genai_config_modify",
    "genai_sensitive_file_access",
    "msbuild_script_parent",
    "msbuild_unusual_child",
    "msbuild_vaultcli_load",
    "privileged_group_enumeration",
    "remote_service_install",
    "scheduled_task_update",
    "sedebug_privilege_enable",
    "unsigned_service_execute",
    "wdac_inert_policy_file",
}
NIGHTLY_SAFE_OPERATIONS = set(OPERATIONS)
ATTACK_MARKER = "ZYBUR_WINDOWS_REVERSIBLE_ATTACK_EXECUTED"
CLEANUP_MARKER = "ZYBUR_WINDOWS_REVERSIBLE_CLEANUP_OK"
PROBE_MARKER = "ZYBUR_WINDOWS_REVERSIBLE_PROBE_CLEAN"
TOKEN_RIGHT_AUDIT_GUID = "{0CCE924A-69AE-11D9-BED3-505054503030}"
_TOKEN = re.compile(r"^[0-9a-f]{8}$")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def _owned_root_scripts(operation, token, body, root=None):
    root = root or rf"C:\Windows\Temp\ZyburValidation-{operation}-{token}"
    owner = f"Zybur Windows validation:{operation}:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
$root = '{root}'
$owner = '{owner}'
$ownerFile = Join-Path $root 'owner.txt'
function Remove-OwnedRoot {{
  if (Test-Path -LiteralPath $root) {{
    if (-not (Test-Path -LiteralPath $ownerFile)) {{ throw 'refusing to remove an unowned validation directory' }}
    $actual = Get-Content -LiteralPath $ownerFile -Raw -ErrorAction Stop
    if ($actual -ne $owner) {{ throw 'refusing to remove a validation directory with a different owner' }}
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedRoot
New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null
Set-Content -LiteralPath $ownerFile -Value $owner -NoNewline -ErrorAction Stop
try {{
  {body}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedRoot
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedRoot
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '{root}') {{ Write-Output 'ZYBUR_WINDOWS_REVERSIBLE_RESIDUAL:root:{operation}:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _scheduled_task_scripts(token):
    name = f"ZyburValidationUpdate-{token}"
    owner = f"Zybur Windows validation:scheduled_task_update:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
$name = '{name}'
$owner = '{owner}'
function Remove-OwnedTask {{
  $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
  if ($null -ne $task) {{
    if ($task.Description -ne $owner) {{ throw 'refusing to remove a scheduled task with a different owner' }}
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedTask
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/d /c exit 0'
$trigger = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01T00:00:00')
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Description $owner -User $env:USERNAME -RunLevel Highest -Force -ErrorAction Stop | Out-Null
try {{
  $updated = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/d /c echo ZYBUR_TASK_UPDATE >nul'
  Set-ScheduledTask -TaskName $name -Action $updated -ErrorAction Stop | Out-Null
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedTask
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedTask
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue
if ($null -ne $task) {{ Write-Output 'ZYBUR_WINDOWS_REVERSIBLE_RESIDUAL:task:{name}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _remote_service_scripts(token):
    name = f"ZVSvc{token}"
    binary = r"C:\Windows\System32\cmd.exe /d /c exit 0"
    common = f"""$ErrorActionPreference = 'Stop'
$name = '{name}'
$binary = '{binary}'
function Remove-OwnedService {{
  $service = Get-CimInstance Win32_Service -Filter ("Name='" + $name + "'") -ErrorAction Stop
  if ($null -ne $service) {{
    if ($service.PathName -ne $binary) {{ throw 'refusing to remove a service with a different binary path' }}
    & sc.exe delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) {{ throw 'service deletion failed' }}
    for ($i=0; $i -lt 20; $i++) {{
      if ($null -eq (Get-CimInstance Win32_Service -Filter ("Name='" + $name + "'") -ErrorAction Stop)) {{ break }}
      Start-Sleep -Milliseconds 250
    }}
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedService
& sc.exe create $name binPath= $binary start= demand | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'service creation failed' }}
try {{
  if ($null -eq (Get-CimInstance Win32_Service -Filter ("Name='" + $name + "'") -ErrorAction Stop)) {{ throw 'service creation was not observable' }}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedService
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedService
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
$service = Get-CimInstance Win32_Service -Filter "Name='{name}'" -ErrorAction Stop
if ($null -ne $service) {{ Write-Output 'ZYBUR_WINDOWS_REVERSIBLE_RESIDUAL:service:{name}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _genai_scripts(token):
    body = r"""$configDir = Join-Path $root '.codex'
New-Item -ItemType Directory -Path $configDir -Force -ErrorAction Stop | Out-Null
$config = Join-Path $configDir 'config.toml'
$writer = Join-Path $root 'writer.vbs'
$script = @'
Set files = CreateObject("Scripting.FileSystemObject")
Set output = files.CreateTextFile(WScript.Arguments(0), True)
output.Write "validation = created"
output.Close
WScript.Sleep 500
Set output = files.CreateTextFile(WScript.Arguments(0), True)
output.Write "validation = modified"
output.Close
'@
Set-Content -LiteralPath $writer -Value $script -Encoding ASCII -ErrorAction Stop
& (Join-Path $env:WINDIR 'System32\cscript.exe') //nologo $writer $config
if ($LASTEXITCODE -ne 0) { throw ('cscript writer exited ' + $LASTEXITCODE) }
Start-Sleep -Milliseconds 500"""
    return _owned_root_scripts("genai_config_modify", token, body)


def _genai_sensitive_file_scripts(token):
    """Run a harmless GenAI-named helper against a disposable credential-shaped file.

    DC1's Defend policy is detect-only, so the unsigned helper reaches the file
    operation instead of being killed by the workstation's behavior prevention.
    Endpoint emits ``open/success`` for image loads but does not emit ordinary
    data-file reads under this policy. The helper therefore launches a harmless
    whoami.exe copy named ``credentials.db`` from a token-owned synthetic child of
    the monitored system credential directory. This tests the rule's exact
    process/file/open predicate without enumerating or opening any existing
    browser, DPAPI, or Credential Manager data.
    """
    source = r'''using System;
using System.Diagnostics;
public static class ZyburGenAiReader {
  public static void Main(string[] args) {
    if (args.Length != 1) throw new ArgumentException("one output path required");
    var start = new ProcessStartInfo(args[0]);
    start.UseShellExecute = false; start.CreateNoWindow = true;
    start.RedirectStandardOutput = true;
    using (var child = Process.Start(start)) {
      child.StandardOutput.ReadToEnd(); child.WaitForExit();
      if (child.ExitCode != 0) throw new Exception("dummy child failed");
    }
    Console.WriteLine("ZYBUR_GENAI_FILE_ACCESSED");
  }
}'''
    body = fr"""$source = Join-Path $root 'genai-reader.cs'
$binary = Join-Path $root 'ollama.exe'
$dummy = Join-Path $root 'credentials.db'
Set-Content -LiteralPath $source -Value @'
{source}
'@ -Encoding UTF8 -ErrorAction Stop
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {{ $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }}
& $compiler /nologo /target:exe /out:$binary $source
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $binary)) {{ throw 'GenAI helper compilation failed' }}
Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\whoami.exe') -Destination $dummy -ErrorAction Stop
& $binary $dummy
if ($LASTEXITCODE -ne 0) {{ throw 'GenAI helper did not launch the harmless dummy image' }}
Start-Sleep -Seconds 2"""
    synthetic_store = (
        rf"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft"
        rf"\Credentials\ZyburValidation-{token}"
    )
    return _owned_root_scripts(
        "genai_sensitive_file_access", token, body, root=synthetic_store,
    )


def _msbuild_path_script():
    return r"""$msbuild = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'
if (-not (Test-Path -LiteralPath $msbuild)) {
  $msbuild = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\MSBuild.exe'
}
if (-not (Test-Path -LiteralPath $msbuild)) { throw 'the built-in .NET Framework MSBuild.exe is absent' }"""


def _msbuild_parent_scripts(token):
    body = fr"""{_msbuild_path_script()}
$project = Join-Path $root 'parent.proj'
$xml = @'
<Project ToolsVersion="4.0" DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build"><Message Text="ZYBUR_MSBUILD_PARENT" Importance="high" /></Target>
</Project>
'@
Set-Content -LiteralPath $project -Value $xml -Encoding UTF8 -ErrorAction Stop
& $msbuild $project /nologo /verbosity:quiet
if ($LASTEXITCODE -ne 0) {{ throw ('MSBuild parent validation exited ' + $LASTEXITCODE) }}
Start-Sleep -Milliseconds 500"""
    return _owned_root_scripts("msbuild_script_parent", token, body)


def _msbuild_child_scripts(token):
    body = fr"""{_msbuild_path_script()}
$project = Join-Path $root 'child.proj'
$xml = @'
<Project ToolsVersion="4.0" DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <UsingTask TaskName="ZyburSpawn" TaskFactory="CodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Fragment" Language="cs"><![CDATA[
        var psi = new System.Diagnostics.ProcessStartInfo();
        psi.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        psi.Arguments = "-NoProfile -NonInteractive -Command Write-Output ZYBUR_MSBUILD_CHILD";
        psi.UseShellExecute = false;
        using (var child = System.Diagnostics.Process.Start(psi)) {{ child.WaitForExit(); }}
      ]]></Code>
    </Task>
  </UsingTask>
  <Target Name="Build"><ZyburSpawn /></Target>
</Project>
'@
Set-Content -LiteralPath $project -Value $xml -Encoding UTF8 -ErrorAction Stop
& $msbuild $project /nologo /verbosity:quiet
if ($LASTEXITCODE -ne 0) {{ throw ('MSBuild child validation exited ' + $LASTEXITCODE) }}
Start-Sleep -Milliseconds 500"""
    return _owned_root_scripts("msbuild_unusual_child", token, body)


def _msbuild_vaultcli_scripts(token):
    """Load the built-in Vault client DLL from an owned MSBuild project."""
    project = r'''<Project ToolsVersion="4.0" DefaultTargets="Zybur" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <UsingTask TaskName="ZyburVaultLoad" TaskFactory="CodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs"><![CDATA[
using System;
using System.Runtime.InteropServices;
using Microsoft.Build.Utilities;
public class ZyburVaultLoad : Task {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr LoadLibrary(string name);
  public override bool Execute() { return LoadLibrary("vaultcli.dll") != IntPtr.Zero; }
}
      ]]></Code>
    </Task>
  </UsingTask>
  <Target Name="Zybur"><ZyburVaultLoad /></Target>
</Project>'''
    body = fr"""{_msbuild_path_script()}
$project = Join-Path $root 'vault-load.proj'
Set-Content -LiteralPath $project -Value @'
{project}
'@ -Encoding UTF8 -ErrorAction Stop
& $msbuild $project /t:Zybur /nologo /verbosity:quiet
if ($LASTEXITCODE -ne 0) {{ throw ('MSBuild Vault client validation exited ' + $LASTEXITCODE) }}
Start-Sleep -Seconds 2"""
    return _owned_root_scripts("msbuild_vaultcli_load", token, body)


def _wdac_scripts(token):
    path = rf"C:\Windows\System32\CodeIntegrity\ZyburValidation-{token}.p7b"
    owner = f"Zybur inert WDAC validation:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
$path = '{path}'
$owner = '{owner}'
function Remove-OwnedPolicy {{
  if (Test-Path -LiteralPath $path) {{
    $actual = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if ($actual -ne $owner) {{ throw 'refusing to remove a WDAC-shaped file with different content' }}
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
  }}
}}
""".strip()
    attack = f"""{common}
Remove-OwnedPolicy
try {{
  Set-Content -LiteralPath $path -Value $owner -NoNewline -Encoding ASCII -ErrorAction Stop
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedPolicy
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedPolicy
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '{path}') {{ Write-Output 'ZYBUR_WINDOWS_REVERSIBLE_RESIDUAL:wdac:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _unsigned_service_scripts(token):
    service = f"ZVUnsigned{token}"
    root = rf"C:\Windows\Temp\ZyburValidation-unsigned-service-{token}"
    binary = root + rf"\ZyburUnsigned-{token}.exe"
    ran_file = root + r"\ran.txt"
    owner = f"Zybur unsigned-service validation:{token}"
    source = r'''using System;
using System.IO;
using System.ServiceProcess;
using System.Threading;
public sealed class ZyburUnsignedService : ServiceBase {
  private Timer timer;
  public ZyburUnsignedService() { ServiceName = "__SERVICE__"; }
  protected override void OnStart(string[] args) {
    File.WriteAllText(@"__RUNFILE__", "ZYBUR_UNSIGNED_SERVICE_RAN");
    timer = new Timer(_ => Stop(), null, 2000, Timeout.Infinite);
  }
  protected override void OnStop() { if (timer != null) timer.Dispose(); }
  public static void Main() { ServiceBase.Run(new ZyburUnsignedService()); }
}'''.replace("__SERVICE__", service).replace("__RUNFILE__", ran_file)
    # Keep this below WinRM's encoded-command limit. run_ps UTF-16/base64 encodes
    # the script, so a seemingly modest 3.3 KiB payload exceeds cmd.exe's 8191
    # character ceiling before PowerShell gets to execute it.
    common = f"""$ErrorActionPreference='Stop'
$name='{service}'
$root='{root}'
$binary='{binary}'
$owner='{owner}'
$ownerFile=Join-Path $root 'owner.txt'
function Assert-OwnedRoot {{
  if (!(Test-Path -LiteralPath $ownerFile)) {{ throw 'unsigned-service root is not owned' }}
  if ((Get-Content -LiteralPath $ownerFile -Raw) -ne $owner) {{ throw 'unsigned-service owner mismatch' }}
}}
function Remove-OwnedServiceAndRoot {{
  $svc=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'")
  if ($null -ne $svc) {{
    Assert-OwnedRoot
    if ($svc.PathName -notlike ('*'+$binary+'*')) {{ throw 'refusing to remove a service with a different binary path' }}
    Stop-Service $name -Force -ErrorAction SilentlyContinue
    sc.exe delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) {{ throw 'unsigned service deletion failed' }}
    for ($i=0;$i -lt 40;$i++) {{
      if ($null -eq (Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'"))) {{ break }}
      Start-Sleep -Milliseconds 250
    }}
  }}
  if (Test-Path -LiteralPath $root) {{
    Assert-OwnedRoot
    Remove-Item -LiteralPath $root -Recurse -Force
  }}
}}
""".strip()
    attack = fr"""{common}
Remove-OwnedServiceAndRoot
  New-Item -ItemType Directory -Path $root -Force | Out-Null
Set-Content -LiteralPath $ownerFile -Value $owner -NoNewline
try {{
  $source=Join-Path $root 'service.cs'
  Set-Content -LiteralPath $source -Value @'
{source}
'@ -Encoding UTF8
  $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
  & $compiler /nologo /target:exe /reference:System.ServiceProcess.dll /out:$binary $source
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $binary)) {{ throw 'unsigned service compilation failed' }}
  New-Service -Name $name -BinaryPathName ('"'+$binary+'"') -StartupType Manual | Out-Null
  Start-Service $name
  for ($i=0;$i -lt 40 -and !(Test-Path -LiteralPath '{ran_file}');$i++) {{ Start-Sleep -Milliseconds 250 }}
  if (-not (Test-Path -LiteralPath '{ran_file}')) {{ throw 'unsigned service did not write its execution marker' }}
  Write-Output '{ATTACK_MARKER}'
}} finally {{
  Remove-OwnedServiceAndRoot
}}
""".strip()
    cleanup = f"""{common}
Remove-OwnedServiceAndRoot
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
$svc = Get-CimInstance Win32_Service -Filter "Name='{service}'" -ErrorAction Stop
if ($null -ne $svc -or (Test-Path -LiteralPath '{root}')) {{ Write-Output 'ZYBUR_WINDOWS_REVERSIBLE_RESIDUAL:unsigned-service:{token}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return attack, cleanup, probe


def _endpoint_alert_scripts(token):
    body = r"""$renamed = Join-Path $root 'ZyburRenamedPowerShell.exe'
Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Destination $renamed -Force -ErrorAction Stop
try {
  & $renamed -NoProfile -NonInteractive -Command 'Write-Output ZYBUR_ENDPOINT_BEHAVIOR'
} catch {
  # An Elastic Defend prevention is an expected execution outcome. The target
  # rule validates the resulting endpoint alert, not child-process success.
}
Start-Sleep -Seconds 3"""
    return _owned_root_scripts("endpoint_behavior_alert", token, body)


def _group_enumeration_scripts(token):
    source = r'''using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class ZyburGroupEnumeration {
  [DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern int NetLocalGroupGetMembers(string server, string group, int level,
    out IntPtr buffer, int preferredMaximumLength, out int entriesRead,
    out int totalEntries, IntPtr resumeHandle);
  [DllImport("Netapi32.dll")]
  static extern int NetApiBufferFree(IntPtr buffer);
  public static void Main() {
    IntPtr buffer=IntPtr.Zero; int read=0,total=0;
    try {
      int status=NetLocalGroupGetMembers(null,"Administrators",0,out buffer,-1,out read,out total,IntPtr.Zero);
      if(status!=0 && status!=234) throw new Win32Exception(status);
      Console.WriteLine("ZYBUR_GROUP_MEMBERS="+read);
    } finally { if(buffer!=IntPtr.Zero) NetApiBufferFree(buffer); }
  }
}'''
    body = fr"""$source = Join-Path $root 'group-enum.cs'
$binary = Join-Path $root 'ZyburGroupEnum-{token}.exe'
Set-Content -LiteralPath $source -Value @'
{source}
'@ -Encoding UTF8 -ErrorAction Stop
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {{ $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }}
& $compiler /nologo /target:exe /out:$binary $source
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $binary)) {{ throw 'group enumeration helper compilation failed' }}
& $binary
if ($LASTEXITCODE -ne 0) {{ throw ('group enumeration helper exited ' + $LASTEXITCODE) }}
Start-Sleep -Milliseconds 500"""
    return _owned_root_scripts("privileged_group_enumeration", token, body)


def _sedebug_scripts(token):
    source = r'''using System;using System.Runtime.InteropServices;
public class ZyburEnableSeDebug{
[StructLayout(LayoutKind.Sequential)]struct L{public uint a;public int b;}
[StructLayout(LayoutKind.Sequential)]struct T{public int n;public L l;public int a;}
[DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
[DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
[DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool LookupPrivilegeValue(string s,string n,out L l);
[DllImport("advapi32.dll",SetLastError=true)]static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref T s,int l,IntPtr p,IntPtr r);
static void A(IntPtr t,L l,int a){T s=new T{n=1,l=l,a=a};if(!AdjustTokenPrivileges(t,false,ref s,0,IntPtr.Zero,IntPtr.Zero)||Marshal.GetLastWin32Error()!=0)throw new Exception("AdjustTokenPrivileges");}
public static void Main(){IntPtr t=IntPtr.Zero;try{if(!OpenProcessToken(GetCurrentProcess(),40,out t))throw new Exception("OpenProcessToken");L l;if(!LookupPrivilegeValue(null,"SeDebugPrivilege",out l))throw new Exception("LookupPrivilegeValue");A(t,l,0);A(t,l,2);Console.WriteLine("ZYBUR_SEDEBUG_ENABLED");}finally{if(t!=IntPtr.Zero)CloseHandle(t);}}}'''
    body = fr"""$source = Join-Path $root 'sedebug.cs'
$binary = Join-Path $root 'ZyburSeDebug-{token}.exe'
Set-Content -LiteralPath $source -Value @'
{source}
'@ -Encoding UTF8 -ErrorAction Stop
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) {{ $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }}
& $compiler /nologo /target:exe /out:$binary $source
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $binary)) {{ throw 'SeDebug helper compilation failed' }}
& $binary
if ($LASTEXITCODE -ne 0) {{ throw ('SeDebug helper exited ' + $LASTEXITCODE) }}
Start-Sleep -Milliseconds 500"""
    return _owned_root_scripts("sedebug_privilege_enable", token, body)


def build_scripts(operation, token):
    if operation not in OPERATIONS:
        raise ValueError(f"unknown managed Windows operation {operation!r}")
    if not _TOKEN.fullmatch(str(token or "")):
        raise ValueError("Windows validation token must be exactly eight lowercase hex characters")
    builders = {
        "endpoint_behavior_alert": _endpoint_alert_scripts,
        "genai_config_modify": _genai_scripts,
        "genai_sensitive_file_access": _genai_sensitive_file_scripts,
        "msbuild_script_parent": _msbuild_parent_scripts,
        "msbuild_unusual_child": _msbuild_child_scripts,
        "msbuild_vaultcli_load": _msbuild_vaultcli_scripts,
        "privileged_group_enumeration": _group_enumeration_scripts,
        "remote_service_install": _remote_service_scripts,
        "scheduled_task_update": _scheduled_task_scripts,
        "sedebug_privilege_enable": _sedebug_scripts,
        "unsigned_service_execute": _unsigned_service_scripts,
        "wdac_inert_policy_file": _wdac_scripts,
    }
    return builders[operation](token)


def run_windows_reversible(cfg, operation, session_factory, token=None):
    if cfg.get("target") not in {"workstation", "domain_controller"}:
        raise ValueError("managed Windows executor requires a registered Windows target")
    token = token or secrets.token_hex(4)
    attack_ps, cleanup_ps, probe_ps = build_scripts(operation, token)

    attack_error = None
    try:
        if operation == "sedebug_privilege_enable":
            audit = session_factory().run_cmd(
                "auditpol.exe", ["/get", f"/subcategory:{TOKEN_RIGHT_AUDIT_GUID}", "/r"])
            audit_out = _text(audit, "std_out")
            if getattr(audit, "status_code", 1) != 0 or ",Success," not in audit_out:
                attack_error = "Token Right Adjusted Events success auditing is not enabled"
        if attack_error is None:
            response = session_factory().run_ps(attack_ps)
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            if getattr(response, "status_code", 1) != 0:
                attack_error = f"Windows operation exited {response.status_code}: {stderr or 'no error text'}"
            elif ATTACK_MARKER not in stdout:
                attack_error = "Windows operation returned no execution marker"
    except Exception as exc:
        attack_error = f"Windows operation transport failed: {type(exc).__name__}: {exc}"

    cleanup_error = None
    try:
        response = session_factory().run_ps(cleanup_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
            cleanup_error = f"cleanup command was not proven: {stderr or 'no cleanup marker'}"
    except Exception as exc:
        cleanup_error = f"cleanup transport failed: {type(exc).__name__}: {exc}"

    probe_error = None
    try:
        response = session_factory().run_ps(probe_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
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


@register("windows_reversible")
def windows_reversible(usecase, ctx):
    start = _now()
    try:
        summary = run_windows_reversible(
            ctx.cfg or {}, (usecase.get("params") or {}).get("operation"),
            ctx.winrm_factory,
        )
        return make_result(
            usecase, "SUCCESS", True, attack_start=start, attack_end=_now(), output=summary,
        )
    except Exception as exc:
        return make_result(
            usecase, f"ERROR: {type(exc).__name__}: {exc}", False,
            attack_start=start, attack_end=_now(),
        )
