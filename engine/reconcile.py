# rules/engine/reconcile.py
"""Pre/post-run reconcile: return the lab target to a known-good posture, and PROVE it.

The defense-evasion use-cases flip real security posture - LSA protection off, UAC
off, script-block logging off, WDigest credential caching on - and a night that
fails to restore them contaminates every later measurement. A PowerShell use-case
that MISSES because a previous night disabled script-block logging is a fabricated
detection failure, which is the one thing this whole subsystem exists to prevent.

THE SHAPE, and why it is not the simpler one:

    probe -> reset -> probe

`residual` is the SECOND probe. It is the gate's ground truth and it is measured,
never assumed. `reset` and `removed` are the DIFFERENCE between the two probes, so
neither can name something that was not observed to change. The superseded design
(plan 2, Task 9) appended to `reset` unconditionally inside a `try/except: pass`
and verified 3 of the 19 items it claimed to fix, which would have reported
`residual == []` over a dirty lab. See
docs/superpowers/specs/2026-07-28-reconcile-design.md.

The probe and the reset are both GENERATED from MANIFEST, so a new entry gets both
halves automatically and coverage cannot silently fall behind the list again.
"""
import json

from cmdline import MAX_RUN_PS_CMDLINE, run_ps_cmdline_len
from firewall import FIREWALL_RULES

# --- the manifest -------------------------------------------------------------
#
# (kind, target, expectation). One entry produces one probe check and one reset
# action. Kinds:
#   regvalue  target=(path, name)  expectation="set:<n>" restore a default
#                                              "absent"  the value must not exist
#   regmember target=(path, name, member)      "absent"  one entry of a MultiString
#                                                        value must not be present,
#                                                        the rest left alone
#   regkey    target=<path>                    "absent"  the whole key must be gone
#   task      target=<task name>            expectation="absent"
#   service   target=<service name>         expectation="absent"
#   bitsjob   target=<job name>             expectation="absent"
#   user      target=<local account name>   expectation="absent"
#   file      target=<full path>            expectation="absent"
#   fileglob  target=<path with * or ?>     expectation="absent"
#
# A file/fileglob target may name an environment variable in %VAR% form (%TEMP%,
# %APPDATA%, %LOCALAPPDATA%). Both generators expand it ON THE BOX with
# [Environment]::ExpandEnvironmentVariables, so a per-user path resolves as
# WIN_USER for the same reason the HKCU entries below do: that is who the
# use-cases run as, through the same run_ps. A path with no %VAR% passes through
# unchanged, so the older entries are untouched by this.
#
# `file` probes and resets with -LiteralPath, which does NOT expand a wildcard: a
# `*` there would look for a file literally named with an asterisk and report
# clean forever. That is what `fileglob` (-Path) exists for, and
# test_reconcile.TestGeneration refuses a wildcard carried as `file`.
#
# Both halves are kept in step with the use-case corpus by
# test_reconcile.TestManifestCoversCorpus, which reads every `cleanup:` line in
# rules/usecases/ and fails if one writes a registry value, or removes a file or
# directory, that this manifest does not know.
MANIFEST = [
    # posture the defense-evasion use-cases turn OFF and must turn back ON
    ("regvalue", (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"), "set:1"),
    ("regvalue", (r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"), "set:1"),
    ("regvalue", (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"), "set:1"),
    # posture the use-cases turn ON and must turn back OFF
    ("regvalue", (r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"), "set:0"),
    ("regvalue", (r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"), "set:1"),
    ("regvalue", (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "Shadow"), "absent"),
    # values whose mere PRESENCE is the weakening
    ("regvalue", (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"), "absent"),
    ("regvalue", (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy"), "absent"),
    # HKCU, per-user, resolved as WIN_USER because that is who the use-cases run
    # as. All three were found by TestManifestCoversCorpus on its FIRST run: the
    # hand-written scan that seeded this manifest matched HKLM: only and missed
    # them, which is precisely why the guard exists rather than a memory.
    ("regvalue", (r"HKCU:\Software\Microsoft\Windows Script\Settings", "AmsiEnable"), "absent"),
    ("regvalue", (r"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce", "CaptchaTest"), "absent"),
    ("regvalue", (r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", "z"), "absent"),
    # Added 2026-09-10 with the widened scan. These three write through a $variable
    # -Path, which the old regex could not read, so nothing here knew them.
    ("regvalue", (r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox", "DNSOverHTTPS"), "absent"),
    ("regvalue", (r"HKLM:\SYSTEM\CurrentControlSet\Services\P3BTestProvider\NetworkProvider", "ProviderPath"), "absent"),
    ("regvalue", (r"HKCU:\Software\Classes\mscfile\shell\open\command", "(default)"), "absent"),

    # A rogue Security Support Provider is the serious one: lsass.exe loads every
    # DLL named in this list at the NEXT REBOOT, so one left behind captures every
    # later logon. The use-case appends a name and its cleanup filters that one
    # name back out - it cannot be "absent", because Security Packages is a real
    # value listing kerberos, msv1_0, schannel and the rest, and deleting it stops
    # the box authenticating anyone. Hence the regmember kind: the member is the
    # deviation, the list is not.
    ("regmember", (r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "Security Packages", "custom_ssp_test"), "absent"),

    # Whole keys a cleanup deletes. Same argument as the values above: the per-run
    # cleanup is best-effort under a bare `except Exception: pass`
    # (caldera_client.py, executors/winrm_command.py), so if it silently fails this
    # probe is the only thing left that looks.
    ("regkey", r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox", "absent"),
    ("regkey", r"HKLM:\SYSTEM\CurrentControlSet\Services\P3BTestProvider", "absent"),
    ("regkey", r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\ZybTestPrinter", "absent"),
    ("regkey", r"HKCU:\Software\Classes\mscfile", "absent"),
    # RunMRU is the one entry here that is a REAL key on any used profile, not an
    # artefact. It is listed because the fake-captcha cleanup deletes the whole key
    # recursively, so reconcile has to do what the corpus already does or the guard
    # is lying; the `z` value above is the artefact that actually matters. Cost: on
    # a night where someone used the Run dialog, this reports one `removed` line
    # and clears that history. It cannot turn the gate red - the reset deletes it.
    ("regkey", r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", "absent"),

    ("task", "P3B_SvchostCmd", "absent"),
    ("task", "P3BScriptTask", "absent"),
    ("task", "P2TestTask", "absent"),
    # Added 2026-10-14: the SYSTEM task the BITS use-case runs its job from (a
    # BITS job owned by a WinRM network logon never runs; one owned by SYSTEM does).
    ("task", "P3BBitsRunner", "absent"),
    # Added 2026-10-14: the task executors/remote_schtask.py registers over RPC and
    # deletes in-code for the supervised scheduled-task operation.
    # A hand entry, not driven by a cleanup line: this is the net if the in-code
    # TSCH/WinRM delete silently fails and leaves a SYSTEM task behind.
    ("task", "TestRemoteTask", "absent"),
    # Added 2026-10-14: the one-shot SYSTEM tasks two DC1 use-cases run their
    # unsigned stand-ins from (Utilman.exe for the accessibility rule,
    # elevation_service.exe for InstallerFileTakeOver), unregistered in-command.
    ("task", "ZybA11yRunner", "absent"),
    ("task", "ZybElevSvcRunner", "absent"),
    # Added 2026-10-16: the one-shot SYSTEM task the MSI-repair use-case runs its
    # browser.exe stand-in from (cleanup: schtasks /delete). Promoted to the nightly
    # pool the same day, so a failed delete must be seen and removed by reconcile.
    ("task", "zybmsi", "absent"),

    ("service", "TestDetectionSvc", "absent"),
    ("bitsjob", "P3BTestJob", "absent"),
    ("user", "TestHidden$", "absent"),

    ("file", r"C:\Windows\System32\test_p3b_ssp.dll", "absent"),
    ("file", r"C:\Windows\Temp\wmi_test.txt", "absent"),
    ("file", r"C:\Windows\Temp\svchost_cmd.txt", "absent"),
    # The SMB transfer operation places a temporary PE at this path.
    # executors/smb_exe_transfer.py puts over SMB. Its cleanup line names this path,
    # so the corpus guard requires it here; reconcile removes it if the in-code delete
    # does not.
    ("file", r"C:\Windows\Temp\staged_tool_test.exe", "absent"),
    ("file", r"C:\Windows\Temp\bits_test.dat", "absent"),
    ("file", r"C:\Windows\Temp\bits_notify.txt", "absent"),
    ("file", r"C:\Windows\Temp\p2_task.bat", "absent"),
    # Added 2026-10-14 with the scheduled-task and BITS payload rewrites: the
    # benign task script, and the BITS stage-2 script P3BBitsRunner runs.
    ("file", r"C:\Windows\Temp\p2_task.ps1", "absent"),
    ("file", r"C:\Windows\Temp\bits_job.ps1", "absent"),
    # Added 2026-08-11 with the safe-promotion batch: the two promoted use-cases
    # that DO write are covered here, so "it cleaned up after itself" is measured
    # on the box rather than promised in a YAML field.
    ("file", r"C:\Windows\Temp\AdFind.exe", "absent"),
    ("file", r"C:\Windows\Temp\7za.exe", "absent"),
    ("file", r"C:\Windows\Temp\test_encrypt.txt", "absent"),
    ("file", r"C:\Windows\Temp\test_encrypted.7z", "absent"),
    # Added 2026-08-21 with the two RMM use-cases (huntress-mirror). Both drop a
    # renamed node.exe under C:\Users\Public. The RMM first-seen one rotates its
    # FILENAME daily across 24 agent names, so the item that can be probed is the
    # directory, not any one file - the "file" kind already probes with Test-Path
    # and resets with Remove-Item -Recurse, both of which are correct for a folder.
    # client32.exe is the same pattern from 2026-07-28 and was never covered.
    ("file", r"C:\Users\Public\rmmchk", "absent"),
    ("file", r"C:\Users\Public\client32.exe", "absent"),
    # Added 2026-08-26 with the rundll32 use-case rewrite. Both of these drop a
    # RENAMED COPY OF cmd.exe into a temp folder - the office one has done so since
    # it was written and was never covered here, so "post_reconcile: 0" has been
    # answering a question it never asked. Directory targets, not the files inside:
    # the "file" kind probes with Test-Path and resets with Remove-Item -Recurse,
    # which is correct for a folder, and a signed binary left lying around under
    # another name is exactly the artefact worth failing a teardown over.
    ("file", r"C:\Windows\Temp\rundll32_test", "absent"),
    ("file", r"C:\Windows\Temp\office_test", "absent"),
    # Added 2026-10-14 with the DC1 moves of three PREVENTED-only use-cases: the
    # folder the memssp one compiles its lsass.exe stand-in into, the renamed cmd.exe
    # the svchost-masquerade one runs, and the file certutil is told to write. Their
    # cleanup lines name these paths. They run on DC1, which reconcile does not
    # probe, so there each payload's own CLEAN or RESIDUE marker is the proof.
    ("file", r"C:\Windows\Temp\zyb_memssp", "absent"),
    ("file", r"C:\Windows\Temp\svchost.exe", "absent"),
    ("file", r"C:\Windows\Temp\ci_test.dat", "absent"),
    # Added 2026-10-14 with the use-cases for enabled rules that had none. Folders
    # the stand-ins compile into or the malware drop lands in, and the flag files
    # that exist only while an audit subcategory is off (or on) because of a run:
    # their cleanup lines restore the setting only while the flag is there. Only
    # zyb_malfile and zyb_workfolders are workstation paths; the rest are DC1, where
    # each payload's own CLEAN/RESTORED or RESIDUE marker is the proof.
    ("file", r"C:\Windows\Temp\zyb_malfile", "absent"),
    ("file", r"C:\Windows\Temp\zyb_workfolders", "absent"),
    ("file", r"C:\Windows\Temp\zyb_dlscript", "absent"),
    ("file", r"C:\Windows\Temp\zyb_wfp", "absent"),
    ("file", r"C:\Windows\Temp\zyb_wfp.flag", "absent"),
    ("file", r"C:\Windows\Temp\zyb_auditpol.flag", "absent"),
    ("file", r"C:\Windows\Temp\zyb_lsasshandle.flag", "absent"),
    # Added 2026-10-22 with the three steered-browser drafts of the default ingest noise baseline (slice 5c, rules/usecases/execution/
    # steered-*.yaml): the throwaway profile or user data folder each one starts a genuine browser in and its cleanup removes. Folders,
    # like rmmchk above: the "file" kind probes with Test-Path and resets with Remove-Item -Recurse. %LOCALAPPDATA% is expanded on the box.
    ("file", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\zybsteer", "absent"),
    ("file", r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\zybsteer.test", "absent"),
    ("file", r"%LOCALAPPDATA%\zybsteer", "absent"),
    # Added 2026-09-10, when TestManifestCoversCorpus grew the file half of its
    # scan. Every entry below is a path a `cleanup:` line in rules/usecases/
    # removes and that NOTHING here probed: 44 of the 53 filesystem artefacts the
    # nightly corpus drops were outside the one thing validation/lib/gates.js
    # reads, so `post_reconcile: 0` was, for those, answering a question it never
    # asked. The regvalue half has had this guarantee since the manifest was
    # written; this is the same guarantee for the kind the guard could not see.
    #
    # dropped in the running user's TEMP - renamed interpreters, staged payloads,
    # markers. %TEMP% is expanded on the box, as WIN_USER, by _ps_path.
    ("file", r"%TEMP%\amsi.dll", "absent"),
    ("file", r"%TEMP%\autoit3.exe", "absent"),
    ("file", r"%TEMP%\browser.exe", "absent"),
    ("file", r"%TEMP%\CompatTelRunner.exe", "absent"),
    ("file", r"%TEMP%\deno.exe", "absent"),
    ("file", r"%TEMP%\invoice_Q4_2025.pdf.exe", "absent"),
    ("file", r"%TEMP%\lsass_test.dmp", "absent"),
    ("file", r"%TEMP%\MSBuild.exe", "absent"),
    ("file", r"%TEMP%\mshta.exe.log", "absent"),
    ("file", r"%TEMP%\node.exe", "absent"),
    ("file", r"%TEMP%\notepad.exe", "absent"),
    ("file", r"%TEMP%\test_cmstp.inf", "absent"),
    ("file", r"%TEMP%\test_psengine.exe", "absent"),
    ("file", r"%TEMP%\test_schtask.vbs", "absent"),
    ("file", r"%TEMP%\test_wsh_ps.vbs", "absent"),
    ("file", r"%TEMP%\update_check.ps1", "absent"),
    ("file", r"%TEMP%\winword.exe", "absent"),
    ("file", r"%TEMP%\zyb.au3", "absent"),
    ("file", r"%TEMP%\zyb.hta", "absent"),
    ("file", r"%TEMP%\zyb_d3.marker", "absent"),
    ("file", r"%TEMP%\zyb_psengine", "absent"),
    ("file", r"%TEMP%\zyb_scriptint.exe", "absent"),
    # per-user persistence, and the INetCache folder the inet-cache use-case runs
    # from. The last one is a DIRECTORY: the file kind resets with
    # Remove-Item -Recurse, which is correct for a folder.
    ("file", r"%APPDATA%\Microsoft\Word\Startup\zyb.wll", "absent"),
    # The supervised startup-folder operation creates and
    # removes inside its own PowerShell command. %APPDATA% expands on the box as
    # WIN_USER; this is the net if that in-command Remove-Item fails and leaves a
    # boot-persistent .lnk in the Startup folder.
    ("file", r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\test_p3b.lnk", "absent"),
    ("file", r"%APPDATA%\remcos\logs.dat", "absent"),
    ("file", r"%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\P3ATEST", "absent"),
    # C:\Users\Public and the Administrator desktop, where the lateral-movement,
    # SAP and UAC-bypass use-cases write. sap.com_zyb is a directory.
    ("file", r"C:\Users\Public\sap.com_zyb", "absent"),
    ("file", r"C:\Users\Public\zyb_dcom_mmc.txt", "absent"),
    ("file", r"C:\Users\Public\zyb_uac.txt", "absent"),
    # Added 2026-10-14: the folder executors/smb_ransom_note.py writes its notes
    # into over SMB. A directory, like rmmchk above. Its own cleanup has been
    # retried and probed since the same day; this is the check after the night.
    ("file", r"C:\Users\Administrator\Desktop\ransom_note_test", "absent"),
    # Added 2026-10-14: the folder executors/smb_rename.py creates the .docx files
    # in and renames to .encrypted over SMB. A directory, removed in-code; this is
    # the net if that Remove-Item fails and leaves the renamed files behind.
    ("file", r"C:\Users\Administrator\Desktop\smb_rename_test", "absent"),
    # C:\Windows\Temp and the webshell root
    ("file", r"C:\Windows\Temp\ncat.exe", "absent"),
    ("file", r"C:\Windows\Temp\sc_test", "absent"),
    ("file", r"C:\Windows\Temp\zyb.txt", "absent"),
    ("file", r"C:\Windows\Temp\zyb_nd.dmp", "absent"),
    ("file", r"C:\Windows\Temp\zyb_wmi.txt", "absent"),
    # Added 2026-10-14 with the name-simulated DC1 batch: each use-case drops its
    # renamed cmd.exe copies into its own subfolder of zyb_masq, and every cleanup
    # line removes the whole parent. A directory, like rmmchk above.
    ("file", r"C:\Windows\Temp\zyb_masq", "absent"),
    # Added 2026-10-14 with the medium env_gap rewrites (all DC1). Per-case folders
    # the stand-ins and unsigned DLLs are compiled into. WebHelpDesk, wps and
    # INetCache exist only because a rule names them; each cleanup removes them
    # once empty. Directories, like rmmchk above.
    ("file", r"C:\Windows\Temp\zyb_a11y", "absent"),
    ("file", r"C:\Windows\Temp\zyb_elevsvc", "absent"),
    ("file", r"C:\Windows\Temp\zyb_phantomdll", "absent"),
    ("file", r"C:\Windows\Temp\zyb_aadagent", "absent"),
    ("file", r"C:\Program Files\WebHelpDesk\zyb_whd", "absent"),
    ("file", r"C:\Program Files\WebHelpDesk", "absent"),
    ("file", r"%TEMP%\wps\INetCache\zyb_wps", "absent"),
    ("file", r"%TEMP%\wps\INetCache", "absent"),
    ("file", r"%TEMP%\wps", "absent"),
    ("file", r"C:\zyb", "absent"),
    # System32. The three RegBack hives are COPIES the regback use-case makes:
    # RegBack has shipped empty by default since Windows 10 1803, so "absent" is
    # the real baseline on this lab, and a readable SAM copy left behind is
    # exactly the artefact worth failing a teardown over. zyb_test is a directory.
    ("file", r"C:\Windows\System32\memssp_test.dll", "absent"),
    ("file", r"C:\Windows\System32\mimilsa.log", "absent"),
    ("file", r"C:\Windows\System32\config\RegBack\SAM", "absent"),
    ("file", r"C:\Windows\System32\config\RegBack\SECURITY", "absent"),
    ("file", r"C:\Windows\System32\config\RegBack\SYSTEM", "absent"),
    ("file", r"C:\Windows\System32\DriverStore\FileRepository\zyb_test", "absent"),
    # wildcard drops. The use-case names the pattern, not the file, so the
    # manifest has to as well - see `fileglob` in the kinds note above.
    ("fileglob", r"%TEMP%\ntds_capi_*.pfx", "absent"),
    ("fileglob", r"C:\Users\Administrator\Desktop\p2a_*.kirbi", "absent"),
    ("fileglob", r"C:\Users\Public\p2a_*.kirbi", "absent"),
    ("fileglob", r"C:\Windows\Temp\p2a_*.kirbi", "absent"),
    ("fileglob", r"C:\Windows\Temp\regback_*_test.hiv", "absent"),
    # Added 2026-10-19: rule batch 2 nightly tests; each line is a cleanup target of a new use-case (integration files).
    ("regkey", r"HKLM:\SOFTWARE\Classes\CLSID\{7E2D4B6A-91C3-4F58-A0D1-3B8C5E6F2A47}", "absent"),
    ("file", r"C:\Windows\Temp\zyb_state", "absent"),
    ("file", r"C:\Windows\Temp\zyb_state\hosts", "absent"),
    ("file", r"C:\Users\Public\zyb_bits", "absent"),
    ("task", "ZybBitsXfer", "absent"),
    ("regvalue", (r"HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp", "127.0.0.1/19080"), "absent"),
    ("file", r"C:\Users\Public\zyb_unusualdir", "absent"),
    ("file", r"C:\Program Files\w.exe", "absent"),
    ("file", r"%LOCALAPPDATA%\Temp\7zOZYBWSH", "absent"),
    ("file", r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\zyb_note.txt", "absent"),
    ("file", r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\zyb_startup_script.vbs", "absent"),
    ("file", r"%LOCALAPPDATA%\ZybBrowser", "absent"),
    ("file", r"C:\Users\Public\zyb_mandatory", "absent"),
    ("file", r"C:\Windows\Tasks\zybjob.job", "absent"),
    ("file", r"C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\zybtest.aspx", "absent"),
    ("file", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\zyb_msi_note.txt", "absent"),
    ("file", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\zyb_unsigned_note.txt", "absent"),
    ("file", r"C:\Windows\Temp\zyb_state\appinit", "absent"),
    ("regkey", r"HKCU:\Software\Classes\CLSID\{6C1E9B24-5D3A-4F87-A0B2-9E41D7C3F5A8}", "absent"),
    ("regkey", r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\zybshim.exe", "absent"),
    ("regvalue", (r"HKLM:\SOFTWARE\Microsoft\NetSh", "zybhelper"), "absent"),
    ("regkey", r"HKCU:\Software\Microsoft\Office test\Special\Perf", "absent"),
    ("regvalue", (r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "ZybRunKey"), "absent"),
    # Rule-dictated value names under the current user's Run key: the 2026-10-20 stand-ins for three rules Defend cannot
    # feed (RemoteMonologue, NullSessionPipes, the DNS block list). No legitimate Run value carries these names, so they
    # are not real objects and the zyb-scoping rule of 2026-10-19 holds.
    ("regvalue", (r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "RunAs"), "absent"),
    ("regvalue", (r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "NullSessionPipes"), "absent"),
    ("regvalue", (r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "EnableGlobalQueryBlockList"), "absent"),
    ("regkey", r"HKCU:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{2B7D4E91-8A3C-4F65-B0D1-5E9A6C3F7B24}", "absent"),
    ("regkey", r"HKLM:\SYSTEM\CurrentControlSet\Services\ZybSvcReg", "absent"),
    ("file", r"C:\Users\Public\Downloads\zyb_masq", "absent"),
    ("file", r"C:\Users\Public\zyb_masq", "absent"),
    ("file", r"C:\inetpub\logs\LogFiles\zyb_w3svc", "absent"),
    ("file", r"C:\TeamCity", "absent"),
    ("fileglob", r"C:\Users\Public\Downloads\zyb_html_*", "absent"),
    # Only the DumpType value, never the LocalDumps key: the key can be a real one (narrowed 2026-10-19 after a night deleted a real object).
    ("regvalue", (r"HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps", "DumpType"), "absent"),
    ("file", r"C:\Windows\Temp\zyb_state\werdump", "absent"),
    ("regkey", r"HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\5A59425A59425A59425A59425A59425A59425A59", "absent"),
    ("regkey", r"HKLM:\SYSTEM\CurrentControlSet\Services\ZybSolarWindsSvc", "absent"),
    ("regkey", r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\{9D2E7C41-3A58-4B06-8E1F-6C4A0B7D5E93}", "absent"),
    ("file", r"C:\Windows\SYSVOL\domain\Policies\zyb_gpotask", "absent"),
    ("file", r"C:\Windows\System32\spool\drivers\x64\3\zyb_spool_del.dll", "absent"),
    ("file", r"C:\Windows\System32\spool\PRINTERS\zyb_spl_test.SPL", "absent"),
    ("file", r"C:\Windows\SoftwareDistribution\Download\Install\psexec64.exe", "absent"),
    ("regkey", r"HKLM:\SYSTEM\ControlSetZyb", "absent"),
]

PROBE_MARKER = "RECONCILE_VERIFY"
# Every lab firewall rule name the executors can open, from the one table that
# defines them. Swept, but NOT probed: see `attempted` in reconcile().
FIREWALL_RULE_NAMES = sorted({rn for rules in FIREWALL_RULES.values() for rn, _, _ in rules})


def item_id(kind, target):
    """The stable name an item is reported under, in both the probe and the diff."""
    if kind == "regvalue":
        path, name = target
        return f"regvalue:{path}\\{name}"
    if kind == "regmember":
        path, name, member = target
        return f"regmember:{path}\\{name}={member}"
    return f"{kind}:{target}"


def _ps_quote(s):
    return str(s).replace("'", "''")


def _ps_path(target):
    """A file target as PowerShell, with any %VAR% resolved on the Windows host.

    Kept out of the single-quoted string itself: PowerShell does not expand inside
    single quotes, and switching these to a double-quoted string would put every
    path through PS parsing for the sake of three environment variables.
    """
    return f"([Environment]::ExpandEnvironmentVariables('{_ps_quote(target)}'))"


def build_probe_ps(manifest=None):
    """One PowerShell script printing one line per DEVIATION, then PROBE_MARKER.

    The marker line alone means clean. Silence means the script never ran (the
    command-line note above manifest_chunks), and _probe refuses it.

    GENERATED from the manifest, one check per entry, which is the whole point: the
    superseded version hand-wrote three checks for nineteen items and would have
    reported a clean lab while sixteen went unexamined.
    """
    manifest = MANIFEST if manifest is None else manifest
    lines = []
    for kind, target, expectation in manifest:
        ident = _ps_quote(item_id(kind, target))
        if kind == "regvalue":
            path, name = target
            got = f"(Get-ItemProperty -Path '{_ps_quote(path)}' -Name '{_ps_quote(name)}' -EA SilentlyContinue).'{_ps_quote(name)}'"
            if expectation == "absent":
                lines.append(f"if ($null -ne {got}) {{ '{ident}' }}")
            else:
                want = expectation.split(":", 1)[1]
                # A MISSING value counts as a deviation for a set: expectation too.
                # "the key is gone" and "the key is right" are different states and
                # only one of them is the baseline.
                lines.append(f"if ({got} -ne {want}) {{ '{ident}' }}")
        elif kind == "regmember":
            # NOT "absent": Security Packages is a real LSA value that lists the
            # providers lsass loads, and removing it breaks logon. The deviation is
            # one MEMBER of the list, so that is what is probed.
            path, name, member = target
            got = f"(Get-ItemProperty -Path '{_ps_quote(path)}' -Name '{_ps_quote(name)}' -EA SilentlyContinue).'{_ps_quote(name)}'"
            lines.append(f"if ({got} -contains '{_ps_quote(member)}') {{ '{ident}' }}")
        elif kind == "regkey":
            lines.append(f"if (Test-Path -LiteralPath '{_ps_quote(target)}') {{ '{ident}' }}")
        elif kind == "task":
            lines.append(f"if (schtasks /query /tn '{_ps_quote(target)}' 2>$null) {{ '{ident}' }}")
        elif kind == "service":
            lines.append(f"if (Get-Service -Name '{_ps_quote(target)}' -EA SilentlyContinue) {{ '{ident}' }}")
        elif kind == "bitsjob":
            lines.append(f"if ((bitsadmin /list /allusers 2>$null) -match '{_ps_quote(target)}') {{ '{ident}' }}")
        elif kind == "user":
            lines.append(f"if (net user '{_ps_quote(target)}' 2>$null) {{ '{ident}' }}")
        elif kind in ("file", "fileglob"):
            path_arg = "-Path" if kind == "fileglob" else "-LiteralPath"
            lines.append(f"if (Test-Path {path_arg} {_ps_path(target)}) {{ '{ident}' }}")
        else:
            raise ValueError(f"reconcile: unknown manifest kind {kind!r}")
    # LAST, and through the pipeline the deviation lines use. A marker printed
    # first (Write-Host, until 2026-10-14) proved only that the script started;
    # this one proves it reached its last check, over the same stream.
    lines.append(f"Write-Output '{PROBE_MARKER}'")
    return "; ".join(lines)


def build_reset_ps(manifest=None):
    """One PowerShell script restoring every manifest item. Best effort per item:
    an absent registry key must not abort the other seventeen repairs."""
    manifest = MANIFEST if manifest is None else manifest
    lines = []
    for kind, target, expectation in manifest:
        if kind == "regvalue":
            path, name = target
            if expectation == "absent":
                lines.append(f"Remove-ItemProperty -Path '{_ps_quote(path)}' -Name '{_ps_quote(name)}' -Force -EA SilentlyContinue")
            else:
                want = expectation.split(":", 1)[1]
                lines.append(
                    f"New-Item -Path '{_ps_quote(path)}' -Force -EA SilentlyContinue | Out-Null; "
                    f"Set-ItemProperty -Path '{_ps_quote(path)}' -Name '{_ps_quote(name)}' "
                    f"-Value {want} -Type DWord -Force -EA SilentlyContinue")
        elif kind == "regmember":
            path, name, member = target
            got = f"(Get-ItemProperty -Path '{_ps_quote(path)}' -Name '{_ps_quote(name)}' -EA SilentlyContinue).'{_ps_quote(name)}'"
            lines.append(
                f"$rcv = {got}; "
                f"if ($rcv -contains '{_ps_quote(member)}') {{ "
                f"Set-ItemProperty -Path '{_ps_quote(path)}' -Name '{_ps_quote(name)}' "
                f"-Value ([string[]]($rcv | Where-Object {{ $_ -ne '{_ps_quote(member)}' }})) "
                f"-Type MultiString -Force -EA SilentlyContinue }}")
        elif kind == "regkey":
            lines.append(f"Remove-Item -LiteralPath '{_ps_quote(target)}' -Recurse -Force -EA SilentlyContinue")
        elif kind == "task":
            lines.append(f"schtasks /delete /tn '{_ps_quote(target)}' /f 2>$null | Out-Null")
        elif kind == "service":
            lines.append(f"sc.exe delete '{_ps_quote(target)}' 2>$null | Out-Null")
        elif kind == "bitsjob":
            lines.append(f"bitsadmin /cancel '{_ps_quote(target)}' 2>$null | Out-Null")
        elif kind == "user":
            lines.append(f"net user '{_ps_quote(target)}' /delete 2>$null | Out-Null")
        elif kind in ("file", "fileglob"):
            path_arg = "-Path" if kind == "fileglob" else "-LiteralPath"
            lines.append(f"Remove-Item {path_arg} {_ps_path(target)} -Recurse -Force -EA SilentlyContinue")
        else:
            raise ValueError(f"reconcile: unknown manifest kind {kind!r}")
    return "; ".join(lines)


# pywinrm's run_ps is `run_cmd('powershell -encodedcommand <base64 of UTF-16LE>')`,
# and WinRS runs every run_cmd as `cmd.exe /C <command>`, so every script rides on
# ONE cmd.exe command string. cmd.exe refuses one over 8,191 characters, and does
# it quietly as far as run_ps can tell: PowerShell never starts, stdout is empty,
# and the call returns normally. The number and the measure live in cmdline.py, so
# the executors, lint and this file cannot disagree.
#
# The first reading of the limit was wrong, and the history is why the guard is
# the marker and not the number. 2026-09-11: the manifest went 31 -> 84 entries in
# a13caa6, the probe encoded to 35,223 characters and failed as a WinRM HTTP 500,
# read here as CreateProcess's 32,767 limit, so chunks were budgeted at 24,000.
# That cleared the loud failure above 32,767 and walked into the silent one below
# it. Measured live 2026-10-14: the 88-entry manifest made 2 chunks whose probes
# were 23,783 and 12,847 characters, and the endpoint process events show every
# one of those cmd.exe processes (command lines 23,814 and 12,878) started with NO
# powershell.exe child, while a 270-character run_ps started both. _probe did not
# look for the marker, so empty stdout read as a clean lab: baseline_reconcile=0
# and post_reconcile=0 on every night since about 2026-09-11 are unproven.
#
# So the chunks are budgeted at MAX_RUN_PS_CMDLINE, probe AND reset, which keeps
# us off the wall we know about. The real guard is in _probe: a chunk whose stdout
# lacks the PROBE_MARKER line (the probe's last statement) or whose exit status is
# not 0 did not run to the end, for whatever reason, the next unmeasured limit
# included, and is a probe failure, never a clean answer.


def manifest_chunks(manifest=None, budget=MAX_RUN_PS_CMDLINE):
    """Split the manifest, in order, so BOTH generated scripts for every chunk fit.

    Greedy and deterministic. An entry that cannot fit even alone raises: silently
    dropping it would be the unexamined item this module exists to prevent."""
    manifest = MANIFEST if manifest is None else manifest

    def fits(chunk):
        return (run_ps_cmdline_len(build_probe_ps(chunk)) <= budget
                and run_ps_cmdline_len(build_reset_ps(chunk)) <= budget)

    chunks, current = [], []
    for entry in manifest:
        if fits(current + [entry]):
            current.append(entry)
            continue
        if not current:
            raise ValueError(f"reconcile: manifest entry {entry!r} alone exceeds the "
                             f"{budget}-character command-line budget")
        chunks.append(current)
        current = [entry]
        if not fits(current):
            raise ValueError(f"reconcile: manifest entry {entry!r} alone exceeds the "
                             f"{budget}-character command-line budget")
    if current:
        chunks.append(current)
    return chunks


def _probe(session, manifest):
    """Deviations as a set of item ids, one run_ps per chunk. A chunk that fails
    raises, and the caller turns that into residual: a HALF-read lab is not clean.

    A chunk with no PROBE_MARKER line, or a non-zero exit status, FAILED, even
    though run_ps returned normally: that is exactly what a script cmd.exe refused
    to start looks like, and it read as a clean lab until 2026-10-14."""
    found = set()
    chunks = manifest_chunks(manifest)
    for n, chunk in enumerate(chunks, 1):
        r = session.run_ps(build_probe_ps(chunk))
        text = (getattr(r, "std_out", b"") or b"").decode("utf-8", "replace")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        status = getattr(r, "status_code", None)
        no_marker = PROBE_MARKER not in lines
        if no_marker or status not in (None, 0):
            why = f"no {PROBE_MARKER} line, " if no_marker else ""
            err = (getattr(r, "std_err", b"") or b"").decode("utf-8", "replace").strip()
            err = f", stderr: {err.splitlines()[0][:160]}" if err else ""
            raise RuntimeError(f"chunk {n} of {len(chunks)} did not run to its end "
                               f"({why}exit status {status}{err})")
        found |= {ln for ln in lines if ln != PROBE_MARKER}
    return found


def reconcile(session, dedup=None, firewall=None, cfg=None, manifest=None):
    """Return {"reset", "removed", "residual", "attempted", "checked"}.

    A clean reconcile has `residual == []`. That is the ONLY claim here that is
    measured on the Windows host, and `validation/lib/gates.js` gates the night on
    it. Everything else is reported for the record.
    """
    manifest = MANIFEST if manifest is None else manifest
    by_id = {item_id(k, t): k for k, t, _ in manifest}
    out = {"reset": [], "removed": [], "residual": [], "attempted": [], "checked": len(manifest)}

    try:
        before = _probe(session, manifest)
    except Exception as e:
        # An unreadable lab is NOT a clean lab. Returning [] here would be the
        # fabricated zero the whole loop exists to remove.
        out["residual"] = [f"probe_failed: {e}"]
        return out

    if before:
        # One run_ps per chunk, best effort per chunk: a failure in one must not
        # stop the others, same rule as per item inside build_reset_ps. What did
        # not get fixed still shows up, measured, in the second probe.
        for chunk in manifest_chunks(manifest):
            try:
                session.run_ps(build_reset_ps(chunk))
            except Exception as e:
                out["attempted"].append(f"reset_failed: {e}")

    try:
        after = _probe(session, manifest)
    except Exception as e:
        out["residual"] = [f"probe_failed: {e}"]
        return out

    # The DIFFERENCE is the only thing we may claim to have fixed.
    for ident in sorted(before - after):
        repaired = by_id.get(ident) in ("regvalue", "regmember")
        (out["reset"] if repaired else out["removed"]).append(ident)
    out["residual"] = sorted(after)

    # Attacker-side and Linux-side. There is no probe for these from the Windows
    # host, so they are ATTEMPTED and never folded into reset/removed. Saying which
    # half of the work is unverified is the point.
    for rn in FIREWALL_RULE_NAMES:
        try:
            session.run_cmd("cmd", ["/c", f'netsh advfirewall firewall delete rule name="{rn}" 2>nul'])
            out["attempted"].append(f"fwrule:{rn}")
        except Exception as e:
            out["attempted"].append(f"fwrule:{rn} failed: {e}")
    if dedup is not None:
        try:
            dedup.cleanup()
            out["attempted"].append("dedup:netns")
        except Exception as e:
            out["attempted"].append(f"dedup:netns failed: {e}")

    return out


def main_json(session, dedup=None, cfg=None):
    """The `run.py --reconcile` body: print one JSON object, exit 0 only when clean."""
    out = reconcile(session, dedup=dedup, cfg=cfg)
    print(json.dumps(out))
    return 0 if not out["residual"] else 1
