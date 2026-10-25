"""DC-local Kerberos AS-REQ validation with no third-party payload binary.

A disposable pre-auth-disabled user is created on the DC. A raw, valid AS-REQ
is generated locally with Impacket's ASN.1 types, then sent from PowerShell on
the detect-only DC to that DC's non-loopback LAN address. Elastic Defend observes
a non-LSASS process connecting to TCP/88 while Security records the matching
successful 4768 on the same clock. The executor independently confirms that
unique 4768 before cleanup. No ticket, reply body, or packet file is retained.
"""
import base64
import datetime
import random
import re
import secrets
from datetime import timezone

from executors.registry import register
from result import make_result


SETUP_MARKER = "ZYBUR_KERBEROS_ASREQ_READY"
ATTACK_MARKER = "ZYBUR_KERBEROS_ASREQ_SENT"
AUDIT_MARKER = "ZYBUR_KERBEROS_ASREQ_4768_CONFIRMED"
CLEANUP_MARKER = "ZYBUR_KERBEROS_ASREQ_CLEANUP_OK"
PROBE_MARKER = "ZYBUR_KERBEROS_ASREQ_PROBE_CLEAN"
_TOKEN = re.compile(r"^[0-9a-f]{8}$")
_REALM = re.compile(r"^[A-Za-z0-9.-]{1,255}$")


def _now():
    return datetime.datetime.now(timezone.utc).isoformat()


def _text(response, field):
    return (getattr(response, field, b"") or b"").decode("utf-8", "replace").strip()


def build_asreq(username, realm, nonce=None, now=None):
    """Return one no-preauth AS-REQ. It contains no password or ticket value."""
    if not re.fullmatch(r"[A-Za-z0-9-]{1,20}", str(username or "")):
        raise ValueError("Kerberos probe username must be a simple account name")
    if not _REALM.fullmatch(str(realm or "")):
        raise ValueError("Kerberos probe realm is invalid")
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter
    from impacket.krb5.types import KerberosTime, Principal
    from pyasn1.codec.der import encoder
    from pyasn1.type.univ import noValue

    realm = realm.upper()
    request = AS_REQ()
    request["pvno"] = 5
    request["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    pac = KERB_PA_PAC_REQUEST()
    # No authorization-data PAC is needed to validate an authentication ticket
    # request. Omitting it keeps the AS-REP below the Windows KDC's UDP response
    # threshold; the response bytes stay in memory and never cross the host boundary.
    pac["include-pac"] = False
    request["padata"] = noValue
    request["padata"][0] = noValue
    request["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    request["padata"][0]["padata-value"] = encoder.encode(pac)
    body = seq_set(request, "req-body")
    body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.proxiable.value,
    ])
    client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    server = Principal(
        "krbtgt/" + realm, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(body, "cname", client.components_to_asn1)
    seq_set(body, "sname", server.components_to_asn1)
    body["realm"] = realm
    future = (now or datetime.datetime.now(timezone.utc)) + datetime.timedelta(hours=1)
    body["till"] = KerberosTime.to_asn1(future)
    body["rtime"] = KerberosTime.to_asn1(future)
    body["nonce"] = nonce if nonce is not None else random.getrandbits(31)
    seq_set_iter(body, "etype", (
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.rc4_hmac.value),
    ))
    return encoder.encode(request)


def _account_scripts(token, password):
    name = f"zv-krb-{token}"
    owner = f"Zybur AD validation:suspicious_kerberos_asreq:{token}"
    common = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$owner = '{owner}'
function Get-OwnedUser {{
  $u = Get-ADUser -LDAPFilter '(cn={name})' -Properties Description -ErrorAction Stop
  if ($null -ne $u -and $u.Description -ne $owner) {{ throw 'refusing to touch a pre-existing Kerberos validation user' }}
  return $u
}}
function Remove-OwnedUser {{
  $u = Get-OwnedUser
  if ($null -ne $u) {{ Remove-ADUser -Identity $u -Confirm:$false -ErrorAction Stop }}
}}
""".strip()
    setup = f"""{common}
Remove-OwnedUser
$secure = ConvertTo-SecureString '{password}' -AsPlainText -Force
$u = New-ADUser -Name '{name}' -SamAccountName '{name}' -Description $owner -Enabled $true -AccountPassword $secure -PassThru -ErrorAction Stop
Set-ADAccountControl -Identity $u -DoesNotRequirePreAuth $true -ErrorAction Stop
Start-Sleep -Milliseconds 500
$realm = (Get-ADDomain -ErrorAction Stop).DNSRoot.ToUpperInvariant()
Write-Output ('{SETUP_MARKER}:' + $realm)
""".strip()
    cleanup = f"""{common}
Remove-OwnedUser
Write-Output '{CLEANUP_MARKER}'
""".strip()
    probe = f"""$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$u = Get-ADUser -LDAPFilter '(cn={name})' -ErrorAction Stop
if ($null -ne $u) {{ Write-Output 'ZYBUR_KERBEROS_ASREQ_RESIDUAL:user:{name}' }}
else {{ Write-Output '{PROBE_MARKER}' }}
""".strip()
    return name, setup, cleanup, probe


def _send_script(packet, dc_host):
    # Kerberos over TCP is a four-byte network-order length followed by DER.
    # PowerShell holds both request and response only in memory.
    encoded = base64.b64encode(packet).decode("ascii")
    return f"""$ErrorActionPreference='Stop'
$payload=[Convert]::FromBase64String('{encoded}')
$client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
$client.ReceiveTimeout=10000; $client.SendTimeout=10000
$stream=$null
function Read-Exact([IO.Stream]$s,[byte[]]$buffer) {{
  $offset=0
  while($offset -lt $buffer.Length) {{
    $n=$s.Read($buffer,$offset,$buffer.Length-$offset)
    if($n -le 0) {{ throw 'KDC closed the TCP stream before a complete response' }}
    $offset+=$n
  }}
}}
try {{
  $client.Connect('{dc_host}',88)
  # Give the endpoint sensor a deterministic network-event timestamp before
  # the KDC writes 4768; the rule requires this exact EQL sequence order.
  Start-Sleep -Milliseconds 1000
  $stream=$client.GetStream()
  $wireLength=[Net.IPAddress]::HostToNetworkOrder([int]$payload.Length)
  $header=[BitConverter]::GetBytes($wireLength)
  $stream.Write($header,0,$header.Length)
  $stream.Write($payload,0,$payload.Length)
  $stream.Flush()
  $replyHeader=New-Object byte[] 4
  Read-Exact $stream $replyHeader
  $replyLength=[Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($replyHeader,0))
  if($replyLength -le 0 -or $replyLength -gt 1048576) {{ throw 'KDC returned an invalid response length' }}
  $reply=New-Object byte[] $replyLength
  Read-Exact $stream $reply
  if($reply[0] -ne 0x6b) {{ throw 'KDC did not return an AS-REP' }}
  $port=([Net.IPEndPoint]$client.Client.LocalEndPoint).Port
  Write-Output ('{ATTACK_MARKER}:'+$port)
}} finally {{
  if($null -ne $stream) {{ $stream.Dispose() }}
  $client.Dispose()
}}"""


def _audit_script(name):
    return f"""$ErrorActionPreference='Stop'
$found=$false
for($attempt=0; $attempt -lt 10 -and -not $found; $attempt++) {{
  $xpath="*[System[(EventID=4768)]] and *[EventData[Data[@Name='TargetUserName']='{name}']]"
  $events=Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents 5 -ErrorAction SilentlyContinue
  foreach($event in $events) {{
    $xml=[xml]$event.ToXml()
    $fields=@{{}}
    foreach($node in $xml.Event.EventData.Data) {{
      $fields[[string]$node.Name]=[string]$node.'#text'
    }}
    if($fields['TargetUserName'] -eq '{name}' -and $fields['Status'] -eq '0x0') {{
      $found=$true
      break
    }}
  }}
  if(-not $found) {{ Start-Sleep -Milliseconds 250 }}
}}
if(-not $found) {{ throw 'matching successful 4768 was not found' }}
Write-Output '{AUDIT_MARKER}'"""


def _default_dc_factory(cfg):
    def make():
        import winrm
        return winrm.Session(
            f"http://{cfg['dc_host']}:5985/wsman",
            auth=(cfg["dc_user"], cfg["dc_pass"]), transport="ntlm",
            operation_timeout_sec=60, read_timeout_sec=70,
        )
    return make


def run_kerberos_asreq(cfg, source_factory, dc_factory=None,
                       token=None, password=None):
    if cfg.get("target") != "domain_controller":
        raise ValueError("Kerberos AS-REQ executor requires target: domain_controller")
    for field in ("dc_host", "dc_user", "dc_pass"):
        if not cfg.get(field):
            raise ValueError(f"Kerberos AS-REQ executor requires {field}")
    token = token or secrets.token_hex(4)
    if not _TOKEN.fullmatch(token):
        raise ValueError("Kerberos probe token must be eight lowercase hex characters")
    password = password or ("Zy!" + secrets.token_hex(12) + "aA9")
    dc_factory = dc_factory or _default_dc_factory(cfg)
    name, setup_ps, cleanup_ps, probe_ps = _account_scripts(token, password)
    attack_error = None
    try:
        response = dc_factory().run_ps(setup_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        line = next((x for x in stdout.splitlines()
                     if x.startswith(SETUP_MARKER + ":")), "")
        realm = line.split(":", 1)[1].strip() if line else ""
        if getattr(response, "status_code", 1) != 0 or not _REALM.fullmatch(realm):
            attack_error = f"Kerberos account setup failed: {stderr or 'no valid realm marker'}"
        else:
            packet = build_asreq(name, realm)
            response = source_factory().run_ps(_send_script(packet, cfg["dc_host"]))
            stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
            if getattr(response, "status_code", 1) != 0 or ATTACK_MARKER not in stdout:
                detail = stderr or stdout or "no AS-REP marker"
                attack_error = f"Kerberos AS-REQ failed: {detail[:500]}"
            else:
                response = dc_factory().run_ps(_audit_script(name))
                stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
                if getattr(response, "status_code", 1) != 0 or AUDIT_MARKER not in stdout:
                    detail = stderr or stdout or "no matching 4768 marker"
                    attack_error = f"Kerberos 4768 confirmation failed: {detail[:500]}"
    except Exception as exc:
        attack_error = f"Kerberos AS-REQ failed: {type(exc).__name__}: {exc}"

    errors = []
    try:
        response = dc_factory().run_ps(cleanup_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or CLEANUP_MARKER not in stdout:
            errors.append(f"Kerberos account cleanup was not proven: {stderr or 'no cleanup marker'}")
    except Exception as exc:
        errors.append(f"Kerberos account cleanup failed: {type(exc).__name__}: {exc}")
    try:
        response = dc_factory().run_ps(probe_ps)
        stdout, stderr = _text(response, "std_out"), _text(response, "std_err")
        if getattr(response, "status_code", 1) != 0 or stdout.strip() != PROBE_MARKER:
            errors.append(f"Kerberos cleanup probe found residual state: {stderr or stdout or 'empty response'}")
    except Exception as exc:
        errors.append(f"Kerberos cleanup probe failed: {type(exc).__name__}: {exc}")
    if errors:
        raise RuntimeError("; ".join(errors).replace(password, "[REDACTED]"))
    if attack_error:
        raise RuntimeError(attack_error.replace(password, "[REDACTED]"))
    return "DC non-loopback TCP/88 AS-REQ and matching 4768 confirmed; disposable account cleanup independently proven"


@register("kerberos_asreq")
def kerberos_asreq(usecase, ctx):
    start = _now()
    try:
        summary = run_kerberos_asreq(ctx.cfg or {}, ctx.winrm_factory)
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
