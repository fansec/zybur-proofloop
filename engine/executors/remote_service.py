# rules/engine/executors/remote_service.py
"""DIRECT_REMOTE_SERVICE: create + start a service remotely via impacket SCMR over TCP,
inside a macvlan netns so all packets originate from a unique source IP."""
from executors.registry import register
from executors._net import now_iso
from result import make_result

@register("remote_service")
def remote_service(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    source_ip = ctx.dedup.allocate(usecase["id"]) if ctx.dedup else None
    fw = ctx.firewall.open(session, "remote_service", ctx.cfg, remoteip=source_ip) if (ctx.firewall and session) else []
    cfg = ctx.cfg
    svc_name = "TestDetectionSvc"
    svc_bin = "cmd.exe /c echo DETECTION_TEST_SERVICE"
    start = now_iso()
    try:
        # Host, user and password reach the snippet on stdin (run_in_netns stdin_json), never as
        # text in it: nothing to quote, nothing in a process argument list, nothing in the file.
        code = f'''
import json, sys, time
from impacket.dcerpc.v5 import scmr, transport as impacket_transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

creds = json.load(sys.stdin)
host, user, passwd = creds["win_host"], creds["win_user"], creds["win_pass"]
svc_name = "{svc_name}"
svc_bin = "{svc_bin}"

print("Resolving SCM endpoint via EPM [src={source_ip}]")
string_binding = epm.hept_map(host, scmr.MSRPC_UUID_SCMR, protocol="ncacn_ip_tcp")
print(f"SCM binding: {{string_binding}}")
rpctransport = impacket_transport.DCERPCTransportFactory(string_binding)
rpctransport.setRemoteHost(host)
rpctransport.set_credentials(user, passwd, "", "", "")
dce = rpctransport.get_dce_rpc()
dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
dce.connect()
dce.bind(scmr.MSRPC_UUID_SCMR)
print(f"Connected to SCM via TCP [src={source_ip}]")

resp = scmr.hROpenSCManagerW(dce)
sc_handle = resp["lpScHandle"]
try:
    resp_open = scmr.hROpenServiceW(dce, sc_handle, svc_name)
    scmr.hRDeleteService(dce, resp_open["lpServiceHandle"])
    scmr.hRCloseServiceHandle(dce, resp_open["lpServiceHandle"])
    print(f"Cleaned up existing {{svc_name}}")
    time.sleep(1)
except Exception:
    pass

resp_create = scmr.hRCreateServiceW(
    dce, sc_handle, svc_name, svc_name,
    lpBinaryPathName=svc_bin,
    dwServiceType=scmr.SERVICE_WIN32_OWN_PROCESS,
    dwStartType=scmr.SERVICE_DEMAND_START,
)
svc_handle = resp_create["lpServiceHandle"]
print(f"Created service: {{svc_name}}")
try:
    scmr.hRStartServiceW(dce, svc_handle)
    print("Service started")
except Exception as e:
    print(f"Service start (expected): {{str(e)[:100]}}")
time.sleep(5)
try:
    scmr.hRDeleteService(dce, svc_handle)
    print("Service deleted")
except Exception:
    pass
scmr.hRCloseServiceHandle(dce, svc_handle)
scmr.hRCloseServiceHandle(dce, sc_handle)
dce.disconnect()
print("SUCCESS")
'''
        rc, stdout, stderr = ctx.dedup.run_in_netns(
            source_ip, code, timeout=60,
            stdin_json={"win_host": cfg["win_host"], "win_user": cfg["win_user"],
                        "win_pass": cfg["win_pass"]})
        end = now_iso()
        output = stdout + ("\n" + stderr if stderr else "")
        if "SUCCESS" in stdout:
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                               op_id="direct-rpc-tcp-service", output=f"{stdout} [src={source_ip}]")
        return make_result(usecase, f"RPC_TCP_FAIL: {output[:200]}", False,
                           attack_start=start, attack_end=end, output=output)
    except Exception as e:
        return make_result(usecase, f"RPC_TCP_FAIL: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall and session:
            ctx.firewall.close(session, fw)
