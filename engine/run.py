# rules/engine/run.py
"""The one runner CLI: select, execute, verify (6-state), ledger, emit-json.

Replaces run_caldera.py + run_p3a.py + run_p3b.py. Selection is by id/technique/
tactic/tag/all (no integer ranges); gate_selection then refuses what a use-case's
safety and network class do not allow without --allow-supervised / --allow-internet,
and a run verifies unless --no-verify. Verification correlates on rule_id and never
collapses "could not measure" into a zero (INCONCLUSIVE), nor "not yet due" into a
miss (PENDING), nor a successful PREVENTION into a detection failure. ES is the
Serverless project ES (from /.env.shared), never the CALDERA-box ES; a missing or
expired key yields INCONCLUSIVE, never an empty list.
"""
import os, sys

# OpenSSL legacy provider for NTLM MD4 - must be set before ssl/winrm init (ported from
# run_caldera.py). Guarded to __main__ so `import run` in tests never re-execs. The config
# file lives in a private per-user directory and is verified, never trusted (opensslconf.py).
if __name__ == "__main__":
    from opensslconf import ensure_openssl_conf
    _OPENSSL_CNF = ensure_openssl_conf()
    if os.environ.get("OPENSSL_CONF") != _OPENSSL_CNF:
        os.environ["OPENSSL_CONF"] = _OPENSSL_CNF
        os.execvp(sys.executable, [sys.executable] + sys.argv)

import json, argparse, time, functools
from collections import Counter
from datetime import datetime, timezone, timedelta

import executors.plugins  # noqa: F401  (registers all executor plugins)
from config import (load_config, config_for_target, missing_for_target, missing_lab_config,
                    LAB_KEYS_BY_EXECUTOR, VALID_TARGETS)
from loader import load_usecases, new_terms_memory_seconds
from ruleid import load_enabled_rules
from result import make_result, Result, Verdict
from caldera_client import CalderaClient
from dedup import DedupAllocator, malformed_names
from firewall import FirewallService
from ctx import Ctx
import executors.registry as registry
import verify as verifymod
import siem as siemmod
from siem.recorded import RecordedAdapter
import labhosts
import selector as selectmod
import ledger as ledgermod
from envshared import read_shared_env

HERE = os.path.dirname(os.path.abspath(__file__))
UC_DIR = os.path.join(HERE, "..", "usecases")
# RULES_EXPORT and LEDGER_FILE point a checkout that does not have the Zybur layout
# (the public export, a CI box) at its own rule export and ledger. Unset, nothing moves.
EXPORT = os.environ.get("RULES_EXPORT") or os.path.join(HERE, "..", "rules_export.ndjson")
LEDGER = os.environ.get("LEDGER_FILE") or os.path.join(HERE, "state", "ledger.jsonl")
STATE_IP = os.path.join(HERE, "state", ".dedup_ip_state.json")

# Minimum wall-clock gap, in seconds, between one detonation finishing and the
# next one starting ON THE SAME HOST, whether or not they share an invocation.
#
# verify.py's neighbour clamps (prev_end_bound / next_start_bound) separate
# back-to-back detonations by their engine-host attack_start/attack_end, but the
# alerts are placed in those windows by their WINDOWS-host behaviour time, and the
# two clocks are not synchronised. verify.CLOCK_SKEW_S (5s) is the tolerance for
# that skew, and its own comment states the invariant it relies on: the gap
# between two detonations is "far below" 5s only when it is much LARGER than 5s
# (5-25s measured 2026-07-29). On 2026-09-29 eight use-cases ran 0.5-1.1s apart,
# below the tolerance, so `prev_end_bound` clamped the mshta window at the
# previous detonation's end and cut off mshta's own Defend prevention (guest
# clock ~0.8s behind): a real PREVENTED was recorded as MISSED and VERIFY went
# red. Spacing detonations >= 2x CLOCK_SKEW_S apart makes the neighbour end
# non-binding, so the skew tolerance governs and the invariant the classifier was
# written against holds again. Enforced by _wait_for_detonation_gap, which reads
# the ledger because the nightly runs ONE use-case per invocation. 0 disables it.
DETONATION_GAP_S = float(os.environ.get("ZYBUR_DETONATION_GAP_S", "10"))


def select(usecases, args):
    """Pure selection by --id / --technique / --tactic / --tag / --all."""
    ids = getattr(args, "id", None)
    if ids:
        # argparse supplies a list for the CLI. Keep accepting the historical
        # string shape used by direct unit callers. Validation intentionally
        # passes one --id per nightly selection; without append semantics only
        # the final case detonated while the selector claimed K cases.
        wanted = ids if isinstance(ids, list) else [ids]
        by_id = {u["id"]: u for u in usecases}
        return [by_id[uid] for uid in dict.fromkeys(wanted) if uid in by_id]
    if getattr(args, "technique", None):
        return [u for u in usecases
                if args.technique in [u.get("technique"), *(u.get("additional_techniques") or [])]]
    if getattr(args, "tactic", None):
        return [u for u in usecases if u.get("tactic") == args.tactic]
    if getattr(args, "tag", None):
        return [u for u in usecases if args.tag in (u.get("tags") or [])]
    if getattr(args, "all", False):
        return list(usecases)
    return []


def gate_selection(selected, args):
    """Split a selection into the use-cases that may run and the lines that say why the rest may not.

    select() filters by id, technique, tactic, tag or "all" and never looked at a use-case's
    safety class, so a first `--all` ran the supervised ones unattended (external review of the
    public export, 2026-10-24). The class is the contract: `never` is refused whatever the flags
    say, `supervised` needs --allow-supervised, and a use-case declared `network: internet`
    needs --allow-internet (one that is both needs both). A class with no member prints no line.
    The lines carry ids only, never a command or a parameter. The loader requires `safety` and
    refuses any value but safe, supervised and never, so a selection holds only those three.
    """
    allow_supervised = getattr(args, "allow_supervised", False)
    allow_internet = getattr(args, "allow_internet", False)
    allowed, supervised, never, internet = [], [], [], []
    for u in selected:
        safety = u.get("safety")
        if safety == "never":
            never.append(u["id"])
            continue
        refused = False
        if safety == "supervised" and not allow_supervised:
            supervised.append(u["id"])
            refused = True
        if u.get("network", "lab") == "internet" and not allow_internet:
            internet.append(u["id"])
            refused = True
        if not refused:
            allowed.append(u)
    refusals = []
    if supervised:
        refusals.append(f"run: {len(supervised)} supervised use-case(s) need --allow-supervised: "
                        f"{' '.join(supervised)}")
    if never:
        refusals.append(f"run: {len(never)} never use-case(s) refused: {' '.join(never)}")
    if internet:
        refusals.append(f"run: {len(internet)} use-case(s) reach the internet and need "
                        f"--allow-internet: {' '.join(internet)}")
    return allowed, refusals


def verify_default(args):
    """A run verifies unless told not to.

    Until 2026-10-24 this fell back to `args.all`, so `--id X` without `--verify` detonated and
    wrote a null verdict into the ledger: a row that looks like a night's measurement and
    measured nothing. Not measuring is now the explicit choice (--no-verify).
    """
    return True if args.verify is None else args.verify


def _winrm_factory(cfg):
    def make():
        import winrm
        return winrm.Session(
            f"http://{cfg['win_host']}:5985/wsman",
            auth=(cfg["win_user"], cfg["win_pass"]), transport="ntlm",
            operation_timeout_sec=60, read_timeout_sec=70,
        )
    return make


def request_guest_shutdown(target, cfg=None, session_factory=None):
    """Request a clean Windows shutdown on one registered lab target."""
    base_cfg = cfg or load_config()
    projected = config_for_target(base_cfg, target)
    host = target_host(projected, target)
    missing = missing_for_target(base_cfg, target)
    if missing:
        return {"ok": False, "target": target, "host": host["name"],
                "error": f"missing target config: {', '.join(missing)}"}
    try:
        session = (session_factory or _winrm_factory(projected))()
        response = session.run_cmd("shutdown.exe", ["/s", "/t", "0"])
        if response.status_code != 0:
            error = (response.std_err or response.std_out or b"").decode(
                errors="replace").strip()[:500]
            return {"ok": False, "target": target, "host": host["name"],
                    "error": error or f"shutdown.exe exited {response.status_code}"}
        return {"ok": True, "target": target, "host": host["name"], "error": None}
    except Exception as exc:
        msg = str(exc)
        password = str(projected.get("win_pass") or "")
        if password:
            msg = msg.replace(password, "[REDACTED]")
        return {"ok": False, "target": target, "host": host["name"],
                "error": f"{type(exc).__name__}: {msg}"}


def _shared_env_paths():
    """Candidate shared-env locations (siemmod.shared_env_paths holds the rule and its history)."""
    return siemmod.shared_env_paths(os.environ)

def _read_shared_any(key):
    return siemmod.read_shared_any(key, os.environ)

def _es_credentials():
    """Serverless project ES url + key (never the CALDERA-box ES). Missing => INCONCLUSIVE.

    The lookup moved to siem.elastic_credentials on 2026-10-22 (the adapter needs the
    same one); `_read_shared_any` is passed in so this module's own seam keeps working.
    """
    return siemmod.elastic_credentials(os.environ, read=_read_shared_any)


def preflight(executors=None):
    """Name every configuration value a run would need and does not have.

    Prints exactly one line, `preflight: missing NAME NAME ...` (exit 1) or
    `preflight ok` (exit 0). Names only: the whole point is that it is safe to paste.
    ES_URL and ES_API_KEY are always required, because verification is the loop.
    """
    names = list(executors) if executors else sorted(registry.executor_names())
    unknown = [n for n in names if n not in LAB_KEYS_BY_EXECUTOR]
    if unknown:
        print("preflight: unknown executor " + " ".join(unknown), file=sys.stderr)
        return 2
    try:
        missing = set(missing_lab_config(load_config(), names))
    except labhosts.LabHostsError:
        # The target addresses come from the registry; an unreadable one is named
        # by the variable that points at it, not by a path.
        missing = {"LAB_HOSTS_FILE"}
    # Set but unusable counts as missing: the gate must not pass what the pool
    # refuses later, after PREPARE and the lab power-on. Only for executors that draw
    # from the pool, as with the unset case above.
    pool_names = {"DEDUP_SUBNET", "DEDUP_GATEWAY", "DEDUP_DENYLIST"}
    if any(pool_names & set(LAB_KEYS_BY_EXECUTOR[e]) for e in names):
        missing.update(malformed_names())
    es_url, api_key = _es_credentials()
    if not es_url:
        missing.add("ES_URL")
    if not api_key:
        missing.add("ES_API_KEY")
    if missing:
        print("preflight: missing " + " ".join(sorted(missing)))
        return 1
    print("preflight ok")
    return 0


def target_host(cfg=None, target="workstation"):
    """The lab host a detonation lands on, from validation/lab-hosts.json.

    Matched by the projected win_host address first. A role fallback is explicit
    and fail-loud, so adding a second range cannot silently label a DC detonation
    as the workstation (or vice versa).
    """
    hosts = labhosts.load_lab_hosts()
    cfg = cfg or config_for_target(load_config(), target)
    cfg_ip = cfg.get("win_host")
    for h in hosts:
        if cfg_ip and h.get("ip") == cfg_ip:
            actual_role = h.get("role", "workstation")
            if actual_role != target:
                raise labhosts.LabHostsError(
                    f"configured {target} target {cfg_ip} belongs to role {actual_role}")
            return {"name": h["name"], "id": h.get("host_id"),
                    "aliases": list(h.get("aliases") or [])}
    if cfg_ip:
        raise labhosts.LabHostsError(
            f"configured {target} target {cfg_ip} is not registered in lab-hosts.json")
    h = labhosts.host_for_role(target)
    return {"name": h["name"], "id": h.get("host_id"),
            "aliases": list(h.get("aliases") or [])}


def _enrich_host(host):
    """Attach canonical aliases to older ledger host identities.

    Rows written before aggregate ES|QL alert support contain only name/id. An
    alert grouped by winlog.computer_name carries neither of those fields, so its
    FQDN must be checked against the canonical aliases from lab-hosts.json.
    """
    host = dict(host or {})
    if not host:
        return host
    wanted_id = str(host.get("id") or "").lower()
    wanted_name = str(host.get("name") or "").lower()
    for candidate in labhosts.load_lab_hosts():
        candidate_names = [candidate.get("name"), *(candidate.get("aliases") or [])]
        same_id = (wanted_id and candidate.get("host_id")
                   and wanted_id == str(candidate["host_id"]).lower())
        same_name = (wanted_name and any(
            wanted_name == str(name or "").lower() for name in candidate_names))
        if same_id or same_name:
            host.setdefault("name", candidate["name"])
            host.setdefault("id", candidate.get("host_id"))
            host["aliases"] = list(candidate.get("aliases") or [])
            break
    return host


def _host_key(host):
    host = host or {}
    return (str(host.get("id") or "").lower(), str(host.get("name") or "").lower())


def _verify_by_host(results, rule_intervals, now=None):
    """Keep alert queries and neighbouring-window bounds isolated per target."""
    groups = {}
    for result in results:
        groups.setdefault(_host_key(result.host), []).append(result)
    for group in groups.values():
        verify_results(group, rule_intervals, now=now, host=group[0].host)
    return results


def _same_host(row_host, host):
    """Match a ledger row's host to the current one; unknown on either side is no match."""
    a, b = row_host or {}, host or {}
    if a.get("name") and b.get("name") and str(a["name"]).lower() == str(b["name"]).lower():
        return True
    return bool(a.get("id") and b.get("id") and str(a["id"]).lower() == str(b["id"]).lower())


def _ledger_starts(host):
    """attack_starts already on record for this host - detonations from OTHER
    invocations the same night bound this one's windows too (finding c0e223be080a)."""
    try:
        return [row.get("attack_start") for row in ledgermod.read(LEDGER)
                if row.get("attack_start") and _same_host(row.get("host"), host)]
    except Exception:
        return []


def _ledger_ends(host):
    """attack_ends already on record for this host, the mirror of _ledger_starts.

    They clamp the clock-skew tolerance on the window's LOWER bound: the tolerance
    may reach back toward a detonation's own start, never past the moment the
    PREVIOUS detonation finished. Same cross-invocation reason as the starts - the
    nightly loop detonates one use-case per engine invocation, so a sibling's end is
    usually only visible through the ledger.
    """
    try:
        return [row.get("attack_end") for row in ledgermod.read(LEDGER)
                if row.get("attack_end") and _same_host(row.get("host"), host)]
    except Exception:
        return []


def _ledger_detonations(host):
    """{attack_start, attack_end, rule_ids} for this host and attribution bounds.

    Starts alone cannot answer "could a later detonation have produced this alert" -
    that needs the later detonation's RULE IDS. And it has to come from the ledger
    for the same reason _ledger_starts does: the nightly detonates one use-case per
    engine invocation, so a sibling is only ever visible here.
    """
    try:
        return [{"attack_start": row.get("attack_start"),
                 "attack_end": row.get("attack_end"),
                 "rule_ids": row.get("rule_ids") or [],
                 "id": row.get("id")}
                for row in ledgermod.read(LEDGER)
                if row.get("attack_start") and _same_host(row.get("host"), host)]
    except Exception:
        return []


def _last_end_on_host(host, results):
    """Latest attack_end on this host, from this invocation's results AND the ledger.

    The ledger half is the load-bearing one: validation/run.js detonates ONE
    use-case per engine invocation (`d.detonate([id])`), so the previous
    detonation is only ever visible there - the same reason _ledger_ends exists.
    """
    ends = _ledger_ends(host) + [getattr(r, "attack_end", None) for r in results
                                 if _same_host(getattr(r, "host", None), host)]
    latest = None
    for end in ends:
        if not end:
            continue
        try:
            ts = verifymod._parse_ts(end)
        except Exception:
            continue
        if latest is None or ts > latest:
            latest = ts
    return latest


def _wait_for_detonation_gap(host, results, gap_s=None, now=None, sleep=time.sleep):
    """Sleep until DETONATION_GAP_S has passed since this host's last detonation ended.

    49bbb56 slept only between detonations of ONE invocation, gated on an
    in-process counter. The nightly starts a fresh engine per use-case, so that
    counter was always 0 and the sleep never ran: on 2026-09-30, the first night
    on the pinned fix, the production detonations were still 0.85-1.87s apart.
    Measuring from the ledger covers both paths. Other hosts are not waited for,
    because the verifier's neighbour clamps are per host (_verify_by_host,
    _ledger_ends). Returns the seconds slept.
    """
    gap = DETONATION_GAP_S if gap_s is None else gap_s
    if gap <= 0:
        return 0.0
    last = _last_end_on_host(host, results)
    if last is None:
        return 0.0
    now = now or datetime.now(timezone.utc)
    # Capped at the gap: an end stamped in the future is bad data, not a reason
    # to hold the lab for longer than the invariant needs.
    wait = min(gap, gap - (now - last).total_seconds())
    if wait <= 0:
        return 0.0
    sleep(wait)
    return wait


def _warn_if_detonations_too_close(results, gap_s=None):
    """Loud stderr warning if two detonations landed inside the skew tolerance.

    The invariant `DETONATION_GAP_S` restores is what the verifier's neighbour
    clamps assume. If it is ever violated again - the gap env is set to 0, a
    handler stalls - a real prevention can be clamped onto the wrong row and read
    as MISSED, silently. This makes that condition visible instead, the same
    "make the silence loud" pattern the rest of the loop uses. It never changes a
    verdict; it only reports. ⚠ It sees THIS invocation's results only, and
    validation/lib/live-deps.js runEngine drops the engine's stderr on success,
    so on the nightly path (one use-case per invocation) it can never fire. The
    proof there is the ledger's attack_end -> next attack_start gaps.
    """
    floor = verifymod.CLOCK_SKEW_S if gap_s is None else gap_s
    starts = []
    for r in results:
        if not getattr(r, "attack_start", None):
            continue
        try:
            starts.append((verifymod._parse_ts(r.attack_start), r))
        except Exception:
            continue
    starts.sort(key=lambda x: x[0])
    for (prev_ts, prev_r), (ts, r) in zip(starts, starts[1:]):
        gap = (ts - prev_ts).total_seconds()
        if gap < floor:
            print(f"# WARNING detonations {prev_r.id} and {r.id} started "
                  f"{gap:.2f}s apart, inside the {floor:.0f}s clock-skew tolerance - "
                  f"neighbour attribution may be wrong (see run.DETONATION_GAP_S)",
                  file=sys.stderr)


def verify_results(results, rule_intervals, now=None, host=None, extra_starts=None,
                   extra_ends=None, extra_detonations=None, siem=None, enrich=True,
                   rule_memory=None, rule_hashes=None):
    """One SIEM query answers both questions: did MY rule fire, and what else fired here.

    `siem` is a siem.SiemAdapter. Left out, the Elastic credentials of today's lookup
    decide (none: alerts is None and every verdict that needs one is INCONCLUSIVE), unless
    `SIEM` names another adapter. A replay passes a RecordedAdapter and needs no
    credential, no lab registry (`enrich=False`: the recorded host already carries its
    aliases) and no rule export (`rule_memory` is the recorded {rule_id: memory} map and
    `rule_hashes` the {rule_id: query hash} map; {} leaves the hashes empty).
    """
    now = now or datetime.now(timezone.utc)
    if siem is None and (os.environ.get("SIEM") or "elastic").strip().lower() != "elastic":
        siem = siemmod.adapter_from_env()
    if siem is not None:
        es_url = api_key = None
    else:
        es_url, api_key = _es_credentials()
    rule_ids = sorted({rid for r in results for rid in r.rule_ids})
    starts = [r.attack_start for r in results if r.attack_start]
    since = min(starts) if starts else now.isoformat()
    if enrich:
        for result in results:
            result.host = _enrich_host(result.host)
        host = _enrich_host(host)
    else:
        host = dict(host or {})
    names = [host.get("name"), *(host.get("aliases") or [])]
    hosts = {"names": list(dict.fromkeys(name for name in names if name)),
             "ids": [host["id"]] if host.get("id") else []}
    alerts = None
    if rule_ids or hosts["names"] or hosts["ids"]:
        if siem is not None:
            alerts = siem.query_alerts(rule_ids, since, hosts)
        elif es_url and api_key:
            alerts = verifymod.query_alerts(es_url, api_key, rule_ids, since, hosts)
    if extra_starts is None:
        extra_starts = _ledger_starts(host)
    if extra_ends is None:
        extra_ends = _ledger_ends(host)
    if extra_detonations is None:
        extra_detonations = _ledger_detonations(host)
    all_starts = starts + [s for s in extra_starts if s]
    # A detonation's OWN end is excluded by prev_end_bound's strict `< mine`, so
    # this list can carry every end without a row clamping itself.
    all_ends = [r.attack_end for r in results if r.attack_end] + [e for e in extra_ends if e]
    # Who could this window actually rob? Built from the detonations themselves, not
    # from their start times alone: the `until` clamp only has work to do when a
    # LATER detonation targets the SAME rule, and that is rare enough to measure
    # (176 of 177 target rule ids belong to one use-case). See
    # verify.contested_rule_ids.
    detonations = [{"attack_start": x.attack_start, "attack_end": x.attack_end,
                    "rule_ids": x.rule_ids} for x in results
             if x.attack_start] + [d for d in (extra_detonations or []) if d.get("attack_start")]
    for r in results:
        # The successor's floor, not its start (2026-10-14): the successor's window
        # reaches CLOCK_SKEW_S before its start, so ending here at its start stored
        # every alert of those 5s on both rows. See verify.attribution_until. The
        # re-check paths reach this loop too (_recheck_rows -> _verify_by_host), with
        # the ledger's starts in all_starts, so a re-check applies the same bound.
        until = verifymod.attribution_until(r.attack_start, r.attack_end, all_starts)
        since = verifymod.prev_end_bound(r.attack_start, all_ends)
        contested = verifymod.contested_rule_ids(r.attack_start, r.rule_ids, detonations)
        target_since = verifymod.previous_rule_end_bounds(
            r.attack_start, r.rule_ids, detonations)
        r.verdict = verifymod.classify(r, alerts, now, rule_intervals, until=until, since=since,
                                       contested=contested, target_since=target_since)
        r.co_firing = verifymod.co_firing_for(r, alerts, rule_intervals, until=until, since=since,
                                              contested=contested, target_since=target_since)
        if r.verdict == Verdict.MISSED:
            _apply_memory_check(r, host, hosts, es_url, api_key, detonations,
                                siem=siem, memory=rule_memory)
        if r.verdict == Verdict.DETECTED:
            # Same window classify() just used, via verify.latency_for. This used to
            # re-filter `alerts` here with a strict `behavior_ts >= attack_start`,
            # a second and stricter floor than the classifier's, so a row could be
            # DETECTED with latency None - see latency_for's docstring.
            r.latency_s = verifymod.latency_for(r, alerts, rule_intervals, until=until,
                                                since=since, contested=contested,
                                                target_since=target_since)
            # P-D3: the ledger records the rule version it proved, the same way
            # co_firing is threaded (computed here, carried on the Result object,
            # surfaced in _ledger_row).
            r.rule_versions = verifymod.rule_versions_for(r, alerts, rule_intervals, until=until,
                                                          since=since, contested=contested,
                                                          target_since=target_since)
            r.rule_query_hashes = _query_hashes_for(r.rule_versions, by_id=rule_hashes)
    return results


# ---------------------------------------------------------------------------
# Record a night, replay it. A recorded night is the verifier's whole input for one host:
# the pre-verify results, the neighbouring detonations, the rule intervals, the clock and
# the alerts the SIEM held. With those, the verdicts come out the same on any machine,
# without a lab, a SIEM or a credential.

REPLAY_SCHEMA_VERSION = 1
# What a result carries before verification. Everything else is recomputed by the replay,
# so a fixture can never smuggle a verdict in.
_POST_VERIFY_BLANKS = {"verdict": None, "latency_s": None, "co_firing": [],
                       "rule_versions": {}, "rule_query_hashes": {}, "verdict_reason": None}
# Free text and identifiers that came from the lab. Nothing in verify.py reads them (it
# reads rule_ids, the window, the host and `executed`), and a fixture is meant to be shared.
_LAB_TEXT_BLANKS = {"output": "", "op_id": "", "nonce": None}
# The ledger rows that bound a night's windows need only reach a little before its first
# detonation: a window never reaches back past the previous end, and the clock-skew
# tolerance is seconds.
RECORD_LOOKBACK = timedelta(hours=1)
RECORD_NOW_MARGIN = timedelta(hours=1)


def replay(path, out=None):
    """Re-verify a recorded night; print one line per result and whether the verdicts match.

    Exit 0 when every verdict matches, 1 when one differs, 2 when the fixture cannot be
    read, is not the recorded shape, or holds no results or no expectations.
    """
    out = out or sys.stdout
    try:
        with open(os.path.join(path, "inputs.json")) as f:
            inputs = json.load(f)
        with open(os.path.join(path, "expected.json")) as f:
            expected = json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        print(f"replay: cannot read {path}: {type(e).__name__}", file=sys.stderr)
        return 2
    # A fixture that is not the recorded shape is unreadable (2), the same as a missing file:
    # exit 1 stays "a verdict did not match", and an empty directory must not pass the gate.
    # Everything that touches fixture content sits in this one try, the verification
    # included, so a hostile or hand-edited field cannot end in a traceback with exit 1.
    try:
        if not isinstance(inputs, dict):
            raise ValueError("inputs.json is not an object")
        if inputs.get("schema_version") != REPLAY_SCHEMA_VERSION:
            print(f"replay: unsupported schema_version {inputs.get('schema_version')!r} "
                  f"(this engine reads {REPLAY_SCHEMA_VERSION})", file=sys.stderr)
            return 2
        results = [Result(**{**row, **_POST_VERIFY_BLANKS}) for row in inputs["results"]]
        if not results or not expected or not isinstance(expected, dict):
            raise ValueError("no results or no expected verdicts")
        now = verifymod._parse_ts(inputs["now"])
        rule_intervals, host = inputs["rule_intervals"], inputs["host"]
        verify_results(results, rule_intervals, now=now,
                       host=host, extra_starts=inputs.get("extra_starts") or [],
                       extra_ends=inputs.get("extra_ends") or [],
                       extra_detonations=inputs.get("extra_detonations") or [],
                       siem=RecordedAdapter(path), enrich=False,
                       rule_memory=inputs.get("rule_memory") or {}, rule_hashes={})
    except Exception as e:  # noqa: BLE001 - any failure on fixture content is a bad fixture
        print(f"replay: malformed fixture {path}: {type(e).__name__}", file=sys.stderr)
        return 2
    for r in results:
        latency = "n/a" if r.latency_s is None else str(int(round(r.latency_s)))
        print(f"{r.verdict.name}\t{r.id}\t{latency}", file=out)
    got = {r.id: r.verdict.name for r in results}
    ids = set(got) | set(expected)
    match = sum(1 for i in ids if got.get(i) == expected.get(i))
    print(f"replay: {match} of {len(ids)} verdicts match expected.json", file=out)
    return 0 if match == len(ids) else 1


def _record_inputs(night, host_results, ledger_rows):
    """Build one host's replay inputs and expectations from a night's result files and the ledger.

    `host_results` is [(result dict as the nightly wrote it, [ledger rows of that detonation])].
    The expectation is the LAST ledger row of each detonation, the verdict the night ended with.
    """
    host = host_results[0][0].get("host") or {}
    finals = {}
    stamps = []
    for r, rows in host_results:
        final = rows[-1]
        finals[r["id"]] = final["verdict"]
        stamps += [verifymod._parse_ts(x.get("rechecked_at") or x.get("run_ts") or x["attack_start"]) for x in rows]
    now = max(stamps) + RECORD_NOW_MARGIN
    own = {(r["id"], r["attack_start"]) for r, _ in host_results}
    floor = min(verifymod._parse_ts(r["attack_start"]) for r, _ in host_results) - RECORD_LOOKBACK
    neighbours = [row for row in ledger_rows
                  if row.get("attack_start") and _same_host(row.get("host"), host)
                  and (row["id"], row["attack_start"]) not in own
                  and verifymod._parse_ts(row["attack_start"]) >= floor
                  and verifymod._parse_ts(row.get("run_ts") or row["attack_start"]) <= now]
    results = []
    for r, _ in host_results:
        row = {k: r[k] for k in Result.__dataclass_fields__ if k in r}
        row.update(_POST_VERIFY_BLANKS)
        row.update(_LAB_TEXT_BLANKS)
        row.pop("verdict_reason", None)
        results.append(row)
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "night": night,
        "now": now.isoformat(),
        "host": {"name": host.get("name"), "id": host.get("id"),
                 "aliases": list(host.get("aliases") or [])},
        "rule_intervals": {},
        "results": results,
        "extra_starts": [x["attack_start"] for x in neighbours],
        "extra_ends": [x["attack_end"] for x in neighbours if x.get("attack_end")],
        "extra_detonations": [{"attack_start": x["attack_start"], "attack_end": x.get("attack_end"),
                               "rule_ids": x.get("rule_ids") or [], "id": x.get("id")}
                              for x in neighbours],
    }, finals


def record_night(night, out_dir, only_host=None, adapter=None, results_dir=None):
    """Write a replay fixture per host for one night. READ-ONLY: one search per host.

    Reads the night's result files and the ledger, asks the SIEM once per host for the
    alerts of the night's window, and writes inputs.json, alerts.json and expected.json
    under `out_dir/<host name>/`. Detonates nothing, touches no lab host, and writes
    neither the ledger nor rules/results.
    """
    try:
        day = datetime.strptime(night, "%Y-%m-%d")
    except ValueError:
        print("record-night: the night is YYYY-MM-DD", file=sys.stderr)
        return 2
    results_dir = results_dir or os.environ.get("RESULTS_DIR") or os.path.join(HERE, "..", "results")
    files = sorted(f for f in os.listdir(results_dir)
                   if f.startswith(f"usecases_{day:%Y%m%d}T") and f.endswith(".json"))
    if not files:
        print(f"record-night: no result files for {night} in {os.path.basename(os.path.abspath(results_dir))}",
              file=sys.stderr)
        return 1
    ledger_rows = ledgermod.read(LEDGER)
    by_host = {}
    for name in files:
        with open(os.path.join(results_dir, name)) as f:
            for r in json.load(f):
                if not (r.get("executed") and r.get("attack_start")):
                    continue
                rows = [x for x in ledger_rows if x.get("id") == r["id"]
                        and x.get("attack_start") == r["attack_start"]]
                if not rows:
                    print(f"record-night: {r['id']} has no ledger row, left out", file=sys.stderr)
                    continue
                by_host.setdefault(_host_key(r.get("host")), []).append((r, rows))
    if only_host:
        by_host = {k: v for k, v in by_host.items()
                   if only_host.lower() in (k[1], *[a.lower() for a in (v[0][0].get("host") or {}).get("aliases") or []])}
    if not by_host:
        print("record-night: nothing to record", file=sys.stderr)
        return 1
    adapter = adapter or siemmod.adapter_from_env()
    if getattr(adapter, "name", None) != "elastic" or not (adapter.api_key and adapter.es_url):
        print("record-night: needs a live SIEM (ES_URL and ES_API_KEY)", file=sys.stderr)
        return 2
    enabled = load_enabled_rules(EXPORT)
    intervals = {v["rule_id"]: v["interval"] for v in enabled.values()}
    try:
        memory_all = _rule_memory_by_rule_id(EXPORT)
    except OSError:
        memory_all = {}
    for host_results in by_host.values():
        inputs, finals = _record_inputs(night, host_results, ledger_rows)
        rule_ids = sorted({rid for r in inputs["results"] for rid in r["rule_ids"]})
        inputs["rule_intervals"] = {rid: intervals[rid] for rid in rule_ids if rid in intervals}
        memory = {rid: memory_all[rid] for rid in rule_ids if rid in memory_all}
        if memory:
            inputs["rule_memory"] = memory
        host = _enrich_host(inputs["host"])
        names = [n for n in [host.get("name"), *(host.get("aliases") or [])] if n]
        hosts = {"names": list(dict.fromkeys(names)), "ids": [host["id"]] if host.get("id") else []}
        since = min(verifymod._parse_ts(r["attack_start"]) for r in inputs["results"])
        if memory:
            # A new-terms rule's memory is judged from alerts before the detonation.
            since -= timedelta(seconds=max(m["window_s"] for m in memory.values()))
        alerts = adapter.query_alerts(rule_ids, since.isoformat(), hosts)
        if alerts is None:
            print(f"record-night: the SIEM could not be read for {host.get('name')}", file=sys.stderr)
            return 1
        # The query has no upper bound, so it also returns what landed after the night's
        # last re-check: the next night's alerts. The classifier never saw those.
        end = verifymod._parse_ts(inputs["now"])
        alerts = [a for a in alerts if verifymod._parse_ts(a["@timestamp"]) <= end]
        target = os.path.join(out_dir, str(host.get("name") or "host").lower())
        os.makedirs(target, exist_ok=True)
        for fname, doc in (("inputs.json", inputs), ("alerts.json", alerts), ("expected.json", finals)):
            with open(os.path.join(target, fname), "w") as f:
                json.dump(doc, f, indent=2, sort_keys=(fname != "inputs.json"))
                f.write("\n")
        print(f"record-night: {target}: {len(inputs['results'])} results, {len(alerts)} alerts")
    return 0


@functools.lru_cache(maxsize=4)
def _rule_memory_by_rule_id(export_path):
    """{rule_id: {name, fields, window, window_s}} for the enabled new-terms rules."""
    out = {}
    for name, v in load_enabled_rules(export_path).items():
        window_s = new_terms_memory_seconds(v)
        if window_s:
            out[v["rule_id"]] = {"name": name, "fields": list(v.get("new_terms_fields") or []),
                                 "window": v.get("history_window_start"), "window_s": window_s}
    return out


def _apply_memory_check(r, host, hosts, es_url, api_key, detonations, siem=None, memory=None):
    """A MISSED against a new-terms rule whose memory already held this host is not a
    detection gap: the rule could not fire. INCONCLUSIVE, and the row says why.

    A host-keyed new-terms rule cannot alert again until its memory window expires.
    Without this check, an intentional suppression can be misreported as a detection
    gap and immediately re-queued inside the same memory window. Only a host-bound
    rule (verify.memory_is_host_bound) is judged here; the
    evidence is the ledger (any use-case naming the rule on this host inside the
    window) and the rule's own alerts (one more, host-scoped, windowed ES read, only
    on this path). A sibling that matched without alerting leaves no record and the
    MISSED stands: a limitation, stated in verify.memory_evidence.
    """
    if memory is None:
        memory = _rule_memory_by_rule_id(EXPORT)
    for rid in r.rule_ids:
        m = memory.get(rid)
        if not m or not verifymod.memory_is_host_bound(m["fields"]):
            continue
        prior_alerts = None
        if (siem is not None or (es_url and api_key)) and r.attack_start:
            since = (verifymod._parse_ts(r.attack_start)
                     - timedelta(seconds=m["window_s"])).isoformat()
            if siem is not None:
                prior_alerts = siem.query_alerts([rid], since, hosts)
            else:
                prior_alerts = verifymod.query_alerts(es_url, api_key, [rid], since, hosts)
        evidence = verifymod.memory_evidence(r, rid, m["window_s"], prior_alerts, detonations)
        if evidence:
            r.verdict = Verdict.INCONCLUSIVE
            r.verdict_reason = verifymod.memory_reason(
                m["name"], rid, m["fields"], m["window"],
                (host or {}).get("name") or "this host", evidence)
            return


@functools.lru_cache(maxsize=4)
def _query_hash_by_rule_id(export_path):
    return {v["rule_id"]: v["query_hash"]
            for v in load_enabled_rules(export_path).values() if v.get("query_hash")}


def _query_hashes_for(rule_versions, by_id=None):
    """{rule_id: query hash} for the proven rules, from the same committed export the
    engine resolves rule names against. A rule_id the export does not carry (a managed
    rule) gets NO key: the reader treats absent as unmeasured, and a null would read as
    a hash of something."""
    if by_id is None:
        by_id = _query_hash_by_rule_id(EXPORT)
    return {rid: by_id[rid] for rid in rule_versions if rid in by_id}



def _apply_miss_classes(results, originals=None):
    """Set Result.miss_class on every MISSED, from the ledger rows written BEFORE this detonation.

    `originals` is None on the detonation path, where tonight's rows are not on file yet (the
    caller classifies before it appends), and the list of the ledger rows being re-checked on
    the re-check paths, where the row under re-check and its siblings ARE on file and are cut
    off by run_ts: with tonight's own MISSED in the history a first miss reads as the second
    one and the night goes red over one failure.

    A ledger that cannot be read or placed in time leaves miss_class None and says so. It must
    never become an empty history: [] means "never detected", the loop treats that as a pass,
    and an unreadable file would turn every MISSED green.
    """
    todo = [(i, r) for i, r in enumerate(results) if r.verdict is Verdict.MISSED]
    if not todo:
        return
    try:
        if not os.path.exists(LEDGER):
            raise OSError("the ledger file does not exist")
        rows = ledgermod.read(LEDGER)
    except Exception as e:
        print(f"engine: miss_class not set, the ledger cannot be read ({type(e).__name__}: {e}); "
              "a MISSED without a class stays red", file=sys.stderr)
        return
    for i, r in todo:
        try:
            mine = [x for x in rows if x.get("id") == r.id]
            if originals is not None:
                mine = selectmod.prior_finals(mine, originals[i].get("run_ts"))
            r.miss_class = selectmod.miss_class(mine, r.verdict.name)
        except Exception as e:
            print(f"engine: miss_class not set for {r.id} ({type(e).__name__}: {e}); "
                  "a MISSED without a class stays red", file=sys.stderr)


def _recheck_report(results, as_json, label="PENDING", written=None):
    """What the caller learns from a re-check pass.

    The counts line is for a human reading cron output. `as_json` is for
    validation's SETTLE stage, which polls this until nothing is PENDING and then
    rewrites its VERIFY gate from the per-id verdicts - counts alone cannot say
    WHICH use-case resolved to what, and the gate records one check per id.
    """
    counts = Counter(r.verdict.name if r.verdict else "NONE" for r in results)
    if as_json:
        print(json.dumps({
            "rechecked": len(results),
            "pending": counts.get(Verdict.PENDING.name, 0),
            "written": len(results) if written is None else written,
            "results": [{"id": r.id,
                         "verdict": r.verdict.name if r.verdict else None,
                         "latency_s": r.latency_s,
                         **({"miss_class": r.miss_class} if getattr(r, "miss_class", None) else {})}
                        for r in results],
        }))
    else:
        tail = "" if written is None else f", {written} changed"
        print(f"rechecked {len(results)} {label} row(s): {dict(counts)}{tail}")


# How far back --recheck-missed will look, and the wall it must never cross.
#
# A re-check answers "is the alert there NOW". Ask that of a detonation whose
# alerts have aged out of Elastic and the answer is a confident, wrong MISSED: the
# absence of a document that retention deleted is not evidence about a detection.
# Live retention measured 31d (inherited Serverless cap), so the ceiling is well
# inside it and the default is well inside the ceiling.
RECHECK_MISSED_DAYS = 7
RECHECK_MISSED_MAX_DAYS = 21


def missed_rows_within(rows, now, days):
    """Standing-MISSED rows young enough that Elastic can still answer for them.

    The age test is the whole safety property of --recheck-missed, which is why it
    is a function rather than a line: past retention, "no alert" stops meaning
    "the rule did not fire" and starts meaning "the document was deleted", and a
    re-check would confirm a false MISSED with total confidence.

    A row with no attack_start is EXCLUDED. Its age cannot be established, and an
    unknown age must not read as young.
    """
    floor = (now - timedelta(days=days)).isoformat()
    return [r for r in selectmod.rows_with_verdict(rows, ("MISSED",))
            if (r.get("attack_start") or "") >= floor]


def recheck_missed(usecases, rule_intervals, now=None, as_json=False, days=RECHECK_MISSED_DAYS):
    """Re-verify recent MISSED rows. Detonates nothing. Writes only what CHANGED.

    A MISSED was terminal: nothing re-read it, so an alert that arrived after the
    20-minute SETTLE poll could never correct the record. That is not a rare edge.
    Measured 2026-08-05 against live Elastic, over the 19 MISSED rows still inside
    retention, EIGHT had their own target rule's alert sitting in the due window.
    Seven of the eight were ingest latency alone - the behavior time was in the
    window, the alert simply had not been written yet when the loop stopped
    looking. In the motivating regression, the slowest alert arrived several hours late.
    The nightly reported all of them to the founder as detection failures.

    `validation/run.js`'s DRAIN comment already named this in 2026-07-28 - "the rule
    fired CORRECTLY at 09:41:39, forty minutes after the engine had already written
    MISSED, and a MISSED row is never re-checked" - and DRAIN only stops teardown
    STRANDING telemetry. It cannot make Elastic ingest faster, so it was never the
    whole fix.

    Unchanged verdicts are NOT written. A pass that re-confirms eight MISSED rows
    must leave the ledger the size it found it, or the append-only record grows by
    the size of the standing problem every night and `index_ledger`'s verdict
    history fills with restatements of one measurement.
    """
    now = now or datetime.now(timezone.utc)
    days = max(1, min(int(days), RECHECK_MISSED_MAX_DAYS))
    missed = missed_rows_within(ledgermod.read(LEDGER), now, days)
    return _recheck_rows(missed, usecases, rule_intervals, now, as_json,
                         label="MISSED", only_changed=True,
                         empty_note=f"no MISSED rows inside the last {days}d to re-check")


def recheck_pending(usecases, rule_intervals, now=None, as_json=False):
    """Re-verify every ledger row still sitting at PENDING. Detonates nothing.

    This is what makes a 12-hour rule measurable by a 90-minute loop. Both of the
    2026-07-25 runs are still PENDING in the ledger because nothing ever looked
    again.

    The new row carries the ORIGINAL run_ts plus `rechecked_at`, so a re-check
    supersedes the verdict without inventing a second detonation. Zero safety
    surface: no power-on, no CALDERA, no WinRM, only an ES read.
    """
    now = now or datetime.now(timezone.utc)
    rows = ledgermod.read(LEDGER)
    return _recheck_rows(selectmod.pending_rows(rows), usecases, rule_intervals, now, as_json,
                         label="PENDING", only_changed=False,
                         empty_note="no PENDING rows to re-check")


def _recheck_rows(rows_to_check, usecases, rule_intervals, now, as_json, label,
                  only_changed, empty_note):
    """The shared re-check body. Same ES read, same supersede-in-place ledger row."""
    if not rows_to_check:
        # An empty pass is the SUCCESS condition for validation's settle poll, so it
        # must be machine-readable in exactly the same shape as a non-empty one.
        _recheck_report([], as_json)
        if not as_json:
            print(empty_note)
        return 0
    by_id = {u["id"]: u for u in usecases}
    results, originals = [], []
    for row in rows_to_check:
        uc = by_id.get(row["id"])
        if uc is None:
            # The use-case was renamed or removed. Say so; do not silently drop a
            # row that is still the only record of an unmeasured detonation.
            print(f"SKIP {row['id']}: no longer in the registry", file=sys.stderr)
            continue
        r = make_result(uc, "RECHECK", True,
                        attack_start=row.get("attack_start"),
                        attack_end=row.get("attack_end") or row.get("attack_start"))
        r.host = row.get("host")
        results.append(r)
        originals.append(row)
    if not results:
        _recheck_report([], as_json)
        return 0
    # Rows written before the host field existed carry none. Backfill from the
    # configured range rather than writing null forward: a re-check that loses the
    # host also loses co_firing, since co-firing is scoped to the target host.
    # A key without a URL is a half-configured verifier: every row would come back
    # INCONCLUSIVE and be written over the real MISSED or PENDING one, with exit 0.
    # (Before 2026-10-22 a default URL hid this.) No key at all stays allowed, as above.
    es_url, api_key = _es_credentials()
    if api_key and not es_url:
        print("engine: ES key is set but ES_URL is not; refusing to re-check rows "
              "without a place to ask", file=sys.stderr)
        return 2
    base_cfg = load_config()
    for r, original in zip(results, originals):
        if not r.host:
            uc = by_id.get(original["id"]) or {}
            target = uc.get("target", "workstation")
            r.host = target_host(config_for_target(base_cfg, target), target)
    _verify_by_host(results, rule_intervals, now=now)
    _apply_miss_classes(results, originals)
    writes = [(r, o) for r, o in zip(results, originals)
              if not only_changed
              or (r.verdict.name if r.verdict else None) != o.get("verdict")]
    if writes:
        ledgermod.append(LEDGER, [_recheck_ledger_row(r, o, now) for r, o in writes])
    _recheck_report(results, as_json, label=label, written=len(writes))
    return 0


def _recheck_ledger_row(r, original, now):
    """One re-check ledger entry: the first-run fields plus when it was re-checked.

    `rule_versions` rides along (D1, 2026-10-20): the nightly's DETECTED verdicts are all
    re-check rows (first-run rows are PENDING), so a row without it made every proof's
    proven_version `unknown` and P-D3 staleness could never mark anything.
    `rule_query_hashes` rides along for the same reason: staleness is judged by the query.
    """
    return {
        "id": r.id, "rule_ids": r.rule_ids, "run_ts": original.get("run_ts"), "host": r.host,
        "verdict": r.verdict.name if r.verdict else None,
        "latency_s": r.latency_s, "attack_start": r.attack_start,
        "attack_end": r.attack_end, "co_firing": r.co_firing,
        "rule_versions": r.rule_versions,
        "rule_query_hashes": r.rule_query_hashes,
        "rechecked_at": now.isoformat(),
        **({"verdict_reason": r.verdict_reason} if getattr(r, "verdict_reason", None) else {}),
        **({"miss_class": r.miss_class} if getattr(r, "miss_class", None) else {}),
    }


def _ledger_row(r, run_ts):
    """One ledger entry. ABORT rows carry WHY.

    An ABORT means the attack never ran, so the row holds no measurement and the
    only thing worth recording is the reason. `validation/lib/attack-report.js`
    has read `row.error` since it was written; nothing ever wrote it, so three
    nights of the same fake-CAPTCHA delivery failure (2026-07-29, 2026-08-16,
    2026-09-04) each reported "ABORT with no error recorded" and the cause stayed
    in a /tmp log nobody read. `status` is the executor's own label, never its
    output, so no payload or credential text can ride along.
    """
    row = {
        "id": r.id, "rule_ids": r.rule_ids, "run_ts": run_ts, "host": r.host,
        "verdict": r.verdict.name if r.verdict else None,
        "latency_s": r.latency_s, "attack_start": r.attack_start,
        "attack_end": r.attack_end, "co_firing": r.co_firing,
        "rule_versions": r.rule_versions,
        "rule_query_hashes": r.rule_query_hashes,
    }
    if not r.executed and r.status:
        row["error"] = r.status
    if getattr(r, "verdict_reason", None):
        row["verdict_reason"] = r.verdict_reason
    if getattr(r, "miss_class", None):
        row["miss_class"] = r.miss_class
    return row


def _write_results(results, cfg):
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = cfg["results_dir"]
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"usecases_{ts}.json")
    with open(path, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)
    return path


def _cleanup_caldera(caldera, usecase_ids):
    """Delete abilities/adversaries/operations named for any known use-case id."""
    ids = set(usecase_ids)
    for a in caldera.api("GET", "/api/v2/abilities") or []:
        if a.get("name") in ids:
            caldera.api("DELETE", f"/api/v2/abilities/{a['ability_id']}")
    for a in caldera.api("GET", "/api/v2/adversaries") or []:
        if a.get("name") in ids:
            caldera.api("DELETE", f"/api/v2/adversaries/{a['adversary_id']}")
    for o in caldera.api("GET", "/api/v2/operations") or []:
        if o.get("name") in ids:
            caldera.api("DELETE", f"/api/v2/operations/{o['id']}")


def _build_parser():
    ap = argparse.ArgumentParser(description="Detection use-case engine runner")
    ap.add_argument("--id", action="append",
                    help="select one use-case; repeat to execute an ordered batch")
    ap.add_argument("--technique")
    ap.add_argument("--tactic")
    ap.add_argument("--tag")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--emit-json", metavar="PATH", help="write the Result array (validation-consumable)")
    ap.add_argument("--verify", dest="verify", action="store_true", default=None,
                    help="verify the detonations against the SIEM (the default; stated so a script can say it)")
    ap.add_argument("--no-verify", dest="verify", action="store_false",
                    help="detonate without verifying: the ledger rows carry no verdict")
    ap.add_argument("--allow-supervised", action="store_true",
                    help="also run `supervised` use-cases (someone should be watching); "
                         "without it a selection that contains one is refused")
    ap.add_argument("--allow-internet", action="store_true",
                    help="also run use-cases declared `network: internet` (they reach a public "
                         "address); without it a selection that contains one is refused")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--include-draft", action="store_true")
    ap.add_argument("--select-nightly", type=int, metavar="K",
                    help="print the deterministic nightly selection and detonate nothing")
    ap.add_argument("--recheck-pending", action="store_true",
                    help="re-verify PENDING ledger rows; no detonation, no power-on")
    ap.add_argument("--recheck-missed", nargs="?", type=int, const=RECHECK_MISSED_DAYS,
                    metavar="DAYS",
                    help=f"re-verify MISSED ledger rows from the last DAYS days "
                         f"(default {RECHECK_MISSED_DAYS}, max {RECHECK_MISSED_MAX_DAYS}); "
                         "writes only the verdicts that CHANGED; no detonation, no power-on")
    ap.add_argument("--json", action="store_true", help="machine-readable output for --select-nightly and --recheck-pending")
    ap.add_argument("--ensure-agent", action="store_true",
                    help="check the sandcat agent is alive and redeploy it if not; detonates nothing")
    ap.add_argument("--reconcile", action="store_true",
                    help="return the lab to its known-good posture and PROVE it; prints JSON, "
                         "exit 0 only when residual is empty. Detonates nothing.")
    ap.add_argument("--preflight", action="store_true",
                    help="print the configuration names a run is missing (or `preflight ok`); "
                         "exit 1 when any is missing; touches no lab and no network")
    ap.add_argument("--executors", metavar="A,B",
                    help="with --preflight: check only these executors (default: every registered one)")
    ap.add_argument("--record-night", metavar="YYYY-MM-DD",
                    help="write a replay fixture for that night from rules/results and the ledger "
                         "(with --out DIR; one search per host, read-only)")
    ap.add_argument("--out", metavar="DIR", help="with --record-night: where the fixtures go")
    ap.add_argument("--host", metavar="NAME", help="with --record-night: only this host")
    ap.add_argument("--replay", metavar="DIR",
                    help="re-verify a recorded night from DIR (inputs.json, alerts.json, "
                         "expected.json); needs no lab, SIEM or credential; exit 0 when every "
                         "verdict matches expected.json")
    ap.add_argument("--shutdown-target", choices=VALID_TARGETS,
                    help="request a clean Windows shutdown on one registered lab target; "
                         "used only after guarded Proxmox shutdown")
    return ap


def main(argv=None):
    args = _build_parser().parse_args(argv)

    # Before load_config: an unreadable registry is one of the things it reports.
    if args.preflight:
        return preflight([e for e in (args.executors or "").split(",") if e])
    # Neither needs the lab: a replay is the verifier on recorded input, and recording
    # reads results, the ledger and the SIEM.
    if args.replay:
        return replay(args.replay)
    if args.record_night:
        if not args.out:
            print("record-night: --out DIR is required", file=sys.stderr)
            return 2
        return record_night(args.record_night, args.out, only_host=args.host)
    cfg = load_config()

    # Does not read the rule export or use-case registry. TEARDOWN must retain its
    # clean guest fallback even if detection content is temporarily malformed.
    if args.shutdown_target:
        result = request_guest_shutdown(args.shutdown_target, cfg=cfg)
        print(json.dumps(result))
        return 0 if result["ok"] else 1

    enabled = load_enabled_rules(EXPORT)
    rule_intervals = {v["rule_id"]: v["interval"] for v in enabled.values()}

    # The registry is read ON FIRST USE, and that is load-bearing rather than a
    # micro-optimisation. `--ensure-agent` and `--reconcile` read no use-case at all
    # (see their own comments below) and validation's PREPARE gate cannot go green
    # without both, so a data problem in the registry must not be able to take them
    # down. Eagerly loading here is exactly how it did on 2026-09-03: ONE use-case
    # naming an installed-but-disabled rule raised LoaderError above every branch,
    # so `--ensure-agent` died on a file it never opens, PREPARE went red at
    # sandcat_deployed, nothing detonated, and the carry-over re-check lost the
    # night's PENDING rows as well. A registry error should cost the subcommands
    # that read the registry, and nothing else.
    _cache = {}

    def usecases():
        if "u" not in _cache:
            _cache["u"] = load_usecases(UC_DIR, EXPORT, include_draft=args.include_draft)
        return _cache["u"]

    def selected():
        if "s" not in _cache:
            _cache["s"] = select(usecases(), args)
        return _cache["s"]

    # Both of these detonate NOTHING, so they run before any CALDERA client is built.
    # `is not None`, not truthiness: --select-nightly 0 is a request for an EMPTY
    # selection and used to fall through to the detonation branch below, which is
    # the opposite of what it asked for.
    if args.select_nightly is not None:
        rows = ledgermod.read(LEDGER)
        ids, meta = selectmod.select_nightly(usecases(), rows, args.select_nightly,
                                             allow_internet=args.allow_internet)
        if args.json:
            print(json.dumps({"ids": ids, "meta": meta}, indent=2))
        else:
            for uid in ids:
                print(uid)
            # The cycle length is PRINTED, never asserted: with a safe pool of
            # {pool} and K max 10 the rotation takes {cycle_nights} nights, and a
            # loop that silently missed its own target would be the failure this
            # design exists to prevent.
            print(f"# pool={meta['pool']} k={meta['k']} cycle={meta['cycle_nights']} nights "
                  f"bound={meta['staleness_bound_nights']}d (HIGH {meta['staleness_bound_high_nights']}d) "
                  f"pending={meta['pending']} regressions={meta['regressions']} stale={meta['stale']} "
                  f"flapping={meta['flapping']}",
                  file=sys.stderr)
        return 0

    if args.recheck_pending:
        return recheck_pending(usecases(), rule_intervals, as_json=args.json)
    if args.recheck_missed is not None:
        return recheck_missed(usecases(), rule_intervals, as_json=args.json,
                              days=args.recheck_missed)

    if args.list:
        for u in selected():
            print(f"{u['id']}\t{u.get('technique')}\t{u['executor']}")
        return 0

    caldera = CalderaClient(cfg)

    # DETONATES NOTHING, so it sits before the selection guard below and needs no
    # use-case. It exists because validation's PREPARE gate measures
    # `sandcat_beacon` and never deploys, while the only redeploy path
    # (CalderaClient.ensure_agent) is called from run_ability - i.e. per
    # detonation, behind the very gate a dead beacon closes. Since teardown powers
    # the lab off every night, the agent dies with it and the gate can never come
    # good again on its own. Measured 2026-07-27: the last beacon on record was
    # 2026-07-26T10:01:31Z, exactly the last detonation window.
    if args.ensure_agent:
        alive_before = caldera.is_agent_alive()
        ok = alive_before
        if not alive_before:
            try:
                ok = caldera.ensure_agent(_winrm_factory(cfg)())
            except Exception as e:  # WinRM down, box still booting, deploy refused
                print(json.dumps({"ok": False, "already_alive": False, "error": str(e)}))
                return 1
        print(json.dumps({"ok": bool(ok), "already_alive": bool(alive_before), "error": None}))
        return 0 if ok else 1

    # DETONATES NOTHING. Sits before the selection guard for the same reason
    # --ensure-agent does: validation's PREPARE gate reads its `residual` and the
    # gate cannot go green without it, so it must be reachable with no use-case.
    if args.reconcile:
        import reconcile as reconcilemod
        try:
            sess = _winrm_factory(cfg)()
        except Exception as e:
            print(json.dumps({"reset": [], "removed": [], "attempted": [],
                              "residual": [f"session_failed: {e}"], "checked": 0}))
            return 1
        return reconcilemod.main_json(sess, cfg=cfg)

    if args.cleanup:
        _cleanup_caldera(caldera, [u["id"] for u in usecases()])
        print("cleanup complete")
        return 0

    if not selected():
        print("no use-cases selected (use --id/--technique/--tactic/--tag/--all)", file=sys.stderr)
        return 2

    # The safety gate: before --dry-run prints (a dry run shows what WILL run, not what was
    # asked for) and before the dedup pool is built (a refused selection powers nothing on).
    # One refused member refuses the whole selection: a run never quietly drops the part of
    # an operator's selection it will not do.
    allowed, refusals = gate_selection(selected(), args)
    for line in refusals:
        print(line, file=sys.stderr)
    if refusals:
        return 2

    if args.dry_run:
        for u in allowed:
            print(f"WOULD RUN {u['id']} via {u['executor']}")
        return 0

    # A new detonation without a verifier measures nothing: the rows would all be
    # INCONCLUSIVE (measured 2026-07-26). --recheck-* of old rows without a key stays
    # honest and stays allowed; a fresh detonation does not.
    do_verify = verify_default(args)
    if do_verify:
        es_url, api_key = _es_credentials()
        if not (es_url and api_key):
            print("engine: ES_URL or ES_API_KEY not set; refusing to detonate without a verifier",
                  file=sys.stderr)
            return 2

    dedup = DedupAllocator(cfg, STATE_IP)
    dedup.assert_pool_safe(cfg)
    firewall = FirewallService()

    results = []
    try:
        for u in allowed:
            target = u.get("target", "workstation")
            uc_cfg = config_for_target(cfg, target)
            # Resolve the safety boundary BEFORE executing. A typo'd DC_HOST must
            # not run first and only discover afterwards that the address was not
            # one of the registered lab targets.
            host = target_host(uc_cfg, target)
            missing = missing_for_target(cfg, target)
            if missing:
                r = make_result(u, f"ERROR: missing target config: {', '.join(missing)}", False)
            else:
                # Space this detonation from the previous one ON THIS HOST so the
                # verifier's neighbour clamps stay outside the clock-skew tolerance
                # (see DETONATION_GAP_S). Measured from the ledger as well as this
                # invocation's results, because the nightly runs one use-case per
                # invocation. A config-skipped row has no attack_end: no wait.
                _wait_for_detonation_gap(host, results)
                dedup.assert_pool_safe(uc_cfg)
                ctx = Ctx(cfg=uc_cfg, caldera=caldera, winrm_factory=_winrm_factory(uc_cfg),
                          dedup=dedup, firewall=firewall)
                handler = registry.get(u["executor"])
                try:
                    r = handler(u, ctx)
                except Exception as e:
                    r = make_result(u, f"ERROR: {e}", False)
            r.host = host
            results.append(r)
            print(f"[{r.status:14}] {u['id']}")
    finally:
        try:
            dedup.cleanup()
        except Exception:
            pass

    _warn_if_detonations_too_close(results)

    if do_verify:
        _verify_by_host(results, rule_intervals)
        # BEFORE the append below: tonight's rows are not on file yet, which is what makes
        # every row on file history (see _apply_miss_classes).
        _apply_miss_classes(results)

    run_ts = datetime.now(timezone.utc).isoformat()
    ledgermod.append(LEDGER, [_ledger_row(r, run_ts) for r in results])

    print(f"results: {_write_results(results, cfg)}")
    if args.emit_json:
        with open(args.emit_json, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"emitted: {args.emit_json}")

    counts = Counter(r.verdict.name if r.verdict else "NONE" for r in results)
    print("verdicts:", dict(counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
