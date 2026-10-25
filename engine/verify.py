# rules/engine/verify.py
"""Detection-wait model + six-state classifier + ES query (injected transport).

Correlates on kibana.alert.rule.rule_id, never on name or uuid. A missing key or a
failed/shape-drifted query returns None (-> INCONCLUSIVE), never an empty list.

PREVENTED exists because the best outcome used to score as the worst. On 2026-07-25
the LSASS use-case's target rule never fired: Defend blocked the dump, so the
telemetry the rule reads never existed. Three other rules fired. The engine called
that MISSED. A nightly loop that reports a successful prevention as a detection
failure is wrong in the direction that matters most.
"""
import json, os, ssl, sys, urllib.request
from datetime import datetime, timedelta
from result import Verdict
# The field list and the query live with the Elastic adapter (siem/elastic.py); the names stay
# importable from here for the callers and tests that always took them from verify.
from siem.elastic import ALERT_SOURCE_FIELDS, ElasticAdapter, _flat, build_alert_query  # noqa: F401

EXEC_SLACK_S = 120  # measured p99.9 schedule delay is ~3.1s; 120s is ~40x headroom (design 0.4)

# The window's LOWER bound tolerance, and it exists because the two ends of a
# detonation are timed by two different machines: `attack_start` is stamped by the
# engine host, the alert's behavior time comes from the Windows host, and nothing
# synchronises them.
#
# Measured live 2026-07-28: rule 8b2b3a62 fired on invoice_Q4_2025.pdf.exe with
# kibana.alert.original_time 08:58:09.456Z against an attack_start of
# 08:58:09.503976Z. 47.976 ms early, so `start <= ts` dropped it and the night
# recorded MISSED over an alert sitting in the index - a detection failure reported
# against a detection that worked. It bites whenever the detectable behavior is the
# FIRST thing the command does (here `Copy-Item` was statement two), so it is
# intermittent rather than rare, and silent either way.
#
# 5s is ~100x the observed skew and still far below the smallest gap between two
# detonations (5-25s measured the same day). It does not have to be chosen finely,
# because it is CLAMPED: `_window_alerts` never reaches back past the previous
# detonation's end, whatever this number says. That clamp is the mirror of the
# `until` bound on the upper side, and it is what makes the tolerance safe rather
# than a second way to steal a neighbour's alert.
CLOCK_SKEW_S = 5


def _grace_from_env(environ=None):
    """ZYBUR_UNCONTESTED_GRACE_S as whole seconds, or CLOCK_SKEW_S when it is unset or empty.

    A malformed value raises: this is a measurement knob, and a typo that quietly fell back to
    the default would make a replay "show no difference" for the wrong reason.
    """
    raw = (os.environ if environ is None else environ).get("ZYBUR_UNCONTESTED_GRACE_S")
    if raw is None or not raw.strip():
        return CLOCK_SKEW_S
    try:
        grace = int(raw)
    except ValueError:
        grace = -1
    if grace < 0:
        raise ValueError(f"ZYBUR_UNCONTESTED_GRACE_S must be a whole number of seconds, got {raw!r}")
    return grace


# D10 (the founder answered yes, 2026-10-24). `_window_alerts` lets an alert of my own target
# rule past `until` (the next detonation's floor) when no later detonation targets that rule:
# a threshold or new-terms alert can land a few seconds past the clamp for the right
# detonation. Measured 2026-10-24 over 5,204 ledger rows: 499 rows co-fired another use-case's
# target rule on a night that use-case also ran on the same host (175 distinct pairs), so the
# exemption could credit a foreign alert to an earlier row; the ledger holds no behaviour
# times, so four recorded nights were replayed with and without a bound (plan status table):
# 5 of 295 detonations changed, all on attended batch nights, none on a nightly.
#
# So the exemption is bounded: an uncontested alert at or past `until + UNCONTESTED_GRACE_S`
# is not mine. The bound is CLOCK_SKEW_S, the tolerance this window already allows for two
# unsynchronised clocks, so an alert that is my own detonation's tail, placed just past the
# next start by skew, still counts. ZYBUR_UNCONTESTED_GRACE_S overrides it in whole seconds,
# for a measurement: a very large value (31536000, a year) restores the old unbounded
# behaviour, so a replay can be compared with and without the bound.
UNCONTESTED_GRACE_S = _grace_from_env()

# Measured live 2026-07-25: every Elastic Defend prevention alert carries
# event.type "denied" and none of the detections do. That is the ECS marker for a
# blocked action, so it is the primary test. The rule-name prefixes are a fallback:
# they are Elastic display strings and can be renamed upstream, which is exactly the
# name-correlation fragility this engine was built to stop relying on.
PREVENTION_EVENT_TYPE = "denied"
# Measured 2026-07-25: 2,645 alerts carry event.type "denied", split
# "Malicious Behavior Prevention Alert" 1,312 and "Malware Prevention Alert" 1,242,
# and ZERO prevention-named alerts lack the denied marker. So the marker alone is
# already complete; these prefixes only matter when event.type is absent from a
# document, and the list is kept complete so that fallback is not half a check.
PREVENTION_NAME_PREFIXES = (
    "Malicious Behavior Prevention Alert",
    "Malware Prevention Alert",
    "Memory Threat Prevention Alert",
    "Ransomware Prevention Alert",
    "Malicious File - Prevented",
)



def parse_interval_to_seconds(s):
    unit = s[-1]; n = int(s[:-1])
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def _parse_ts(iso):
    return datetime.fromisoformat(str(iso).replace("Z", "+00:00"))


def behavior_ts(alert, siblings=None):
    """When the blocked/matched behavior happened, not when the alert was written.

    Measured live 2026-07-26: Defend batch-writes prevention alerts, so @timestamp
    ran 19s behind kibana.alert.original_time and one write burst landed inside five
    overlapping verification windows (findings c0e223be080a / 721ab38ba1a0).

    A SEQUENCE SHELL ALERT (carries group_id, carries no building_block_type) is not
    itself a behavior: its own original_time is close to its WRITE time, not to when
    the sequence's components ran. Measured live 2026-10-16: `Incoming Execution via
    WinRM Remote Shell` wrote its shell at 04:07:19Z while its two building blocks
    (building_block_type "default", same group_id) carried original_time 04:02:36Z
    and 04:02:38Z - the real behavior, five minutes earlier. Scoring the shell by its
    own original_time against an attack_start of 04:03:56Z read a false DETECTED: the
    window test passed, but the alert said nothing about what happened at that time.
    The shell's behavior time is the EARLIEST original_time among its own building
    blocks (same group_id, building_block_type == "default") found in `siblings`
    (the alerts fetched for this verification, per P-D2). No matching sibling: the
    shell cannot be evaluated against the window, so this returns None rather than
    falling back to the shell's own misleading timestamp.
    """
    if alert.get("group_id") and not alert.get("building_block_type"):
        components = [
            s for s in (siblings or [])
            if s.get("group_id") == alert.get("group_id")
            and s.get("building_block_type") == "default"
            and s.get("original_time")
        ]
        if not components:
            return None
        return min(_parse_ts(s["original_time"]) for s in components)
    written = _parse_ts(alert["@timestamp"])
    original = alert.get("original_time")
    if not original:
        return written
    behavior = _parse_ts(original)
    if behavior <= written + timedelta(seconds=CLOCK_SKEW_S):
        return behavior

    # A behavior cannot occur after the alert that reports it. Measured live on
    # DC1 2026-09-05: Windows was nine hours fast, while the rule correctly ran on
    # event.ingested. The signal was written at 08:39Z with original_time 17:35Z;
    # trusting that impossible future time turned a real detection into MISSED.
    # Prefer the source document's ingest time in this one invalid-clock shape,
    # falling back to the alert write time if the signal does not retain it.
    ingested = alert.get("event_ingested")
    if ingested:
        ingest_time = _parse_ts(ingested)
        if ingest_time <= written + timedelta(seconds=CLOCK_SKEW_S):
            return ingest_time
    return written


def next_start_bound(my_start_iso, all_starts_iso):
    """The earliest attack_start strictly after mine, or None.

    A behavior at or after the next detonation started belongs to that detonation;
    without this bound every back-to-back window absorbs its successors' alerts.
    """
    if not my_start_iso:
        return None
    mine = _parse_ts(my_start_iso)
    later = [_parse_ts(s) for s in all_starts_iso or [] if s and _parse_ts(s) > mine]
    return min(later) if later else None


def attribution_until(my_start_iso, my_end_iso, all_starts_iso):
    """Where this detonation's window ends: at the NEXT detonation's floor, not its start.

    The successor's window reaches back CLOCK_SKEW_S before its own attack_start
    (that tolerance is what keeps a 48 ms "early" behavior from reading MISSED), so
    clamping this window at the successor's START left [next_start - CLOCK_SKEW_S,
    next_start) inside both. An alert there was stored on two rows, and a row with
    no alert of its own read PREVENTED on its neighbour's block. Measured live
    2026-10-11: test_psengine.exe was blocked at behavior time 04:04:30.571Z, 42 ms
    before the neighbouring sample started, and the
    prevention also landed in the mshta row's co_firing, because mshta's window ran
    to 04:04:30.613Z. Seen again 2026-10-13: the two 58bc134c alerts on the
    initial-access Office row were also on lateral-movement/remote-file-copy-to-a-
    hidden-share, the next detonation, and the report called them "caused by a
    later detonation". DETONATION_GAP_S (10s) does not close the overlap; it only
    keeps it from also cutting into the successor.

    So this window stops where the successor's starts, next_start - CLOCK_SKEW_S,
    and never before my own attack_end (attack_start when no end is recorded): a
    detonation is never clipped inside its own execution. When the two ran closer
    than CLOCK_SKEW_S the bound is my attack_end, which is also where the
    successor's floor sits (prev_end_bound), so the windows still meet without
    overlapping. My own uncontested target alerts are still let past this bound by
    _window_alerts; that exemption is unchanged. None when nothing starts later.
    """
    nxt = next_start_bound(my_start_iso, all_starts_iso)
    if nxt is None:
        return None
    bound = nxt - timedelta(seconds=CLOCK_SKEW_S)
    own = my_end_iso or my_start_iso
    return max(bound, _parse_ts(own))


def prev_end_bound(my_start_iso, all_ends_iso):
    """The latest attack_end strictly before my start, or None.

    The mirror of next_start_bound. A behavior at or before the previous detonation
    finished belongs to THAT detonation, so this is how far back the clock-skew
    tolerance is allowed to reach - and no further, however large the tolerance is.
    """
    if not my_start_iso:
        return None
    mine = _parse_ts(my_start_iso)
    earlier = [_parse_ts(s) for s in all_ends_iso or [] if s and _parse_ts(s) < mine]
    return max(earlier) if earlier else None


def previous_rule_end_bounds(my_start_iso, my_rule_ids, detonations):
    """Target rule id -> latest earlier end of a detonation targeting that rule.

    The global predecessor end is correct for unattributed/co-firing alerts, but
    not for a target alert from a rule the predecessor could not produce.  This
    per-rule bound keeps clock-skew tolerance without letting a repeated
    detonation of the same rule claim its predecessor's evidence.
    """
    if not my_start_iso or not my_rule_ids:
        return {}
    mine = _parse_ts(my_start_iso)
    wanted = set(my_rule_ids)
    out = {}
    for detonation in detonations or []:
        end = detonation.get("attack_end")
        if not end:
            continue
        parsed = _parse_ts(end)
        if parsed >= mine:
            continue
        for rid in wanted & set(detonation.get("rule_ids") or []):
            if rid not in out or parsed > out[rid]:
                out[rid] = parsed
    return out


def due_time(attack_end_iso, interval, exec_slack_s=EXEC_SLACK_S):
    return _parse_ts(attack_end_iso) + timedelta(seconds=parse_interval_to_seconds(interval) + exec_slack_s)


# The dataset Elastic Defend's own alerts come from. `denied` is a prevention only
# there: a DETECTION rule over a Windows event that was itself a block (WFP 5157,
# event.type [connection, info, denied], dataset system.security) carries the same
# marker. Measured 2026-10-14: the Windows Filtering Platform rule's alert graded the
# next row, the audit-policy case, PREVENTED on a host whose Defend never prevents.
# An alert with no dataset keeps the old reading (every fixture, and every Defend
# document measured on 2026-07-25, which had both).
DEFEND_ALERT_DATASET = "endpoint.alerts"


def is_prevention(alert):
    """True when this alert document says an action was BLOCKED, not merely seen."""
    types = alert.get("event_type") or []
    if isinstance(types, str):
        types = [types]
    dataset = alert.get("event_dataset")
    if isinstance(dataset, list):
        dataset = dataset[0] if dataset else None
    from_defend = not dataset or str(dataset) == DEFEND_ALERT_DATASET
    if from_defend and any(str(t).lower() == PREVENTION_EVENT_TYPE for t in types):
        return True
    name = str(alert.get("name") or "")
    return any(name.startswith(p) for p in PREVENTION_NAME_PREFIXES)


def _on_target_host(alert, result):
    """Match endpoint hosts and aggregate Windows alerts to the target.

    ES|QL alerts grouped by winlog.computer_name legitimately omit both host.id
    and host.name. Canonical lab aliases travel with results so that retained
    identity remains host-scoped instead of being discarded (or accepted without
    a host check).
    """
    host = result.host or {}
    names = [host.get("name"), *(host.get("aliases") or [])]
    names = {str(value).lower() for value in names if value}
    hid = host.get("id")
    if not names and not hid:
        return True
    alert_names = {
        str(value).lower()
        for value in (alert.get("host_name"), alert.get("winlog_computer_name"))
        if value
    }
    if names & alert_names:
        return True
    if hid and alert.get("host_id") and str(alert["host_id"]).lower() == str(hid).lower():
        return True
    return False


def _dues(result, rule_intervals):
    return [due_time(result.attack_end, rule_intervals[rid])
            for rid in result.rule_ids if rid in rule_intervals]


def contested_rule_ids(my_start_iso, my_rule_ids, later_detonations):
    """Of MY target rules, the ones a LATER detonation also targets.

    This is the whole question the `until` clamp exists to answer. The clamp stops
    a window absorbing a successor's alerts - but a successor can only be robbed of
    an alert it could have produced, and 176 of the 177 target rule ids in the
    registry belong to exactly one use-case. When nothing later targets my rule,
    an alert from my rule is mine whenever it lands inside my due window, and the
    clamp is discarding evidence to prevent a theft that cannot happen.

    `later_detonations` is a list of {attack_start, rule_ids}. The same use-case
    detonated twice in one night IS a contest, which is why this compares rule ids
    rather than use-case ids.
    """
    if not my_start_iso or not my_rule_ids:
        return set()
    mine = _parse_ts(my_start_iso)
    out = set()
    for d in later_detonations or []:
        start = d.get("attack_start")
        if not start or _parse_ts(start) <= mine:
            continue
        out |= (set(my_rule_ids) & set(d.get("rule_ids") or []))
    return out


def _window_alerts(result, alerts, rule_intervals, until=None, since=None, contested=None,
                   target_since=None):
    """Alerts on the target host whose BEHAVIOR happened inside this detonation's
    window: from attack_start (less a clock-skew tolerance) to the latest due
    deadline, bounded above by `until` and below by the previous detonation's end.
    run.py passes attribution_until as `until` (since 2026-10-14: the next
    detonation's floor, not its start, so neighbouring windows do not overlap).

    BOTH bounds are clamped to a neighbour, and symmetrically. The upper bound
    stops a window absorbing its successors' alerts; the lower one lets the window
    tolerate two unsynchronised clocks WITHOUT letting it reach into a predecessor.
    Without the tolerance a real detection 48 ms "early" reads as MISSED; without
    the clamp the tolerance would be a second way to steal a neighbour's alert.

    The upper clamp does NOT apply to an alert from my own target rule when no
    later detonation targets that rule - see contested_rule_ids. Measured live
    2026-07-29: detonations ran 1-5s apart, so every window was ~5s wide, and the
    threshold rule in the regression fixture fired on
    the right host, for the right detonation, with a bucket-boundary behavior time
    4.89s past the clamp. The engine recorded MISSED over an alert it had already
    read. A threshold rule's original_time is a bucket `from` rounded to the whole
    second, so it can NEVER be relied on to land inside a five-second window.

    UNCONTESTED_GRACE_S bounds that exemption (D10): see its comment.
    """
    if not alerts or not result.attack_start:
        return []
    start = _parse_ts(result.attack_start)
    dues = _dues(result, rule_intervals)
    end = max(dues) if dues else (start + timedelta(seconds=EXEC_SLACK_S))
    tolerance_floor = start - timedelta(seconds=CLOCK_SKEW_S)
    contested = set(contested or ())
    mine = set(result.rule_ids or ())
    out = []
    for a in alerts:
        if not _on_target_host(a, result):
            continue
        ts = behavior_ts(a, alerts)
        if ts is None:
            # A sequence shell with no building-block sibling in this fetch: there is
            # no behavior time to evaluate it against, so it is skipped rather than
            # compared with None (see P-D2 and behavior_ts). Printed, not swallowed:
            # there is no other skip-reason channel in this module, and a nightly run
            # must be able to say WHY a shell went uncredited.
            print(f"# SKIP {a.get('rule_id')} alert on {result.id}: sequence_no_components "
                  f"(group_id={a.get('group_id')!r}, no building-block sibling fetched)",
                  file=sys.stderr)
            continue
        rid = a.get("rule_id")
        # When run.py supplies target_since, target alerts are bounded by the
        # previous detonation of THAT rule. An unrelated use-case ending inside
        # the clock-skew window cannot have produced this rule's alert. Direct
        # callers that omit it retain the historical global bound.
        lower = since
        if rid in mine and target_since is not None:
            lower = target_since.get(rid)
        floor = tolerance_floor if lower is None else max(tolerance_floor, lower)
        if not (floor <= ts <= end):
            continue
        uncontested_mine = rid in mine and rid not in contested
        if until is not None and ts >= until and not uncontested_mine:
            continue
        if (uncontested_mine and until is not None and UNCONTESTED_GRACE_S is not None
                and ts >= until + timedelta(seconds=UNCONTESTED_GRACE_S)):
            continue
        out.append(a)
    return out


def latency_for(result, alerts, rule_intervals, until=None, since=None, contested=None,
                target_since=None):
    """Seconds from attack_start to the FIRST alert this detonation caused, or None.

    Read from the SAME windowed set classify() reads, and that is the whole point.
    Until 2026-09-03 run.py re-filtered the raw alert list itself with a strict
    `behavior_ts >= attack_start`, so the CLOCK_SKEW_S tolerance that classify has
    applied since 2026-07-28 was missing here and the two disagreed about which
    alerts belong to a detonation.

    Measured on the 2026-09-03 run: 3 of 8 DETECTED rows came back with
    latency None, their behavior time early by 29, 52 and 94 ms - precisely the
    "the detectable behavior is the FIRST thing the command does" case the
    CLOCK_SKEW_S comment above was written for, and the same millisecond race that
    produced a false MISSED before that tolerance existed.

    The consequence was a MISSING number rather than a wrong one, which is why it
    survived: `lib/attack-report.js` raises its slow-detection finding only when
    `latency_s != null`, so a genuinely slow detection went unflagged whenever its
    behavior timestamp happened to lose that race. The race is uncorrelated with
    how slow the detection was, so the skip was silent and effectively random.
    """
    if not result.attack_start:
        return None
    mine = set(result.rule_ids or ())
    start = _parse_ts(result.attack_start)
    hits = [_parse_ts(a["@timestamp"])
            for a in _window_alerts(result, alerts, rule_intervals, until=until,
                                    since=since, contested=contested,
                                    target_since=target_since)
            if a.get("rule_id") in mine]
    return (min(hits) - start).total_seconds() if hits else None


def co_firing_for(result, alerts, rule_intervals, until=None, since=None, contested=None,
                  target_since=None):
    """Every alert on the target host in the window that is NOT the target rule.

    This is the difference between "we missed it" and "we caught it three other
    ways", and it costs no extra query: verification already reads this window.
    """
    if alerts is None:
        return []
    targets = set(result.rule_ids or [])
    out = []
    # The uncontested-target exemption cannot reach this list: every alert it lets
    # through carries a target rule id, and target rule ids are filtered out below.
    for a in sorted(_window_alerts(result, alerts, rule_intervals, until=until, since=since,
                                   contested=contested, target_since=target_since),
                    key=lambda x: x["@timestamp"]):
        if a.get("rule_id") in targets:
            continue
        out.append({"rule_id": a.get("rule_id"), "name": a.get("name"),
                    "ts": a.get("@timestamp"), "prevented": is_prevention(a)})
    return out


def is_sequence_component(alert):
    """A building block OF A SEQUENCE: building_block_type "default" AND a group id.

    Elastic writes an EQL sequence as one shell alert (group id, no
    building_block_type) plus one building-block alert per step (same group id,
    building_block_type "default"). Those steps are the only alerts a target hit must
    skip: their original_time is the step's own, not the sequence's, and the shell
    already carries the credit (behavior_ts). A building-block RULE can write alerts with
    building_block_type "default" and NO group id: those are the rule's only output
    and are a target hit like any other. Measured 2026-10-22: the ping rule's alert
    at 04:05:34Z (building block, no group) was the one the record called MISSED.
    """
    return bool(alert.get("group_id")) and alert.get("building_block_type") == "default"


# --- new-terms memory (2026-10-22) -------------------------------------------------
# A new-terms rule alerts on a value of new_terms_fields it has NOT seen inside its
# history window ("now-5d"). Fields a lab host cannot vary between two detonations:
# a rule keyed on these alone remembers the HOST, so any match on the same host inside
# the window, by any use-case, silences the next one. A rule keyed on a field the
# payload can vary (process.command_line, process.executable, a task name) tells
# nothing about tonight's value from a prior detonation, so no memory is inferred for
# it and a MISSED stands.
INVARIANT_NEW_TERMS_FIELDS = frozenset({
    "host.id", "host.name", "host.hostname", "user.id", "user.name", "agent.id",
})


def memory_is_host_bound(fields):
    fields = [f for f in (fields or []) if f]
    return bool(fields) and all(f in INVARIANT_NEW_TERMS_FIELDS for f in fields)


def memory_evidence(result, rule_id, window_s, prior_alerts=None, prior_detonations=None):
    """The latest record, inside [attack_start - window, attack_start), that the rule's
    memory already held this host: a ledger detonation naming the rule (any use-case,
    same host), or an alert of the rule itself at its behaviour time. None when
    nothing on record falls inside the window.

    None is "no evidence", never "the memory was clear": a sibling that matched the
    rule's query WITHOUT alerting (its own target was another rule, or it was itself
    silenced) leaves no record the engine can read. Measured 2026-10-22: the
    attended MSBuild tests of 2026-10-19 silenced both MSBuild rules on dc1 for five
    days and alerted for neither.
    """
    if not result.attack_start or not window_s:
        return None
    start = _parse_ts(result.attack_start)
    floor = start - timedelta(seconds=window_s)
    found = []
    for d in prior_detonations or []:
        if rule_id not in (d.get("rule_ids") or []) or not d.get("attack_start"):
            continue
        t = _parse_ts(d["attack_start"])
        if floor <= t < start:
            found.append((t, {"source": "detonation", "at": d["attack_start"],
                              "usecase": d.get("id")}))
    for a in prior_alerts or []:
        if a.get("rule_id") != rule_id:
            continue
        ts = a.get("original_time") or a.get("@timestamp")
        if not ts:
            continue
        t = _parse_ts(ts)
        if floor <= t < start:
            found.append((t, {"source": "alert", "at": ts, "usecase": None}))
    if not found:
        return None
    return max(found, key=lambda x: x[0])[1]


def memory_reason(rule_name, rule_id, fields, window, host_name, evidence):
    """One sentence for the ledger row and the report: why MISSED became INCONCLUSIVE."""
    who = evidence.get("usecase") or "the rule's own alert"
    return (f"rule memory: {rule_name or rule_id} is a new-terms rule keyed on "
            f"{', '.join(fields or []) or 'unknown fields'} with a {window or 'unknown'} memory, and "
            f"{host_name or 'this host'} already matched on {evidence.get('at')} "
            f"({evidence.get('source')}: {who}), so it could not fire again inside that window")


def rule_versions_for(result, alerts, rule_intervals, until=None, since=None, contested=None,
                      target_since=None):
    """{rule_id: kibana.alert.rule.version} for this detonation's target hit.

    Read from the SAME windowed hit classify() used (see latency_for's docstring for
    why that matters, and classify's own hit line for why a sequence's components are
    excluded). A proof is only as current as the rule version it was measured
    against (P-D3): the pack moves rule versions forward, and a proof of version
    215 says nothing about version 216.
    """
    if alerts is None or not result.rule_ids:
        return {}
    hit = [a for a in _window_alerts(result, alerts, rule_intervals, until=until, since=since,
                                     contested=contested, target_since=target_since)
           if a.get("rule_id") in result.rule_ids and not is_sequence_component(a)]
    out = {}
    for a in hit:
        rid = a.get("rule_id")
        version = a.get("rule_version")
        if rid and version is not None:
            out[rid] = version
    return out


def classify(result, alerts, now, rule_intervals, until=None, since=None, contested=None,
             target_since=None):
    if not result.executed:
        return Verdict.ABORT
    # A use-case whose rule is deliberately absent can never be detected, so it can
    # never be MISSED either. Reporting it as a detection failure would make the one
    # number this loop produces a lie.
    if getattr(result, "expect", "detected") != "detected":
        return Verdict.INCONCLUSIVE
    if alerts is None:
        return Verdict.INCONCLUSIVE
    if not result.rule_ids:
        # expect: detected, but nothing resolved. There is no due time and no rule to
        # miss. Could-not-measure, never a measured zero.
        return Verdict.INCONCLUSIVE
    # HOST-SCOPED AND UPPER-BOUNDED, exactly as _window_alerts already is for the
    # PREVENTED and co-firing paths. The 2026-07-26 behaviour-time attribution fix
    # went to preventions and never reached the verdict that matters most: a target
    # rule firing on another host, or after the next detonation started, credited a
    # false DETECTED. _window_alerts' lower bound is the same attack_start this
    # branch used; what it adds is _on_target_host and the upper deadline.
    # A sequence's COMPONENTS are never a target hit themselves: crediting one
    # directly would re-introduce the false DETECTED P-D2 exists to close, just from
    # the other side (a component landing inside the window instead of the shell's
    # own misleading original_time). Only the shell, or an ordinary alert, satisfies
    # a target rule id. An ordinary alert INCLUDES one from a building-block RULE
    # (building_block_type "default", no group id): eight enabled rules are built
    # that way, and from 2026-10-19 to 2026-10-22 the filter here read "any
    # building-block alert", which recorded the ping discovery rule MISSED while
    # its own alert sat 62 s after the attack. See is_sequence_component.
    hit = [a for a in _window_alerts(result, alerts, rule_intervals, until=until, since=since,
                                     contested=contested, target_since=target_since)
           if a.get("rule_id") in result.rule_ids and not is_sequence_component(a)]
    if hit:
        return Verdict.DETECTED
    # due = the EARLIEST due time across the use-case's rules (any due rule can miss)
    dues = _dues(result, rule_intervals)
    if dues and now < min(dues):
        # Not due yet. A prevention seen now is evidence, not a conclusion: the rule
        # may still fire, and nothing re-checks a row that is not PENDING.
        return Verdict.PENDING
    if any(is_prevention(a) for a in _window_alerts(result, alerts, rule_intervals, until=until,
                                                    since=since, contested=contested,
                                                    target_since=target_since)):
        return Verdict.PREVENTED
    return Verdict.MISSED


def query_alerts(es_url, api_key, rule_ids, since_iso, hosts=None, http=urllib.request, ssl_ctx=None):
    """Return a list of alert dicts, or None if it could not be measured.

    The Elastic query itself is siem.elastic.ElasticAdapter; this keeps the old call
    shape for run.py and the tests that patch it.
    """
    return ElasticAdapter(es_url, api_key, http=http, ssl_ctx=ssl_ctx).query_alerts(
        rule_ids, since_iso, hosts)
