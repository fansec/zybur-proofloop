# rules/engine/selector.py
"""Deterministic nightly selection over the safe pool.

Named `selector`, not `select`: `select` is in sys.builtin_module_names on this
host and builtins beat sys.path, so a local select.py can never be imported. That
is not a style choice, it is the difference between this module working and not.

No model participates. Same ledger, same clock, same K, same selection - asserted
by a test, because a rotation that cannot be reproduced cannot be reasoned about.

The staleness bound is COMPUTED, not fixed. The spec's "every loop-safe use-case
within 4 nights" is arithmetically unreachable: 82 use-cases, a safe pool of 52,
and K capped at 10 gives a 6-night floor. A loop that silently misses its own
target is the failure this design exists to prevent, so the cycle length is
measured and printed instead of asserted.
"""
import math
from datetime import datetime, timezone, timedelta

K_MIN, K_MAX = 5, 10

# Severity drives how fast debt accrues. A HIGH use-case left unrun for four nights
# is worth more attention than a LOW one left for four nights.
SEVERITY_WEIGHT = {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}

# A use-case that keeps flapping between DETECTED and MISSED is more informative
# per run than one that has been stable for a month.
FLAKY_WEIGHT_MAX = 2.0

# The verdicts that are a MEASUREMENT. PENDING and ABORT are the loop describing
# itself, not the detection, and a history that counts them answers the wrong
# question - see priority_ids.
REAL_VERDICTS = ("DETECTED", "PREVENTED", "MISSED")

# How many times running a standing MISSED earns a priority slot before it stops
# being news and becomes someone's to-do.
MISSED_RETEST_MAX = 3

# The same bound on lane 1, added 2026-08-26. Lane 3 has been bounded since
# 2026-08-05 with a comment saying an unfirable use-case "must not hold a nightly
# slot forever - that would starve the rotation exactly the way yesterday's PENDING
# used to". Yesterday's PENDING was still doing it. Measured that morning on the
# live ledger: two use-cases had remained PENDING for many consecutive detonations,
# allowing lane 1 to consume a disproportionate share of the rotation without
# producing a measurement.
#
# The root cause is fixed in validation/run.js (the carry-over re-check now runs
# BEFORE select, so a row that CAN resolve has resolved by the time this function
# reads it). This bound is the backstop for a row that cannot: a rule that was
# deleted, or one whose interval is longer than a night. Two nights, not three,
# because with the re-check in front of it a second consecutive PENDING already
# means "re-checking did not help".
PENDING_RETEST_MAX = 2


def _parse_ts(iso):
    return datetime.fromisoformat(str(iso).replace("Z", "+00:00"))


# A use-case whose target is a new-terms rule cannot be measured again until the rule
# has forgotten this host: Elastic alerts on a value it has NOT seen inside the rule's
# history window, and a lab host re-running the same behaviour inside that window IS
# the value it has seen. Measured 2026-10-21 and 2026-10-22: both MSBuild use-cases on
# dc1, MISSED on consecutive nights after lane 2 re-queued the first one the morning
# after its miss, which guaranteed the second. The rule evaluates its window at ITS
# run time, not the detonation's, so one day of margin keeps a detonation at the
# window's edge from reading as new. loader.py puts rule_memory_s on the use-case; a
# use-case without it has no memory to wait for.
MEMORY_MARGIN_S = 86400


def in_rule_memory(usecase, entry, now):
    memory_s = usecase.get("rule_memory_s")
    if not memory_s or not entry or not entry.get("last_run_ts"):
        return False
    return _parse_ts(entry["last_run_ts"]) > now - timedelta(seconds=memory_s + MEMORY_MARGIN_S)


def safe_pool(usecases, allow_internet=False):
    """Loop-safe, unattended: safety safe, not evidence-destroying, expects detection.

    A use-case that erases the telemetry other use-cases depend on is excluded from
    the rotation ENTIRELY, not merely ordered last. A rotation that can destroy its
    own evidence is not a rotation, and the next morning's MISSED verdicts would be
    artefacts of the loop itself.

    `safe` covers cleanup, not egress: a use-case declared `network: internet` (it fetches a
    URL or asks a public resolver) stays out of an unattended pool unless the operator allows
    it (run.py --allow-internet). validation/lib/attack-report.js mirrors this pool for the
    coverage report and mirrors the pool a nightly WITH that allowance draws from.
    """
    return [u for u in usecases
            if u.get("safety") == "safe"
            and not u.get("destroys_evidence")
            and u.get("expect", "detected") == "detected"
            and u.get("status") != "draft"
            and (allow_internet or u.get("network", "lab") != "internet")]


def cycle_nights(pool_size, k=K_MAX):
    """How many nights a full rotation takes at the k that is actually detonated.

    Takes the RUN k, not K_MAX. Until 2026-08-31 both callers passed the cap while
    the loop detonated 5 (validation/lib/live-deps.js selectK), so a 97-use-case pool
    on a 20-night rotation declared a 10-night one.
    """
    if pool_size <= 0:
        return 0
    return math.ceil(pool_size / max(1, k))


def staleness_bounds(pool_size, k=K_MAX):
    """(all, high) staleness bounds in nights, derived from the real cycle length.

    A bound shorter than the rotation that has to satisfy it is not a bound, it is a
    permanent state. Measured on the live pool at 06:00 on 2026-08-31, with the bound
    computed off K_MAX=10 against a run of k=5: `stale` held 71 of 97 use-cases, so
    the lane that exists to interrupt the debt ranking WAS the debt ranking, and
    "past its staleness bound" carried no information about any use-case.
    """
    c = cycle_nights(pool_size, k)
    return max(4, c), max(2, math.ceil(c / 2))


def index_ledger(rows):
    """id -> {last_run_ts, last_verdict, verdicts[]} from the append-only ledger.

    Re-check rows carry the ORIGINAL run_ts plus `rechecked_at`; they supersede the
    verdict without inventing a second detonation, so last_run_ts must not move.
    """
    out = {}
    for r in rows:
        uid = r.get("id")
        if not uid:
            continue
        e = out.setdefault(uid, {"last_run_ts": None, "last_verdict": None, "verdicts": [],
                                 "by_detonation": {}})
        ts = r.get("run_ts")
        if ts and (e["last_run_ts"] is None or ts > e["last_run_ts"]):
            e["last_run_ts"] = ts
        e["last_verdict"] = r.get("verdict")
        e["verdicts"].append(r.get("verdict"))
        # One entry per DETONATION, keyed by its original run_ts, last write wins in
        # file order. `verdicts` cannot answer "how many nights ended PENDING":
        # every detonation writes PENDING once and every settle poll appends another,
        # so a single night contributes a dozen PENDING entries to that list and any
        # count over it fires on night one. See consecutive_pending_detonations.
        if ts:
            e["by_detonation"][ts] = r.get("verdict")
    return out


def consecutive_pending_detonations(entry):
    """How many of the most recent DETONATIONS ended PENDING, counting back from the newest.

    Per detonation, never per row - see the by_detonation note in index_ledger. Zero
    for an entry whose newest detonation reached a real verdict, which is the normal
    case and the one that must cost nothing.
    """
    by = (entry or {}).get("by_detonation") or {}
    n = 0
    for ts in sorted(by, reverse=True):
        if by[ts] != "PENDING":
            break
        n += 1
    return n


def flaky_weight(verdicts, window=6):
    """1.0 for a stable history, up to FLAKY_WEIGHT_MAX for one that keeps flipping.

    FILTER FIRST, then take the window - corrected 2026-08-26. The other order took
    the last six RAW ledger rows and only then kept the real verdicts, and a single
    night writes one PENDING per detonation plus one per settle poll, so those six
    rows are almost always one night's PENDINGs and at most one real verdict.
    `len(seen) < 2` then returns 1.0. Measured on the live ledger the same day: 112
    of 118 use-cases scored exactly 1.0, including
    credential-access/lsass-memory-dump-creation whose real history is
    PREVENTED, DETECTED, PREVENTED - a textbook flapping detection, weighted as
    perfectly stable.

    This is the SAME defect as the dead regression lane fixed on 2026-08-05 (`vs[-2]`
    was PENDING for 81 of 82 pool members), in the same file, found because
    priority_ids was being read again. Any code here that reads `verdicts` positionally
    has to filter to REAL_VERDICTS before it counts anything.
    """
    seen = [v for v in verdicts if v in ("DETECTED", "PREVENTED", "MISSED")][-window:]
    if len(seen) < 2:
        return 1.0
    flips = sum(1 for a, b in zip(seen, seen[1:]) if a != b)
    return 1.0 + min(1.0, flips / max(1, len(seen) - 1)) * (FLAKY_WEIGHT_MAX - 1.0)


def debt(usecase, entry, now):
    """(now - last_run) * severity_weight * flaky_weight. Never run is maximal debt."""
    sev = SEVERITY_WEIGHT.get(str(usecase.get("severity", "MEDIUM")).upper(), 2.0)
    if not entry or not entry.get("last_run_ts"):
        # Never run at all. Not "very stale" - unmeasured, which outranks everything
        # that has at least one measurement behind it.
        return float("inf")
    age_s = (now - _parse_ts(entry["last_run_ts"])).total_seconds()
    return max(0.0, age_s) * sev * flaky_weight(entry.get("verdicts") or [])


def _past_staleness(usecase, entry, now, bounds):
    """Is this use-case past its staleness bound? One implementation, two callers.

    Lane 4's own test, extracted 2026-08-26 so the over-bound PENDING branch could
    reach the same answer rather than growing a second copy of it.
    """
    bound_all, bound_high = bounds
    if not entry or not entry.get("last_run_ts"):
        return False
    nights = (now - _parse_ts(entry["last_run_ts"])).total_seconds() / 86400.0
    limit = bound_high if str(usecase.get("severity", "")).upper() == "HIGH" else bound_all
    return nights >= limit


def priority_ids(usecases, ledger_index, now, bounds):
    """Injected AHEAD of the debt ranking, in the spec's order.

    1. yesterday's PENDING - unmeasured, and the reason --recheck-pending exists,
       BOUNDED by PENDING_RETEST_MAX since 2026-08-26,
    2. a suspected regression - one healthy run then a miss,
    3. a standing MISSED - the detection is broken and nobody has re-measured it,
       bounded by MISSED_RETEST_MAX,
    4. anything past its staleness bound, INCLUDING anything never run at all.

    A use-case with no ledger row is past every bound by definition, and it is the
    only kind that has never been measured even once. Leaving it to the debt ranking
    let a use-case last run thirty days ago outrank one that has never run, which is
    exactly backwards.

    Lane 3 was added 2026-08-05, and lane 2 did not work before that date. Measured
    on the live ledger that morning: EIGHT pool use-cases were sitting on a MISSED
    verdict 6 to 8 nights old and not one was in the next night's selection, because
    a MISSED earned no priority at all and `debt()` ranks purely on age. The worst
    result the loop can produce was the one result it never re-measured.
    """
    bound_all, bound_high = bounds
    pending, regressions, missed, stale = [], [], [], []
    for u in usecases:
        e = ledger_index.get(u["id"])
        if not e or not e.get("last_run_ts"):
            stale.append(u["id"])
            continue
        if e.get("last_verdict") == "PENDING":
            # BOUNDED, exactly like the standing MISSED below and for exactly the
            # same reason. A PENDING that the carry-over re-check could resolve has
            # already been resolved by the time this runs (validation/run.js runs it
            # before select); one that is STILL pending after that many detonations
            # is not waiting on a rule, it is a use-case nobody can measure, and it
            # must stop out-ranking the 96 use-cases that can be.
            if consecutive_pending_detonations(e) <= PENDING_RETEST_MAX:
                pending.append(u["id"])
                continue
            # Over the bound. It drops to the STALENESS lane - never to lanes 2 or 3,
            # whose tests read `vs[-1]`, the last REAL verdict, which for a row that
            # is pending NOW is some earlier night's. Calling a currently-unmeasured
            # use-case a regression on the strength of a verdict it has since
            # superseded would be a worse lie than the starvation this bound fixes.
            if _past_staleness(u, e, now, bounds):
                stale.append(u["id"])
            continue
        # REAL verdicts only. Every detonation writes PENDING first and the re-check
        # supersedes it by appending, so the raw history reads
        # [... PENDING, PENDING, MISSED] and `vs[-2]` is PENDING for 81 of the 82
        # pool members - measured 2026-08-05. Tested against the raw list, lane 2
        # could not fire for anything, ever.
        vs = [v for v in (e.get("verdicts") or []) if v in REAL_VERDICTS]
        if len(vs) >= 2 and vs[-1] == "MISSED" and vs[-2] in ("DETECTED", "PREVENTED"):
            regressions.append(u["id"])
            continue
        # A standing MISSED is re-measured a BOUNDED number of times. Three
        # consecutive misses is no longer news, it is a finding someone has to act
        # on (fix the payload, fix the rule, or write `expect: env_gap` with the
        # measured reason), and a use-case that can never fire here must not hold a
        # nightly slot forever - that would starve the rotation exactly the way
        # yesterday's PENDING used to.
        if vs and vs[-1] == "MISSED":
            consecutive = 0
            for v in reversed(vs):
                if v != "MISSED":
                    break
                consecutive += 1
            if consecutive <= MISSED_RETEST_MAX:
                missed.append(u["id"])
                continue
        if _past_staleness(u, e, now, bounds):
            stale.append(u["id"])
    return pending, regressions, missed, stale


# --- confirmed regression versus first miss (slice 6, 2026-10-22) --------------------------
#
# A MISSED is not one thing. A use-case that has never detected is a gap someone has to
# close, a use-case that detected last time and missed tonight may be a flake or a lab
# hiccup, and only a use-case that detected once and has now missed twice in a row is a
# regression the founder has to be woken for. The loop turns red on the third kind only
# (validation/run.js verifyPass); this is where the three are told apart.
GOOD_FINALS = ("DETECTED", "PREVENTED")


def _utc(iso):
    """A ledger timestamp as an aware datetime. Naive means UTC, which is what the engine writes."""
    t = _parse_ts(iso)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _finals(rows, placed=True):
    """[(when, verdict)], one per DETONATION, oldest first, REAL verdicts only.

    A detonation is (id, run_ts): a re-check row carries the ORIGINAL run_ts, so a MISSED that
    --recheck-missed later corrected to DETECTED is one detonation whose last final wins, not a
    miss followed by a hit (that reading would call every corrected ingest delay a flap).
    The sort is stable, so equal timestamps keep file order.

    `placed=True` raises ValueError for a final row whose run_ts is missing or unparseable: a
    miss that cannot be ordered is not skipped, because skipping it can turn a confirmed
    regression into a first miss, and the gate would go green over a broken detection. The
    caller decides what an unplaceable history means. `placed=False` drops such rows instead,
    for the flapping metric, which only counts and gates nothing.
    """
    last = {}
    for r in rows:
        v = r.get("verdict")
        if v not in REAL_VERDICTS:
            continue
        last[(r.get("id"), r.get("run_ts"))] = (r, v)
    out = []
    for (uid, ts), (_r, v) in last.items():
        try:
            when = _utc(ts)
        except (TypeError, ValueError):
            if placed:
                raise ValueError(f"a {v} row of {uid} has no usable run_ts ({ts!r})")
            continue
        out.append((when, v))
    out.sort(key=lambda x: x[0])
    return out


def prior_finals(rows, run_ts):
    """The final rows of `rows` from detonations strictly BEFORE `run_ts`.

    The history a re-check classifies against. The row being re-checked, and anything
    written for the same detonation, must not be in it: with tonight's own MISSED in the
    list a first miss reads as the second one.
    """
    cutoff = _utc(run_ts)
    return [r for r in rows if r.get("verdict") in REAL_VERDICTS and _utc(r.get("run_ts")) < cutoff]


def miss_class(rows, tonight_verdict):
    """Why a MISSED is, or is not, an alarm. `rows` are one use-case's ledger rows from BEFORE tonight.

    None unless tonight's verdict is MISSED. Then:
      never_detected        no earlier final is DETECTED or PREVENTED (includes an empty history),
      first_miss            the last earlier final is DETECTED or PREVENTED,
      confirmed_regression  the last earlier final is MISSED and a still earlier one was good.

    An empty list means "never measured", so a caller that could not READ the ledger must not
    pass [] here: it must leave the class None, which the loop treats as red.
    Raises ValueError when a final row cannot be placed in time (see _finals).
    """
    if tonight_verdict != "MISSED":
        return None
    finals = [v for _when, v in _finals(rows)]
    if not any(v in GOOD_FINALS for v in finals):
        return "never_detected"
    return "first_miss" if finals[-1] in GOOD_FINALS else "confirmed_regression"


def flapping(rows, now, days=30):
    """Sorted ids whose finals inside [now - days, now] hold both MISSED and DETECTED or PREVENTED.

    The nights a use-case flips are the nights its verdict says least about the rule, so the
    report counts them apart from the standing misses. A detonation outside the window, or one
    whose run_ts cannot be read, does not count.
    """
    now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    start = now - timedelta(days=days)
    by_id = {}
    for r in rows:
        if r.get("id"):
            by_id.setdefault(r["id"], []).append(r)
    out = []
    for uid, mine in by_id.items():
        vs = {v for when, v in _finals(mine, placed=False) if start <= when <= now}
        if "MISSED" in vs and vs & set(GOOD_FINALS):
            out.append(uid)
    return sorted(out)


def select_nightly(usecases, ledger_rows, k, now=None, k_max=K_MAX, allow_internet=False):
    """The whole selection, deterministic. Returns (ids, meta)."""
    now = now or datetime.now(timezone.utc)
    idx = index_ledger(ledger_rows)
    # Cooling: inside a target rule's memory since its last detonation. Out of the
    # pool for tonight, so no lane (regression, standing MISSED, staleness) can hand
    # it a slot it would only turn into a guaranteed MISSED.
    cooling = sorted(u["id"] for u in safe_pool(usecases, allow_internet=allow_internet)
                     if in_rule_memory(u, idx.get(u["id"]), now))
    pool = [u for u in safe_pool(usecases, allow_internet=allow_internet) if u["id"] not in set(cooling)]
    by_id = {u["id"]: u for u in pool}
    # CLAMP FIRST, then derive the bounds from what will actually run tonight. The
    # other order read the cap for both, which is the whole 71-of-97 defect.
    k = max(K_MIN, min(int(k), k_max))
    bounds = staleness_bounds(len(pool), k)
    pending, regressions, missed, stale = priority_ids(pool, idx, now, bounds)

    # Within each priority group, order by debt descending then id, so a never-run
    # use-case (infinite debt) leads the stale group and every tie breaks identically
    # on every run.
    def by_debt(uid):
        return (-debt(by_id[uid], idx.get(uid), now), uid)

    ordered = []
    for group in (pending, regressions, missed, stale):
        for uid in sorted(group, key=by_debt):
            if uid not in ordered:
                ordered.append(uid)

    # Then debt ranking over whatever is left. Ties break on id, so the selection is
    # a pure function of (registry, ledger, clock, k).
    rest = sorted((uid for uid in by_id if uid not in ordered), key=by_debt)
    ordered.extend(rest)

    # A powered DC with a safe use-case must be exercised, not merely sit in the
    # same debt queue as roughly one hundred workstation cases. Reserve one slot
    # per explicit non-default target, ordered deterministically. The target's own
    # debt still decides which of its use-cases occupies that slot, so additional
    # DC cases rotate rather than being starved by the reservation.
    targets = sorted({u.get("target", "workstation") for u in pool})
    reserved = []
    for target in (t for t in targets if t != "workstation"):
        uid = next((candidate for candidate in ordered
                    if by_id[candidate].get("target", "workstation") == target), None)
        if uid is not None:
            reserved.append(uid)
    ids = (reserved + [uid for uid in ordered if uid not in reserved])[:k]
    flaps = flapping(ledger_rows, now)
    meta = {
        "pool": len(pool),
        "k": k,
        "cycle_nights": cycle_nights(len(pool), k),
        "staleness_bound_nights": bounds[0],
        "staleness_bound_high_nights": bounds[1],
        "pending": len(pending),
        "regressions": len(regressions),
        "missed": len(missed),
        "stale": len(stale),
        "targets": targets,
        "cooldown": len(cooling),
        "cooldown_ids": cooling,
        "flapping": len(flaps),
        "flapping_ids": flaps,
    }
    return ids, meta


def rows_with_verdict(ledger_rows, verdicts):
    """The ledger rows whose LATEST verdict for that id is one of `verdicts`."""
    wanted = set(verdicts)
    latest = {}
    for r in ledger_rows:
        if r.get("id"):
            latest[r["id"]] = r
    return [r for r in latest.values() if r.get("verdict") in wanted]


def pending_rows(ledger_rows):
    """The ledger rows whose LATEST verdict for that id is still PENDING."""
    return rows_with_verdict(ledger_rows, ("PENDING",))
