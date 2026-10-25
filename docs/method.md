# The method

How Zybur Proofloop turns "a technique ran on a host" and "these alerts exist" into one verdict per
use-case. Everything here is in `engine/verify.py`, `engine/result.py` and `engine/run.py`; the
constants are named so you can find them.

## The six verdicts

| Verdict | Meaning |
|---|---|
| `DETECTED` | A target rule of the use-case fired on the target host inside the use-case's window. |
| `PREVENTED` | No target rule fired, the rule is due, and an Endpoint prevention alert sits in the window. |
| `MISSED` | The rule is due, the SIEM answered, and nothing in the window explains the silence. |
| `PENDING` | The rule is not due yet. A later re-check measures it. |
| `INCONCLUSIVE` | Could not measure: the SIEM did not answer, no rule resolved, the use-case does not expect a detection (`expect: env_gap` or `not_enabled`), or a new-terms rule already remembered this host (see below). |
| `ABORT` | The technique never ran (`executed: false`); the ledger row carries the executor's reason. |

When several signals describe one detonation, the precedence is
`ABORT > INCONCLUSIVE > DETECTED > PREVENTED > PENDING > MISSED` (`result.PRECEDENCE`): a
prevention can never hide a real detection, and `MISSED` survives only when nothing else applies.
Precedence orders simultaneous signals; it is not how a re-check works. A later measurement of a
`PENDING` row replaces it.

`classify()` in `verify.py` decides in this order: not executed is `ABORT`; a use-case that does
not expect detection, an unanswered query or no resolved rule is `INCONCLUSIVE`; a target alert in
the window is `DETECTED`; before the due time it is `PENDING`; a prevention in the window is
`PREVENTED`; otherwise `MISSED`.

## Due time

A rule can only be judged once it has had a chance to run over the attack:

```
due = attack_end + the rule's schedule interval + 120 s
```

`EXEC_SLACK_S` is the 120 seconds: the measured 99.9th percentile of Elastic's schedule delay was
about 3 seconds, so this is wide headroom. A use-case with several target rules is due at the
earliest of their due times. Correlation is on the rule's `rule_id`, never on its name or its
saved-object id.

## Behaviour time

An alert is placed in time by when the behaviour happened, not when the alert was written:
`kibana.alert.original_time`, falling back to `@timestamp`. Elastic Defend writes prevention alerts
in batches, so the write time can trail the behaviour by tens of seconds and land inside the next
detonation's window. Two refinements (`behavior_ts`):

- An `original_time` later than the alert itself (a guest clock running fast) is not believed; the
  source event's ingest time is used instead when it is earlier.
- A sequence (EQL) alert's own timestamp is close to its write time. Its behaviour time is the
  earliest `original_time` among its building blocks with the same group id; without them it
  cannot be placed and does not count. A building block of a sequence is never a target hit on its
  own.

## The prevention discriminator

An alert is a prevention when it comes from Elastic Defend (`event.dataset: endpoint.alerts`, or no
dataset) and its `event.type` contains `denied` (`is_prevention`). A detection rule over a Windows
event that was itself a block (a firewall drop carries `denied` too) is from another dataset and is
not a prevention. The rule-name prefixes of Defend's prevention alerts ("Malware Prevention Alert",
"Malicious Behavior Prevention Alert", ...) are a fallback for documents without `event.type`.

## The window

A detonation owns the alerts on its target host (by host name, alias or agent id) between two
bounds:

- **Lower:** its own `attack_start` less `CLOCK_SKEW_S` (5 seconds), because the attack is timed by
  the machine running Zybur Proofloop and the behaviour by the Windows host, and nothing synchronises
  them. The tolerance is clamped: it never reaches back past the end of the previous detonation on
  that host (and, for a target rule, past the previous detonation that targeted the same rule).
- **Upper:** the next detonation's start less the same 5 seconds, so the two windows meet without
  overlapping, and never before this detonation's own `attack_end`. A detonation is never clipped
  inside its own execution. One exception, for the use-case's own target rule: when no later
  detonation targets that rule, its alert may land up to `UNCONTESTED_GRACE_S` (the same 5
  seconds) beyond this bound and still count, because a threshold or new-terms alert can be placed
  there by clock skew for the right detonation. Further out it is not this detonation's evidence,
  and a rule that a later detonation also targets keeps the plain bound. `ZYBUR_UNCONTESTED_GRACE_S`
  overrides the 5 seconds for a measurement (a very large value restores the unbounded exemption).

Alerts outside the window, or on another host, are not this use-case's evidence. Alerts inside it
from rules the use-case does not target are recorded as `co_firing`.

## Spacing

Two detonations on the same host start at least `DETONATION_GAP_S` apart (10 seconds,
`ZYBUR_DETONATION_GAP_S`; 0 disables it), measured from the ledger as well as the current run.
At that gap the previous detonation's end is never inside the clock-skew tolerance, so the lower
bound above is the tolerance itself, as designed. A run whose detonations ended up closer prints a
warning.

## Re-checks

Nothing is final while it may still change:

- `run.py --recheck-pending` re-verifies every `PENDING` row. No detonation.
- `run.py --recheck-missed [DAYS]` re-verifies `MISSED` rows from the last DAYS days (default 7,
  at most 21). Alerts can be ingested hours late; a re-check that finds the target alert turns the
  row `DETECTED`. It never reaches past the SIEM's retention, because a deleted alert would read as
  a confident, wrong `MISSED`. Only verdicts that changed are written.

## New-terms rules

A new-terms rule alerts only on a value it has not seen inside its history window (for example
`now-5d`). Running the same technique on the same host inside that window cannot fire it. A
`MISSED` against such a rule whose memory already held this host becomes `INCONCLUSIVE` with a
`verdict_reason` saying so, and the selector keeps the use-case out of the rotation until the
window has passed.

## Proof staleness

A `DETECTED` row proves a rule as it was. The row records, per target rule, its version and a hash
of its query (`rulehash.py`: sha256, first 16 hex characters, over canonical JSON of the fields that
decide what the rule matches: type, language, query, index, filters, threshold, new-terms fields
and window, threat-match and machine-learning fields). A proof whose recorded query hash differs
from the rule's hash in the current pack is stale: the rule that was proven is not the rule that
runs now. A version bump alone (Elastic re-versions rules for tag changes) does not make a proof
stale. The engine records both on every row and leaves the judgement to whoever reads the ledger;
it does not itself take a stale proof out of the rotation.

## The ledger

`engine/state/ledger.jsonl`, one JSON object per line, append-only. A row holds: the use-case `id`,
its target `rule_ids`, `run_ts`, the target `host` (name, agent id, aliases), the `verdict`,
`latency_s` (seconds from `attack_start` to the first target alert's `@timestamp`), `attack_start` and
`attack_end`, `co_firing`, `rule_versions` and `rule_query_hashes`; an `ABORT` row adds `error`,
a re-check row adds `rechecked_at`, and a row whose verdict needs explaining adds
`verdict_reason`. The selector (`selector.py`, `run.py --select-nightly K`) reads the ledger to
choose the next night from the safe pool, deterministically: yesterday's `PENDING` rows, a suspected
regression (a healthy run, then a miss), a standing `MISSED` (both retests bounded), anything past
its staleness bound or never run, and then the rest by debt (time since the last run, weighted by
severity and by how often the verdict flapped).
