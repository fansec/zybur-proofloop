# rules/engine/result.py
"""The per-use-case Result and the six-state verdict."""
import enum
from dataclasses import dataclass, asdict, field

class Verdict(enum.Enum):
    DETECTED = "DETECTED"
    PREVENTED = "PREVENTED"
    MISSED = "MISSED"
    PENDING = "PENDING"
    INCONCLUSIVE = "INCONCLUSIVE"
    ABORT = "ABORT"

# Spec precedence: ABORT > INCONCLUSIVE > DETECTED > PREVENTED > PENDING > MISSED.
# Lower number wins. It exists so a prevention can never mask a real detection and
# MISSED survives only when nothing fired at all.
#
# This orders SIMULTANEOUS signals about one detonation. It is NOT how a re-check
# supersedes an earlier row: a later measurement of a PENDING use-case replaces it,
# whatever the precedence says.
PRECEDENCE = {
    Verdict.ABORT: 0,
    Verdict.INCONCLUSIVE: 1,
    Verdict.DETECTED: 2,
    Verdict.PREVENTED: 3,
    Verdict.PENDING: 4,
    Verdict.MISSED: 5,
}

def worst(verdicts):
    """The highest-precedence verdict in a set, or None for an empty set."""
    vs = [v for v in verdicts if v is not None]
    return min(vs, key=PRECEDENCE.get) if vs else None

@dataclass
class Result:
    id: str
    rule_ids: list
    executor: str
    executed: bool
    status: str
    verdict: Verdict = None
    attack_start: str = None
    attack_end: str = None
    latency_s: float = None
    output: str = ""
    op_id: str = ""
    expect: str = "detected"
    host: dict = None
    co_firing: list = field(default_factory=list)
    rule_versions: dict = field(default_factory=dict)
    # {rule_id: rulehash.rule_query_hash of that rule in the committed export}, for the
    # rule_ids in rule_versions. A rule outside the export (a managed rule) has no key.
    rule_query_hashes: dict = field(default_factory=dict)
    # Set only by an executor that generated a {{NONCE}} itself (C-S5, 2026-10-19:
    # rules/engine/executors/winrm_command.py, for the canary use-case). The exact
    # literal value templated into the command BEFORE it was ever sent - never one
    # read back out of stdout - so a caller that already has this Result has the
    # one value worth polling Elastic for, with nothing left to parse.
    nonce: str = None
    # Why the verdict is what it is, when the verdict alone would mislead. Set by
    # run.py's memory check (2026-10-22): a MISSED against a new-terms rule whose memory
    # already held this host becomes INCONCLUSIVE, and this says so in words. Surfaced in
    # the ledger row and the report; absent on every other row.
    verdict_reason: str = None
    # What kind of MISSED this is, set by run.py against the ledger from BEFORE this detonation
    # (selector.miss_class): never_detected, first_miss or confirmed_regression. None for every
    # other verdict, and None when the ledger could not be read, which the loop treats as red.
    miss_class: str = None

    def to_dict(self):
        d = asdict(self)
        d["verdict"] = self.verdict.name if self.verdict else None
        return d

def make_result(usecase, status, executed, **kw):
    out = kw.pop("output", "")
    kw.setdefault("expect", usecase.get("expect", "detected"))
    return Result(
        id=usecase["id"],
        rule_ids=list(usecase.get("rule_ids") or []),
        executor=usecase.get("executor", ""),
        executed=executed,
        status=status,
        output=out[:500] if out else "",
        **kw,
    )
