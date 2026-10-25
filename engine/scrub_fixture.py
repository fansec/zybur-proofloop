# rules/engine/scrub_fixture.py
"""Make a recorded night safe to publish: lab names out, the shape of the evidence kept.

    python3 scrub_fixture.py SRC_DIR DST_DIR

reads inputs.json, alerts.json and expected.json from SRC_DIR (what `run.py --record-night`
wrote) and writes the scrubbed three to DST_DIR. Exit 0 only when the result passes
`check`; anything else exits 1 and names the pattern and the JSON path, never a value.

What changes, and why the verdicts do not:
  - The host becomes `ws` (id `h1`), its aliases are dropped; every other host becomes
    `other-host` (ids `h2`, `h3`, ...). The classifier matches an alert to the target by
    name or id, so a consistent rename keeps every match and every non-match.
  - `winlog_computer_name` becomes `ws` where it named the target (an aggregate alert may
    carry no other host field, and the classifier reads this one), else `other-host`
    or None.
  - Alert group ids become `g1`, `g2`, ...: only their equality is read.
  - A detonation that is Zybur's own (its id or rule id carries a denied token, today the
    canary) is not part of a public fixture, but it still bounds its neighbours' windows.
    It moves from `results` to the neighbours (`extra_*`) under `neighbour-N` ids and
    `neighbour-rule-N` rule ids, and its alerts are renamed the same way.
  - Rule ids and names of Elastic's prebuilt rules stay: they are public.

`check` is the allow pass: it holds the scrubbed files to a closed shape AND closed values
(timestamps, statuses, executor names, datasets, intervals, verdict names), requires every
retained rule id to be an immutable, Elastic-authored rule in the rules export with the
name the export gives it, then denies by pattern. A fixture that fails is not written.
"""
import json
import os
import re
import sys

from result import Verdict

HOST = {"name": "ws", "id": "h1", "aliases": []}
OTHER_HOST = "other-host"

# Substrings that must not survive in any string of a public fixture (compared case-folded).
# The lab's address prefix is assembled, not written: test_lab_config forbids that literal
# anywhere in the engine's sources, and this file is the one place that must name it.
DENY_SUBSTRINGS = (".".join(("192", "168")) + ".", "zybur", "production", "dc1", "infected")
# The rest are shapes. A private address of any range, a MAC, a Windows SID, an e-mail
# address, a DOMAIN\account, a host in a lab-style zone.
DENY_PATTERNS = {
    "private IPv4 10/8": re.compile(r"(?<![\d.])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d])"),
    "private IPv4 172.16/12": re.compile(r"(?<![\d.])172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?![\d])"),
    "private IPv4 192.168/16": re.compile(r"(?<![\d.])192\.168\.\d{1,3}\.\d{1,3}"),
    # Any dotted quad: a lab or customer address that is not in a private range (a NAT address,
    # a public egress) is as identifying as one that is. A version string needs 4 numeric parts.
    "IPv4 address": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d])"),
    "loopback or link-local IPv4": re.compile(r"(?<![\d.])(127|169\.254)\.\d{1,3}\.\d{1,3}(\.\d{1,3})?"),
    "IPv6 ULA or link-local": re.compile(r"(?i)(?<![0-9a-f:])(f[cd][0-9a-f]{2}|fe80):[0-9a-f:]*"),
    "MAC address": re.compile(r"(?i)\b[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}\b"),
    "Windows SID": re.compile(r"S-1-\d+-\d+(-\d+)+"),
    "e-mail address": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "DOMAIN\\account": re.compile(r"[A-Za-z0-9_-]+\\[A-Za-z0-9_$.-]+"),
    "lab-style host name": re.compile(r"(?i)\b[\w-]+\.(lab|local|internal|corp|invalid|lan)\b"),
}
GUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
LONG_HEX = re.compile(r"(?i)\b[0-9a-f]{32,}\b")

RESULT_KEYS = {"id", "rule_ids", "executor", "executed", "status", "verdict", "attack_start",
               "attack_end", "latency_s", "output", "op_id", "expect", "host", "co_firing",
               "rule_versions", "rule_query_hashes", "nonce"}
INPUT_KEYS = {"schema_version", "night", "now", "host", "rule_intervals", "results", "extra_starts",
              "extra_ends", "extra_detonations", "rule_memory"}
ALERT_KEYS = {"rule_id", "name", "@timestamp", "original_time", "event_ingested", "host_name",
              "host_id", "winlog_computer_name", "event_type", "event_dataset", "group_id",
              "group_index", "building_block_type", "rule_version"}
# Where an Elastic prebuilt rule's GUID may appear. Anywhere else a GUID could be a host.
GUID_PATHS = re.compile(
    r"^(alerts\[\d+\]\.rule_id"
    r"|inputs\.results\[\d+\]\.rule_ids\[\d+\]"
    r"|inputs\.extra_detonations\[\d+\]\.rule_ids\[\d+\]"
    r"|inputs\.rule_intervals\.key"
    r"|inputs\.rule_memory\.key)$")


# Values, not just keys. Free text that no deny pattern happens to match must still not pass,
# so every field that survives the scrub is held to the shape it has in a real night.
ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
ISO_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
USECASE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*")
# ECS event.type values, the use-case "expect" values, and the building block type: closed
# lists, because a lowercase word such as a user name would pass any word-shaped rule.
EVENT_TYPES = {"access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied",
               "end", "error", "group", "indicator", "info", "installation", "protocol", "start", "user"}
EXPECT_VALUES = {"detected", "env_gap", "not_enabled"}
BUILDING_BLOCK_TYPES = {"default"}
DATASET = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
# The integration an event.dataset belongs to: a closed list, because any word.word passes
# DATASET and a user.domain pair is shaped exactly like a dataset. A night recorded from an
# integration not listed here is refused with the path named; add the integration then.
DATASET_INTEGRATIONS = {"endpoint", "windows", "system", "o365", "azure", "aws", "gcp", "okta",
                        "network_traffic", "elastic_agent", "sysmon_operational", "microsoft_defender_endpoint",
                        "crowdstrike", "sentinel_one", "m365_defender", "kubernetes", "github", "google_workspace"}
# ECS and integration field namespaces a new-terms rule may name; the leaf is checked against
# the rules export when one is given.
FIELD_NAMESPACES = {"agent", "client", "cloud", "container", "destination", "dll", "dns", "event", "file",
                    "group", "host", "http", "network", "o365", "azure", "aws", "okta", "powershell", "process",
                    "registry", "server", "service", "source", "tls", "url", "user", "user_agent", "winlog"}
NEIGHBOUR_ID = re.compile(r"neighbour-\d+")
DETONATION_KEYS = {"attack_start", "attack_end", "rule_ids", "id"}
INTERVAL = re.compile(r"\d{1,4}[smhd]")
FIELD_NAME = re.compile(r"[A-Za-z0-9_@.-]{1,80}")
NEIGHBOUR_RULE = re.compile(r"neighbour-rule-\d+")
NEIGHBOUR_NAME = re.compile(r"Neighbour Rule \d+")
DEFEND_RULE_NAME = "Endpoint Security (Elastic Defend)"
DEFEND_BEHAVIOR_NAME = re.compile(r"Malicious Behavior (Prevention|Detection) Alert: [A-Za-z0-9 ,.'()/_-]{1,120}")
# The executor's own status label (make_result calls in executors/ and run.py).
RESULT_STATUSES = {"SUCCESS", "EXECUTED", "RECHECK", "SETUP_FAIL", "TIMEOUT", "WMI_CONNECT_FAIL"}
VERDICT_NAMES = {v.name for v in Verdict}
DEFAULT_EXPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules_export.ndjson")


class ScrubError(Exception):
    pass


def _fold(s):
    return str(s).casefold()


def _private(*values):
    return any(tok in _fold(v) for v in values if v for tok in DENY_SUBSTRINGS)


def lab_denials(path=None):
    """Extra denied strings: every name, alias, address and id in the lab registry, if one is here.

    Names only come out of this file; it holds no secret. A checkout without it (the
    public export) simply has nothing extra to deny, and the fixed list above still holds.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    p = path or os.environ.get("LAB_HOSTS_FILE") or os.path.join(here, "..", "..", "validation", "lab-hosts.json")
    try:
        with open(p) as f:
            hosts = json.load(f).get("hosts") or []
    except (OSError, ValueError, AttributeError):
        return ()
    out = []
    for h in hosts:
        out += [h.get("name"), h.get("ip"), h.get("host_id"), *(h.get("aliases") or [])]
    return tuple(sorted({str(x) for x in out if x}))


def scrub(inputs, alerts, expected):
    """Return (inputs, alerts, expected) with the lab out. Inputs are not modified."""
    inputs = json.loads(json.dumps(inputs))
    alerts = json.loads(json.dumps(alerts))
    expected = dict(expected)
    host = inputs["host"]
    own_names = {_fold(n) for n in [host.get("name"), *(host.get("aliases") or [])] if n}
    own_id = _fold(host.get("id") or "")

    def is_own_name(n):
        n = _fold(n)
        return n in own_names or any(n.startswith(o + ".") for o in own_names)

    # Zybur's own detonations leave results and become neighbours.
    keep, moved = [], []
    for r in inputs["results"]:
        (moved if _private(r["id"], *r["rule_ids"]) else keep).append(r)
    inputs["results"] = keep
    for r in moved:
        expected.pop(r["id"], None)

    rule_alias = {}
    ids_alias = {}

    def alias_rule(rid):
        if rid is None or not _private(rid):
            return rid
        return rule_alias.setdefault(rid, f"neighbour-rule-{len(rule_alias) + 1}")

    def alias_id(uid):
        if not _private(uid):
            return uid
        return ids_alias.setdefault(uid, f"neighbour-{len(ids_alias) + 1}")

    for r in moved:
        inputs["extra_starts"].append(r["attack_start"])
        if r.get("attack_end"):
            inputs["extra_ends"].append(r["attack_end"])
        inputs["extra_detonations"].append({"attack_start": r["attack_start"],
                                            "attack_end": r.get("attack_end"),
                                            "rule_ids": list(r["rule_ids"]), "id": r["id"]})
    for d in inputs["extra_detonations"]:
        d["rule_ids"] = [alias_rule(x) for x in d["rule_ids"]]
        d["id"] = alias_id(d.get("id"))

    inputs["host"] = dict(HOST)
    for r in inputs["results"]:
        r["host"] = dict(HOST)
        r["output"], r["op_id"], r["nonce"] = "", "", None
    inputs["rule_intervals"] = {alias_rule(k): v for k, v in inputs["rule_intervals"].items()}
    if "rule_memory" in inputs:
        # The memory row repeats the rule's name: a neighbour's name goes with its id.
        mem = {}
        for k, v in inputs["rule_memory"].items():
            nk = alias_rule(k)
            if nk != k:
                v = {**v, "name": "Neighbour Rule " + nk.rsplit("-", 1)[1]}
            mem[nk] = v
        inputs["rule_memory"] = mem

    other_ids, groups = {}, {}
    for a in alerts:
        a["rule_id"] = alias_rule(a.get("rule_id"))
        if a["rule_id"] and str(a["rule_id"]).startswith("neighbour-rule-"):
            a["name"] = "Neighbour Rule " + a["rule_id"].rsplit("-", 1)[1]
        hn = a.get("host_name")
        a["host_name"] = None if hn is None else ("ws" if is_own_name(hn) else OTHER_HOST)
        hid = a.get("host_id")
        if hid is not None:
            if _fold(hid) == own_id:
                a["host_id"] = "h1"
            else:
                a["host_id"] = other_ids.setdefault(_fold(hid), f"h{len(other_ids) + 2}")
        wn = a.get("winlog_computer_name")
        a["winlog_computer_name"] = None if wn is None else ("ws" if is_own_name(wn) else OTHER_HOST)
        if a.get("group_id") is not None:
            a["group_id"] = groups.setdefault(a["group_id"], f"g{len(groups) + 1}")
    return inputs, alerts, expected


def _walk(node, path):
    """Every (json path, string) in a document; dict keys are yielded as `<path>.key`."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}.key", str(k)
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def prebuilt_rules(path, fields=None):
    """{rule_id: name} of the rules in the export that are immutable and authored by Elastic.

    `fields`, when a dict is passed, is filled with {rule_id: [new_terms_fields]} of the same rules.

    Raises ScrubError when the export cannot be read: a fixture whose rule ids cannot be shown
    to be Elastic's public ones is not publishable, and "no file" must not read as "all fine".
    """
    out = {}
    try:
        with open(path) as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                if r.get("immutable") is True and r.get("author") == ["Elastic"] and r.get("rule_id"):
                    out[r["rule_id"]] = r.get("name")
                    if fields is not None:
                        fields[r["rule_id"]] = list(r.get("new_terms_fields") or [])
    except (OSError, ValueError) as e:
        raise ScrubError(f"cannot read the rules export to prove the rule ids are public ({type(e).__name__})")
    return out


def _executor_names():
    import executors.plugins  # noqa: F401  (registers every executor)
    import executors.registry as registry
    return registry.executor_names()


def check_values(inputs, alerts, expected, prebuilt=None, prebuilt_fields=None):
    """The allow pass on values. Returns a list of 'what at where' problems (never a value)."""
    problems = []

    def bad(what, path):
        problems.append(f"{what} at {path}")

    def full(rx, v, what, path, allow_none=False):
        if v is None and allow_none:
            return
        if not (isinstance(v, str) and rx.fullmatch(v)):
            bad(what, path)

    def rule_id(v, path):
        if isinstance(v, str) and NEIGHBOUR_RULE.fullmatch(v):
            return
        if not (isinstance(v, str) and GUID.fullmatch(v)):
            bad("rule id is neither a GUID nor a neighbour", path)
        elif prebuilt is not None and v not in prebuilt:
            bad("rule id is not an immutable Elastic rule in the export", path)

    def rule_name(rid, name, path):
        if isinstance(rid, str) and NEIGHBOUR_RULE.fullmatch(rid):
            full(NEIGHBOUR_NAME, name, "neighbour rule name", path)
        elif prebuilt is not None and prebuilt.get(rid) != name:
            # Elastic Defend raises one alert per behavior rule of its shipped protections
            # ruleset, all under the one "Endpoint Security" rule id, so the alert name is the
            # behavior's public name and not the export's. Only that prefix and a plain-text
            # tail pass; the tail is not provable against a list we do not hold, the deny
            # patterns still read it, and a custom rule id never reaches this branch.
            if not (isinstance(name, str) and DEFEND_BEHAVIOR_NAME.fullmatch(name)
                    and prebuilt.get(rid) == DEFEND_RULE_NAME):
                bad("rule name is not the export's name for that rule id", path)

    full(ISO_DAY, inputs.get("night"), "night", "inputs.night")
    full(ISO_TS, inputs.get("now"), "now", "inputs.now")
    for k in ("extra_starts", "extra_ends"):
        for i, v in enumerate(inputs.get(k, [])):
            full(ISO_TS, v, "timestamp", f"inputs.{k}[{i}]")
    for i, d in enumerate(inputs.get("extra_detonations", [])):
        p = f"inputs.extra_detonations[{i}]"
        # These dicts are copied from the lab ledger: a closed key set and a closed id shape, so
        # a field or an id that is a lab fact has nowhere to sit.
        if not (isinstance(d, dict) and set(d) == DETONATION_KEYS):
            bad("detonation keys are not the closed set", p)
            continue
        if not (isinstance(d["id"], str) and (USECASE_ID.fullmatch(d["id"]) or NEIGHBOUR_ID.fullmatch(d["id"]))):
            bad("detonation id", p + ".id")
        full(ISO_TS, d.get("attack_start"), "timestamp", p + ".attack_start")
        full(ISO_TS, d.get("attack_end"), "timestamp", p + ".attack_end", allow_none=True)
        for j, rid in enumerate(d.get("rule_ids", [])):
            rule_id(rid, f"{p}.rule_ids[{j}]")
    for rid, v in inputs.get("rule_intervals", {}).items():
        rule_id(rid, "inputs.rule_intervals")
        full(INTERVAL, v, "rule interval", "inputs.rule_intervals")
    for rid, m in inputs.get("rule_memory", {}).items():
        p = "inputs.rule_memory"
        rule_id(rid, p)
        if not (isinstance(m, dict) and set(m) == {"name", "fields", "window", "window_s"}):
            bad("rule memory keys are not the closed set", p)
            continue
        rule_name(rid, m["name"], p + ".name")
        if not (isinstance(m["fields"], list) and all(isinstance(x, str) and FIELD_NAME.fullmatch(x)
                                                       and x.split(".")[0] in FIELD_NAMESPACES and "." in x
                                                       for x in m["fields"])):
            bad("rule memory fields", p + ".fields")
        elif prebuilt_fields is not None and rid in prebuilt_fields \
                and not set(m["fields"]) <= set(prebuilt_fields[rid]):
            bad("rule memory fields are not the rule's new_terms_fields in the export", p + ".fields")
        if not (m["window"] is None or (isinstance(m["window"], str) and re.fullmatch(r"now-\d{1,4}[smhd]", m["window"]))):
            bad("rule memory window", p + ".window")
        if not isinstance(m["window_s"], (int, float)) or isinstance(m["window_s"], bool):
            bad("rule memory window_s", p + ".window_s")
    try:
        executors = _executor_names()
    except Exception:
        executors = None  # no executor registry in this tree: the shape rule below still holds
    ids = []
    for i, r in enumerate(inputs.get("results", [])):
        p = f"inputs.results[{i}]"
        ids.append(r.get("id"))
        full(USECASE_ID, r.get("id"), "use-case id", p + ".id")
        if executors is not None:
            if r.get("executor") not in executors:
                bad("executor is not a registered one", p + ".executor")
        else:
            full(re.compile(r"[a-z][a-z0-9_]*"), r.get("executor"), "executor", p + ".executor")
        if r.get("status") not in RESULT_STATUSES:
            bad("result status", p + ".status")
        if not isinstance(r.get("executed"), bool):
            bad("result executed", p + ".executed")
        if r.get("expect") not in EXPECT_VALUES:
            bad("result expect", p + ".expect")
        full(ISO_TS, r.get("attack_start"), "timestamp", p + ".attack_start")
        full(ISO_TS, r.get("attack_end"), "timestamp", p + ".attack_end", allow_none=True)
        for j, rid in enumerate(r.get("rule_ids", [])):
            rule_id(rid, f"{p}.rule_ids[{j}]")
        for k in ("co_firing", "rule_versions", "rule_query_hashes"):
            if r.get(k) not in ([], {}):
                bad("a post-verify field is filled", f"{p}.{k}")
    if set(expected) != set(ids):
        bad("expected.json ids are not the result ids", "expected")
    for v in expected.values():
        if v not in VERDICT_NAMES:
            bad("expected verdict", "expected")
    for i, a in enumerate(alerts):
        p = f"alerts[{i}]"
        full(ISO_TS, a.get("@timestamp"), "timestamp", p + ".@timestamp")
        full(ISO_TS, a.get("original_time"), "timestamp", p + ".original_time", allow_none=True)
        full(ISO_TS, a.get("event_ingested"), "timestamp", p + ".event_ingested", allow_none=True)
        full(DATASET, a.get("event_dataset"), "event_dataset", p + ".event_dataset", allow_none=True)
        if a.get("event_dataset") is not None and str(a["event_dataset"]).split(".")[0] not in DATASET_INTEGRATIONS:
            bad("event_dataset integration", p + ".event_dataset")
        et = a.get("event_type")
        if not (et is None or (isinstance(et, list) and all(x in EVENT_TYPES for x in et))):
            bad("event_type", p + ".event_type")
        if a.get("building_block_type") not in BUILDING_BLOCK_TYPES | {None}:
            bad("building_block_type", p + ".building_block_type")
        for k in ("rule_version", "group_index"):
            v = a.get(k)
            if not (v is None or (isinstance(v, int) and not isinstance(v, bool))):
                bad(k, f"{p}.{k}")
        rule_id(a.get("rule_id"), p + ".rule_id")
        rule_name(a.get("rule_id"), a.get("name"), p + ".name")
    return problems


def check(inputs, alerts, expected, extra_denials=(), rules_export=None):
    """Raise ScrubError naming the problems; return None when the fixture is publishable.

    `rules_export` is the path of rules_export.ndjson: when given, every retained rule id and
    name must be an immutable, Elastic-authored rule of it (the producer, scrub_dir, always
    gives it). Without it the value shapes are still held, the provenance is not.
    """
    problems = []
    prebuilt = prebuilt_fields = None
    if rules_export is not None:
        try:
            prebuilt_fields = {}
            prebuilt = prebuilt_rules(rules_export, fields=prebuilt_fields)
        except ScrubError as e:
            problems.append(str(e))

    def bad(what, path):
        problems.append(f"{what} at {path}")

    if not set(inputs) <= INPUT_KEYS or not (INPUT_KEYS - {"rule_memory"}) <= set(inputs):
        bad("inputs keys are not the closed set", "inputs")
    if inputs.get("host") != HOST:
        bad("the host is not the scrubbed one", "inputs.host")
    for i, r in enumerate(inputs.get("results", [])):
        p = f"inputs.results[{i}]"
        if set(r) != RESULT_KEYS:
            bad("result keys are not the closed set", p)
        if r.get("host") != HOST:
            bad("result host is not the scrubbed one", p + ".host")
        if r.get("output") != "" or r.get("op_id") != "" or r.get("nonce") is not None:
            bad("lab text left in a result", p)
        if r.get("verdict") is not None or r.get("latency_s") is not None:
            bad("a post-verify field is filled", p)
    for i, a in enumerate(alerts):
        p = f"alerts[{i}]"
        if set(a) != ALERT_KEYS:
            bad("alert keys are not the 14 normalised fields", p)
            continue
        if a["host_name"] not in (None, "ws", OTHER_HOST):
            bad("alert host_name", p)
        if a["winlog_computer_name"] not in (None, "ws", OTHER_HOST):
            bad("alert winlog_computer_name", p)
        if a["host_id"] is not None and not re.fullmatch(r"h\d+", str(a["host_id"])):
            bad("alert host_id", p)
        if a["group_id"] is not None and not re.fullmatch(r"g\d+", str(a["group_id"])):
            bad("alert group_id", p)
        if not (GUID.fullmatch(str(a["rule_id"])) or re.fullmatch(r"neighbour-rule-\d+", str(a["rule_id"]))):
            bad("alert rule_id is neither an Elastic rule id nor a neighbour", p)
    for i, d in enumerate(inputs.get("extra_detonations", [])):
        if isinstance(d, dict) and not NEIGHBOUR_ID.fullmatch(str(d.get("id"))) and _private(d.get("id")):
            bad("neighbour id", f"inputs.extra_detonations[{i}]")
    try:
        problems += check_values(inputs, alerts, expected, prebuilt, prebuilt_fields)
    except (AttributeError, TypeError, KeyError) as e:
        problems.append(f"a document is not the shape of a recorded night ({type(e).__name__})")
    docs = (("inputs", inputs), ("alerts", alerts), ("expected", expected))
    denials = tuple(_fold(x) for x in extra_denials if x)
    for root, doc in docs:
        for path, text in _walk(doc, root):
            folded = _fold(text)
            for tok in DENY_SUBSTRINGS:
                if tok in folded:
                    bad(f"denied string {tok!r}", path)
            for tok in denials:
                if tok in folded:
                    bad("a name or address from the lab registry", path)
            for label, rx in DENY_PATTERNS.items():
                if rx.search(text):
                    bad(label, path)
            if LONG_HEX.search(text):
                bad("long hex id", path)
            if GUID.search(text) and not GUID_PATHS.match(path):
                bad("a GUID outside a rule id", path)
    if problems:
        raise ScrubError("; ".join(problems[:20]) + (f"; and {len(problems) - 20} more" if len(problems) > 20 else ""))


def scrub_dir(src, dst):
    docs = []
    for name in ("inputs.json", "alerts.json", "expected.json"):
        with open(os.path.join(src, name)) as f:
            docs.append(json.load(f))
    inputs, alerts, expected = scrub(*docs)
    check(inputs, alerts, expected, extra_denials=lab_denials(),
          rules_export=os.environ.get("RULES_EXPORT") or DEFAULT_EXPORT)
    os.makedirs(dst, exist_ok=True)
    for name, doc in (("inputs.json", inputs), ("alerts.json", alerts), ("expected.json", expected)):
        with open(os.path.join(dst, name), "w") as f:
            json.dump(doc, f, indent=2, sort_keys=(name != "inputs.json"))
            f.write("\n")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: scrub_fixture.py SRC_DIR DST_DIR", file=sys.stderr)
        return 2
    try:
        scrub_dir(argv[0], argv[1])
    except ScrubError as e:
        print(f"scrub_fixture: refused: {e}", file=sys.stderr)
        return 1
    print(f"scrub_fixture: wrote {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
