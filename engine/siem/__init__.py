# rules/engine/siem/__init__.py
"""The SIEM behind one small boundary, so the verifier asks a question and does not care who answers.

The classifier (verify.py) never sees Elasticsearch. It sees a list of normalised alert
dicts, or None. An adapter is whatever turns "which of these rules fired, or what else fired
on these hosts, since this moment" into that list:

    elastic    the lab's Elastic Security project (siem/elastic.py), the only live one
    recorded   a directory with alerts.json, for replaying a night without a SIEM (siem/recorded.py)

A second SIEM is one new file with a class that has `name` and `query_alerts`, plus one
branch in `adapter_from_env`.

The returned dicts carry the 14 normalised fields verify.ALERT_SOURCE_FIELDS names
(rule_id, name, @timestamp, original_time, event_ingested, host_name, host_id,
winlog_computer_name, event_type, event_dataset, group_id, group_index,
building_block_type, rule_version).

`None` means COULD NOT MEASURE. An adapter never returns an empty list for a failed read:
the verifier turns None into INCONCLUSIVE and an empty list into MISSED, and reporting a
detection gap that was really an outage is the failure verify.py exists to prevent.
"""
import os
import typing

from envshared import read_shared_env


@typing.runtime_checkable
class SiemAdapter(typing.Protocol):
    name: str

    def query_alerts(self, rule_ids, since_iso, hosts=None):
        """Alerts of `rule_ids`, or on `hosts` ({"names": [...], "ids": [...]}), since
        `since_iso`; None when it could not be measured."""
        ...


def shared_env_paths(env=None):
    """Candidate shared-env locations: the configured env root, else host and repo.

    The systemd release runs from a clean detached worktree while
    ``ZYBUR_ENV_ROOT`` points at the operator-owned checkout containing the private
    shared environment.  Ignoring that variable left verification without an
    Elastic key even though the JavaScript PREPARE probe used the same setting and
    passed.  Keep absolute paths only so a service cwd can never redirect the
    credential lookup.  Since 2026-10-22 a configured absolute root is the ONLY place
    looked in; the host and repo places are the fallback when it is unset.
    """
    env = os.environ if env is None else env
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    configured = env.get("ZYBUR_ENV_ROOT")
    if configured and os.path.isabs(configured):
        # An absolute root REPLACES the defaults below: a run pointed at another
        # tree (the public export, a test with an empty root) must not pick up the
        # developer's own key from the checkout it happens to sit in.
        return [os.path.join(configured, ".env.shared")]
    candidates = [
        "/.env.shared",
        os.path.join(here, "..", "..", ".env.shared"),
    ]
    return list(dict.fromkeys(candidates))


def read_shared_any(key, env=None):
    for path in shared_env_paths(env):
        v = read_shared_env(key, path)
        if v:
            return v
    return None


def elastic_credentials(env=None, read=None):
    """Serverless project ES url + key (never the CALDERA-box ES). Missing => INCONCLUSIVE.

    There is no default URL: it was a literal until 2026-10-22, which made a checkout
    without a configuration verify against someone else's project. Each half is None
    when nothing supplies it; --preflight names them and a new detonation refuses.

    `env` is the process environment unless a caller passes its own mapping; `read` looks
    a key up in the shared env files (run.py passes its own `_read_shared_any`, which is
    the seam its tests patch).
    """
    env = os.environ if env is None else env
    read = read or (lambda key: read_shared_any(key, env))
    # An explicit process-scoped value is an intentional operator override. This
    # is needed when the least-privilege validation key cannot read a newly added
    # integration index during diagnosis; putting it last made the override
    # silently ineffective whenever the tracked key existed.
    api_key = (env.get("ES_API_KEY")
               or read("ELASTIC_VALIDATION_API_KEY")
               or read("ELASTIC_LEGACY_API_KEY"))
    es_url = (env.get("ES_URL")
              or read("ELASTIC_VALIDATION_URL")
              or read("ELASTIC_URL"))
    return es_url, api_key


def adapter_from_env(env=None):
    """The adapter `SIEM` names: `elastic` (default) or `recorded` (needs SIEM_RECORDED_DIR).

    An Elastic adapter without a url or key is still returned: its query_alerts answers
    None, which is how a missing credential has always become INCONCLUSIVE.
    """
    env = os.environ if env is None else env
    kind = (env.get("SIEM") or "elastic").strip().lower()
    if kind == "elastic":
        from siem.elastic import ElasticAdapter
        es_url, api_key = elastic_credentials(env)
        return ElasticAdapter(es_url, api_key)
    if kind == "recorded":
        path = env.get("SIEM_RECORDED_DIR")
        if not path:
            raise ValueError("SIEM=recorded needs SIEM_RECORDED_DIR (a directory with alerts.json)")
        from siem.recorded import RecordedAdapter
        return RecordedAdapter(path)
    raise ValueError(f"unknown SIEM adapter: {env.get('SIEM')!r} (elastic or recorded)")
