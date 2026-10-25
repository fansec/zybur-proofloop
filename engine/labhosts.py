# rules/engine/labhosts.py
"""Reader for validation/lab-hosts.json - the one place a Zybur attack range is named.

Fail-loud by design. A missing, unparseable or empty list raises rather than
returning [], because an empty lab-host set silently re-opens the customer-facing
path to validation traffic in four workflows at once, and every one of them keeps
looking healthy while it happens.

The Node twin is validation/lib/lab-hosts.js; the two are kept in step by their
tests reading the same shipped file.
"""
import json, os

# Overridden by the LAB_HOSTS_FILE environment variable, read at call time.
DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "validation", "lab-hosts.json")


class LabHostsError(Exception):
    pass


def load_lab_hosts(path=None):
    # LAB_HOSTS_FILE points a checkout without validation/ (the public export) at its
    # own registry. An explicit path argument still wins, so tests stay hermetic.
    p = os.path.abspath(path or os.environ.get("LAB_HOSTS_FILE") or DEFAULT_PATH)
    try:
        with open(p) as f:
            doc = json.load(f)
    except FileNotFoundError:
        raise LabHostsError(f"lab-hosts.json not found at {p}")
    except json.JSONDecodeError as e:
        raise LabHostsError(f"lab-hosts.json is not valid JSON at {p}: {e}")
    hosts = doc.get("hosts") if isinstance(doc, dict) else None
    if not isinstance(hosts, list) or not hosts:
        raise LabHostsError(f"lab-hosts.json must list at least one host ({p})")
    for h in hosts:
        if not isinstance(h, dict) or not str(h.get("name") or "").strip():
            raise LabHostsError(f"lab-hosts.json: every host needs a non-empty name ({p})")
        if h.get("role") is not None and h["role"] not in ("workstation", "domain_controller"):
            raise LabHostsError(
                f"lab-hosts.json: host {h['name']} has unsupported role {h['role']} ({p})")
        has_vmid = h.get("proxmox_vmid") is not None and str(h["proxmox_vmid"]).strip() != ""
        has_pve_name = bool(str(h.get("proxmox_name") or "").strip())
        if has_vmid != has_pve_name:
            raise LabHostsError(
                f"lab-hosts.json: host {h['name']} needs both proxmox_vmid and proxmox_name ({p})")
    return hosts


def primary_host(path=None):
    """The host the nightly rotation detonates against: the first entry."""
    return load_lab_hosts(path)[0]


def host_for_role(role="workstation", path=None):
    """Return the one configured target for a use-case role, failing closed."""
    for host in load_lab_hosts(path):
        if host.get("role", "workstation") == role:
            return host
    raise LabHostsError(f"lab-hosts.json has no host with role {role}")


def host_names(hosts):
    """Every name the box has answered to, current first (see aliases in the json)."""
    out = []
    for h in hosts:
        out.append(h["name"])
        for a in h.get("aliases") or []:
            if a not in out:
                out.append(a)
    return out


def host_ips(hosts):
    return [h["ip"] for h in hosts if h.get("ip")]


def host_ids(hosts):
    """Non-null ids only. A terms query over [None] is a coin flip, not a filter."""
    return [h["host_id"] for h in hosts if h.get("host_id")]


def _norm(v):
    return str(v or "").strip().lower()


def is_lab_host(subject, hosts):
    """subject is {name, ip, id}; ip may be one address or a comma-joined list."""
    name = _norm(subject.get("name"))
    hid = _norm(subject.get("id"))
    ips = [_norm(x) for x in str(subject.get("ip") or "").split(",") if _norm(x)]
    for h in hosts:
        if name and _norm(h.get("name")) == name:
            return True
        if name and any(_norm(a) == name for a in h.get("aliases") or []):
            return True
        if hid and h.get("host_id") and _norm(h["host_id"]) == hid:
            return True
        if h.get("ip") and _norm(h["ip"]) in ips:
            return True
    return False
