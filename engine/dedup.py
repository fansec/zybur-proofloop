# rules/engine/dedup.py
"""Source-IP allocator + macvlan netns service, ported from run_caldera.py.

Why source-IP rotation at all: plans/04-technical/source-ip-rotation-research.md.

The infra hosts (for Zybur, the self-hosted git server, the sole repo copy) are denylisted
in ONE place here: they must never enter the dedup pool nor be a target. This
reconciles the fix on branch fix/caldera-dedup-infra-denylist (d4637bb) - the legacy
pool (range(110,200)) included that host and once spoofed it.

Since 2026-10-22 the pool's subnet, its gateway and the denylist are configuration
(DEDUP_SUBNET, DEDUP_GATEWAY, DEDUP_DENYLIST, resolved like every other lab value),
not literals. Unset, the pool refuses to exist and names the three.
"""
import os, sys, json, time, tempfile, subprocess, logging, ipaddress

import config
import opensslconf

log = logging.getLogger("engine.dedup")

# A snippet that runs inside a namespace may import the engine's own modules (the WMI helper does).
ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))

_NAMES = ("DEDUP_SUBNET", "DEDUP_GATEWAY", "DEDUP_DENYLIST")


class DedupConfigError(RuntimeError):
    """The dedup pool is not configured. The message names env vars, never values."""


def _settings():
    """The three dedup values as configured; an unset one is None."""
    return {name: config._resolve(name) for name in _NAMES}


def _require():
    got = _settings()
    missing = [n for n in _NAMES if not got[n]]
    if missing:
        raise DedupConfigError(
            "dedup pool not configured: set " + ", ".join(missing)
            + " (environment or the creds file)")
    return got


def _parse_denylist(raw):
    """The denylist as a set of normalised IP strings. Unset parses to the empty set.

    A set value is held to the format: it is free text in a creds file and it guards
    the sole repo copy, so an entry that is not a bare IP (a semicolon list, a CIDR, a
    stray character) would become a useless member and let the host back into the
    pool. That is refused by name, never by value.
    """
    if not raw:
        return set()
    out = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(str(ipaddress.ip_address(part)))
        except ValueError:
            raise DedupConfigError(
                "DEDUP_DENYLIST must be bare IP addresses separated by commas")
    if not out:
        raise DedupConfigError("DEDUP_DENYLIST holds no IP address")
    return out


def infra_denylist():
    """Hosts that must never enter the pool nor be a target. DEDUP_DENYLIST, comma-separated."""
    return _parse_denylist(_require()["DEDUP_DENYLIST"])


def _subnet_base(raw):
    """The first three octets of the /24 the pool is drawn from."""
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise DedupConfigError("DEDUP_SUBNET is not a network address")
    if net.version != 4 or net.prefixlen != 24:
        raise DedupConfigError("DEDUP_SUBNET must be an IPv4 /24 (the netns aliases are added as /24)")
    return ".".join(str(net.network_address).split(".")[:3])

def malformed_names():
    """The DEDUP_* names that are set to something the pool will refuse, never the values.

    --preflight is the gate before a release is pinned; without this it said `ok` for
    a semicolon denylist or a /16 that build_pool() rejects only after the lab is up.
    An unset name is not malformed here (the missing list already names it).
    """
    got = _settings()
    bad = []
    for name, check in (("DEDUP_SUBNET", _subnet_base),
                        ("DEDUP_DENYLIST", _parse_denylist),
                        ("DEDUP_GATEWAY", ipaddress.ip_address)):
        if not got[name]:
            continue
        try:
            check(got[name])
        except (DedupConfigError, ValueError):
            bad.append(name)
    return bad


# Reuse window - avoid IPs used within this period (observed cache TTL ~3 days + margin).
DEDUP_REUSE_WINDOW_HOURS = 96


def _detect_nic():
    """Return the primary NIC name (the one with the default route)."""
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        parts = r.stdout.strip().split()
        return parts[parts.index("dev") + 1] if "dev" in parts else "enp6s18"
    except Exception:
        return "enp6s18"


PRIMARY_NIC = _detect_nic()


def build_pool(lo=110, hi=200):
    """The dedup source-IP pool: <DEDUP_SUBNET>.<lo..hi-1>, with the denylist removed.

    Raises DedupConfigError when DEDUP_SUBNET, DEDUP_GATEWAY or DEDUP_DENYLIST is unset.
    """
    got = _require()
    base = _subnet_base(got["DEDUP_SUBNET"])
    deny = _parse_denylist(got["DEDUP_DENYLIST"])
    return [ip for i in range(lo, hi)
            for ip in (f"{base}.{i}",)
            if ip not in deny]


pool = build_pool


def _create_netns(ns_name, ip_addr):
    """Create a network namespace with macvlan on the physical NIC (verbatim port).

    macvlan gives the namespace a virtual interface on the same L2 segment, so
    traffic goes directly to the target with the correct source IP. No NAT needed.
    """
    mv_name = f"mv_{ns_name[-8:]}"
    gw = config._resolve("DEDUP_GATEWAY")
    try:
        r = subprocess.run(["ip", "-4", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        parts = r.stdout.strip().split()
        if "via" in parts:
            gw = parts[parts.index("via") + 1]
    except Exception:
        pass
    if not gw:
        raise DedupConfigError("dedup pool not configured: set DEDUP_GATEWAY (no default route to read it from)")
    cmds = [
        ["sudo", "ip", "netns", "add", ns_name],
        ["sudo", "ip", "link", "add", mv_name, "link", PRIMARY_NIC, "type", "macvlan", "mode", "bridge"],
        ["sudo", "ip", "link", "set", mv_name, "netns", ns_name],
        ["sudo", "ip", "netns", "exec", ns_name, "ip", "addr", "add", f"{ip_addr}/24", "dev", mv_name],
        ["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", mv_name, "up"],
        ["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"],
        ["sudo", "ip", "netns", "exec", ns_name, "ip", "route", "add", "default", "via", gw],
        ["sudo", "ip", "netns", "exec", ns_name,
         "sysctl", "-w", "net.ipv4.ip_local_port_range=49152 65535"],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0 and "File exists" not in r.stderr:
            log.debug("netns cmd %s: %s", " ".join(cmd[-3:]), r.stderr.strip())


def _ensure_netns(source_ip):
    """Ensure the network namespace for a source IP exists. Returns ns name."""
    ns_name = f"dedup_{source_ip.replace('.', '_')}"
    ns_check = subprocess.run(
        ["sudo", "ip", "netns", "list"], capture_output=True, text=True, timeout=5
    )
    if ns_name not in ns_check.stdout:
        _create_netns(ns_name, source_ip)
    return ns_name


class DedupAllocator:
    """Least-recently-used source-IP allocator over build_pool(), keyed by any string."""

    def __init__(self, cfg, state_path):
        self.cfg = cfg
        self.state_path = state_path
        self._run_allocations = {}  # key -> ip, for the current run (avoid intra-run collisions)

    def _load_state(self):
        try:
            with open(self.state_path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _save_state(self, state):
        with open(self.state_path, "w") as f:
            json.dump(state, f, indent=2)

    def allocate(self, key):
        """Pick the least-recently-used pool IP outside the reuse window; record it."""
        if key in self._run_allocations:
            return self._run_allocations[key]
        state = self._load_state()
        now = time.time()
        cutoff = now - DEDUP_REUSE_WINDOW_HOURS * 3600
        used_this_run = set(self._run_allocations.values())
        candidates = sorted((state.get(ip, 0), ip) for ip in build_pool() if ip not in used_this_run)
        if not candidates:
            raise RuntimeError("No available IPs in dedup pool - all in use this run")
        chosen = next((ip for last_used, ip in candidates if last_used < cutoff), candidates[0][1])
        state[chosen] = now
        self._save_state(state)
        self._run_allocations[key] = chosen
        log.info("Allocated dedup IP %s for %s", chosen, key)
        return chosen

    def assert_pool_safe(self, cfg):
        """Fail loud if the infra denylist leaked into the pool or the target is unsafe."""
        # Checks what is configured and no more: the WinRM executors never draw from
        # the pool, so a run of only those must not need DEDUP_*. Any executor that
        # does draw (allocate) refuses on its own with DedupConfigError.
        got = _settings()
        deny = _parse_denylist(got["DEDUP_DENYLIST"])
        if not deny:
            # The target-is-an-infra-host check below has nothing to compare with.
            # Not an error (see above), but never silent: run.py --preflight with no
            # --executors demands DEDUP_DENYLIST, and the nightly should run that.
            log.warning("DEDUP_DENYLIST is not set: the target is not checked against "
                        "the infra denylist")
        host = cfg.get("win_host")
        if host in deny:
            raise RuntimeError(f"target win_host {host} is an infra host on the denylist")
        if not (got["DEDUP_SUBNET"] and got["DEDUP_GATEWAY"] and got["DEDUP_DENYLIST"]):
            return
        pool_ips = set(build_pool())
        leaked = deny & pool_ips
        if leaked:
            raise RuntimeError(f"infra IP leaked into dedup pool: {sorted(leaked)}")
        if host in pool_ips:
            raise RuntimeError(f"target win_host {host} overlaps the dedup source pool")

    # --- netns helpers (need root; not unit-tested) ---
    def setup(self, ips):
        """Add alias IPs to the primary NIC for dedup bypass. Idempotent."""
        existing = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", PRIMARY_NIC],
            capture_output=True, text=True, timeout=5,
        ).stdout
        added = []
        for ip in sorted(set(ips)):
            if ip in existing:
                continue
            r = subprocess.run(
                ["sudo", "ip", "addr", "add", f"{ip}/24", "dev", PRIMARY_NIC],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                added.append(ip)
                log.info("Added dedup IP %s to %s", ip, PRIMARY_NIC)
            else:
                log.warning("Failed to add %s: %s", ip, r.stderr.strip())
        return added

    def run_in_netns(self, source_ip, python_code, timeout=60, stdin_json=None):
        """Run a Python snippet inside the source_ip macvlan namespace.

        `stdin_json`, when given, reaches the snippet as JSON on its standard input
        (`json.load(sys.stdin)`): that is how a credential travels. It never goes into the
        snippet's text (the wrapper file holds only code), and so never into a process
        argument list, where `ps` shows it to every local user. The wrapper puts the engine
        directory first on sys.path, so a snippet can import engine modules, and points
        OPENSSL_CONF at the verified private config (opensslconf.py), computed here in the
        parent: a config that is wrong stops the call before `sudo` runs anything.
        """
        ns_name = _ensure_netns(source_ip)
        conf = opensslconf.ensure_openssl_conf()
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        wrapper = f"""
import os, sys
sys.path.insert(0, {ENGINE_DIR!r})
os.environ["OPENSSL_CONF"] = {conf!r}
{python_code}
"""
        tmp.write(wrapper)
        tmp.close()
        extra = {"input": json.dumps(stdin_json)} if stdin_json is not None else {}
        try:
            r = subprocess.run(
                ["sudo", "ip", "netns", "exec", ns_name, sys.executable, tmp.name],
                capture_output=True, text=True, timeout=timeout, **extra,
            )
            return r.returncode, r.stdout.strip(), r.stderr.strip()
        finally:
            os.unlink(tmp.name)

    def cleanup(self):
        """Remove all dedup network namespaces. Call in a finally from run.py."""
        r = subprocess.run(["sudo", "ip", "netns", "list"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().split("\n"):
            ns = line.split()[0] if line.strip() else ""
            if ns.startswith("dedup_"):
                subprocess.run(["sudo", "ip", "netns", "delete", ns], capture_output=True, timeout=5)
                log.debug("Removed netns %s", ns)
