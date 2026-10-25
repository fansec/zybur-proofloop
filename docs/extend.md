# Extending Zybur Proofloop

Three things can be added without touching the verifier: a use-case, an executor and a SIEM
adapter. Run the suite, `lint.py` and the replay (see [CONTRIBUTING.md](../CONTRIBUTING.md)) after
any of them.

## A use-case

One YAML file under `usecases/<tactic>/<name>.yaml`; its `id` is that path without `.yaml`.
`engine/schema.py` is the schema and `engine/lint.py` the gate. A small, complete example:

```yaml
id: discovery/query-registry-using-built-in-tools
title: "Query Registry using Built-in Tools"
rules:
- "Query Registry using Built-in Tools"
technique: T1012
tactic: discovery
severity: LOW
safety: safe
evidence: real_behaviour
leaves_no_artifact: true
description: "Read a Windows registry value without changing system state."
executor: winrm_command
expect: detected
target: workstation
params:
  platform: windows
  shell: cmd
  command: 'reg.exe query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName'
```

The fields:

- **Required:** `id`, `title`, `rules` (rule names as they appear in your export), `technique` and
  `tactic` (MITRE ATT&CK; `T####` or `T####.###`), `executor`, `params` (handed to the executor;
  for `winrm_command`: `shell` `cmd` or `psh`, and `command`), `safety`.
- **`expect`:** `detected` (default; the rules must be enabled), `env_gap` (the rules are enabled
  but this environment cannot produce the telemetry they read) or `not_enabled` (the rules are
  installed and deliberately off). Only `detected` can produce a detection verdict; the other two
  are recorded `INCONCLUSIVE` and stay out of the nightly rotation.
- **`safety`:** `safe`, `supervised` or `never` (see the README). `safe` requires one of: a
  `cleanup` command that undoes what the command left, `leaves_no_artifact: true` (and then the
  command may not contain a verb that persists something, such as `reg add`, `schtasks /create`,
  `New-Item` or a download to disk), or `cleanup_managed_by: <this executor>` for the executors
  whose own code proves the cleanup. `destroys_evidence: true` (the use-case erases telemetry other
  use-cases need) can never be `safe`.
- **`network`:** `lab` (the default, never written) or `internet`. `safe` is a statement about
  cleanup, not about where the traffic goes. A use-case whose `params` or `cleanup` name an
  `http(s)` URL, or one of the public resolvers 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4 and 9.9.9.9, must
  say `network: internet`, and `lint.py` fails when it does not (a URL whose host is the
  `{{SERVER}}` template is the lab's own server, not the internet). Such a use-case stays out of
  `--select-nightly` and is refused by a run unless `--allow-internet` is given.
- **`evidence`:** `real_behaviour` (the real tool or technique ran) or `stand_in` (a harmless
  stand-in that produces the same telemetry, for example an in-box binary copied under the name
  the rule watches for). Required for every use-case in the nightly pool.
- **`target`:** `workstation` (default) or `domain_controller`.
- **Optional:** `additional_techniques`, `severity` (`LOW`, `MEDIUM`, `HIGH`; the selector weighs
  it), `tags`, `description`, `reason` (why an `env_gap` or `not_enabled`), `status: draft` (kept
  out of the lock, the loader and the rotation), `needs` (executor-specific requirements).
- **Templates** in `command` and `cleanup`: `{{WIN_HOST}}`, `{{WIN_USER}}`, `{{WIN_PASS}}`,
  `{{ATTACKER_IP}}`, `{{SERVER}}` (the CALDERA server) and `{{NONCE}}` (a fresh random value per
  detonation) are filled in at run time, so no lab value or secret is written into a use-case.
- A `winrm_command` payload must stay under 8,000 characters on the `cmd.exe` command line after
  its WinRM wrapping; `lint.py` measures it, because `cmd.exe` refuses anything over 8,191 and the
  call still returns as if it ran.

Then run `python3 genlock.py` (with your export) and `python3 lint.py`.

**The reconcile manifest.** `engine/reconcile.py` holds `MANIFEST`: every file, registry value,
registry key, scheduled task, service, BITS job and local account a use-case can leave behind, with
the state it must be in after a night. `run.py --reconcile` probes them, resets what is off, and probes again;
the second probe is the result. A use-case whose `cleanup` removes something the manifest does not
list fails the suite (`test_reconcile.py`), so add the entry with the use-case.

## An executor

An executor is a function `handler(usecase, ctx) -> Result`, registered by name:

```python
# engine/executors/my_executor.py
from datetime import datetime, timezone
from executors.registry import register
from result import make_result

@register("my_executor")
def run(usecase, ctx):
    start = datetime.now(timezone.utc).isoformat()
    # ... do the technique against ctx.cfg["win_host"] ...
    end = datetime.now(timezone.utc).isoformat()
    return make_result(usecase, "SUCCESS", True, attack_start=start, attack_end=end, output="")
```

`ctx` carries the configuration projected onto the use-case's target (`ctx.cfg`: `win_host`,
`win_user`, `win_pass`, `attacker_ip`, ...), a WinRM session factory, the CALDERA client, the
source-address allocator and the firewall service. Stamp `attack_start` immediately before the
technique and `attack_end` immediately after it: the verifier's windows are built from them. A
technique that did not run returns `make_result(usecase, "<reason>", False)`, which becomes `ABORT`
with the reason in the ledger. Never put a secret in `status` or `output`.

**Credentials.** `ctx.cfg["win_pass"]` must never reach a command line, where the process list shows
it to every local user, and must not be written into a generated script. The helpers do this for
you. `smb_client` and `smb_client_from` (`executors/_net.py`) give smbclient a one-call
authentication file (`-A`, mode 0600, removed afterwards). A snippet that runs inside a
source-address namespace gets its credentials on standard input:
`ctx.dedup.run_in_netns(source_ip, code, stdin_json={"win_host": ..., "win_user": ..., "win_pass": ...})`,
read in the snippet with `json.load(sys.stdin)`. A tool that takes a password only as an option is
handed it through the environment of its process and a pipe, as `rdp_keystroke` does with
`RDP_PASS` and `/from-stdin`.

Then import the module in `engine/executors/plugins.py` and add the executor's configuration names
to `LAB_KEYS_BY_EXECUTOR` in `engine/config.py` (`test_lab_config.py` fails while they differ).

## A SIEM adapter

An adapter answers one question: which alerts of these rules, or on these hosts, exist since this
moment. It is a class with a `name` and a `query_alerts` method (`engine/siem/__init__.py`,
`SiemAdapter`):

```python
class MyAdapter:
    name = "mysiem"

    def query_alerts(self, rule_ids, since_iso, hosts=None):
        """A list of normalised alerts, or None when the SIEM could not be asked."""
```

`hosts` is `{"names": [...], "ids": [...]}`. Each alert is a dict with the fourteen fields listed in
the module docstring (`rule_id`, `name`, `@timestamp`, `original_time`, `host_name`, `host_id`,
`event_type`, `event_dataset`, ...). Return `None` for any failure, never an empty list: `None`
becomes `INCONCLUSIVE`, an empty list becomes `MISSED`, and reporting an outage as a detection gap
is the error this engine exists to prevent. `siem/elastic.py` is the reference implementation and
`siem/recorded.py` the smallest one. Add a branch for it in `adapter_from_env`, selected by
`SIEM=mysiem`.
