# Running Zybur Proofloop

Everything runs from `engine/`. `python3 run.py --help` lists every command; this page is the
configuration reference, the replay fixture format, and what each executor needs.

## Configuration

A lab value is read from the environment first, then from the credentials file
(`ZYBUR_CREDS_FILE`, `KEY=VALUE` lines). Nothing has a default that points at a lab: a missing
value is named by `python3 run.py --preflight [--executors a,b]`, which prints
`preflight: missing NAME ...` or `preflight ok` and never a value.

| Name | What it is for |
|---|---|
| `LAB_HOSTS_FILE` | The lab registry (`lab-hosts.example.json` is the template). The only hosts a detonation may land on; a configured address that is not in it is refused. |
| `WIN_HOST` | The workstation target's address. Defaults to the registry's first `workstation`. |
| `WIN_USER`, `WIN_PASS` | The account WinRM and SMB log in as on the workstation (`WIN_USER` defaults to `Administrator`). |
| `DC_HOST` | The domain controller's address, for use-cases with `target: domain_controller`. Defaults to the registry's `domain_controller`. |
| `DC_USER`, `DC_PASS`, `DC_DOMAIN`, `DC_FQDN` | The domain controller's account (`DC_USER` defaults to `Administrator`), its domain and its full name. |
| `ATTACKER_IP` | The address the machine running Zybur Proofloop has on the lab network (network executors). |
| `DEDUP_SUBNET`, `DEDUP_GATEWAY`, `DEDUP_DENYLIST` | The pool of source addresses the network executors rotate through (a /24; its `.110` to `.199`), its gateway, and the addresses that must never be used or attacked (comma-separated bare addresses). A detonation does not come from an address a rule saw recently. |
| `CALDERA_SERVER`, `CALDERA_API_KEY` | The CALDERA server and its API key, for the `caldera_command` executor. |
| `CALDERA_GROUP`, `CALDERA_PLANNER` | The agent group (default `red`) and the planner id (default: CALDERA's built-in atomic planner). |
| `SIEM` | Which adapter answers the verifier: `elastic` (default) or `recorded`. |
| `SIEM_RECORDED_DIR` | With `SIEM=recorded`: a directory holding `alerts.json`. |
| `ES_URL`, `ES_API_KEY` | The Elasticsearch endpoint of your Elastic Security project and an API key that can read `.alerts-security.alerts-*`. |
| `ZYBUR_ENV_ROOT` | An absolute folder holding `.env.shared` (and optionally `.env.internal`), read for `ELASTIC_VALIDATION_URL` and `ELASTIC_VALIDATION_API_KEY` (or `ELASTIC_URL`, `ELASTIC_LEGACY_API_KEY`) when `ES_URL` or `ES_API_KEY` is not set. When it is set, no other place is searched. |
| `ZYBUR_CREDS_FILE` | The credentials file for the lab values above. When it is set, no other place is searched. |
| `RULES_EXPORT` | Your enabled-rules export (default `../rules_export.ndjson`). |
| `LEDGER_FILE` | The ledger (default `state/ledger.jsonl`). |
| `RESULTS_DIR` | Where each run writes its results file (default `../results`). |
| `ZYBUR_DETONATION_GAP_S` | Minimum seconds between two detonations on one host (default 10; 0 disables the wait). |

The engine sets `OPENSSL_CONF` for itself (NTLM needs MD4, which OpenSSL 3 only offers through its
legacy provider); you do not set it. The file it points at is made by `engine/opensslconf.py` in a
directory named for your uid (mode 0700) under `$XDG_RUNTIME_DIR`, else the temp directory, with the
file inside it mode 0600. Both are checked on every start: a symlink, a file owned by someone else or
one that group or other can write stops the run and names the path, because whoever controls that
file chooses which OpenSSL providers the harness loads.

## What a run refuses

The safety classes are enforced by `run.py`, not only by the lint. A selection (`--id`, `--all`,
`--technique`, `--tactic`, `--tag`) is checked before anything is powered on or detonated, and one
refused member refuses the whole selection with exit 2 and a line per class on stderr that names ids
and nothing else:

| Use-case | Run only with |
|---|---|
| `safety: supervised` | `--allow-supervised` |
| `safety: never` | never; no flag admits it |
| `network: internet` | `--allow-internet` |

`--select-nightly K` takes `--allow-internet` as well; without it the nightly pool leaves the internet
use-cases out. `--dry-run` goes through the same gate and prints only what would run. A run verifies
against the SIEM unless you pass `--no-verify`, and refuses to detonate without a verifier (`ES_URL` and
`ES_API_KEY`).

## Where credentials travel

Nothing in a process argument list, because `ps` shows that to every local user. smbclient reads an
authentication file made for the one call (mode 0600, removed afterwards); the executors that run
Python inside a source-address namespace (`psremoting`, `remote_service` and `remote_schtask`, whose WMI
fallback works the same way) are handed host, user and password on standard input; `rdp_keystroke`
passes the password in its process's environment and `xfreerdp3` reads it from stdin (`/from-stdin`). Two
executors, `dcomexec` and `wmiexec`, still write the credentials into their generated snippet as
base64, which is an encoding and not protection; the snippet file is mode 0600, removed after the call,
and no command line carries them. Moving those two to standard input is open.

## The rule pack and the lock

`run.py` reads `../rules_export.ndjson`: the rules export from your own Kibana, one rule per line.
Use-cases name their rules by name; `python3 genlock.py` resolves every name to a `rule_id` against
your export and writes `../usecases/_ruleid.lock.json`, and `python3 lint.py` fails when that lock is
stale. The lock in this repository carries the `rule_id` of each Elastic prebuilt rule and no
`rule_uuid` (those are saved-object ids of one Kibana instance); `genlock.py` fills them for yours.

Without your export, `python3 lint.py --no-resolve --export fixtures/rules_export.sample.ndjson
--usecases ../usecases --lock ../usecases/_ruleid.lock.json` checks everything except name
resolution: the schema, the executors, the safety contract, the command-line length limits and the
lock's shape against the use-cases. Its summary line ends `shape only (--no-resolve)`.

## Replay fixtures

`python3 run.py --replay DIR` re-verifies one recorded night for one host. `DIR` holds:

- `inputs.json`: `schema_version` (1), `night`, `now` (the clock the verdicts are computed at), the
  `host` (`name`, `id`, `aliases`), `rule_intervals` (`rule_id` to schedule interval, for example
  `"5m"`), `results` (each use-case's result as the executor returned it, before verification:
  `id`, `rule_ids`, `executor`, `executed`, `status`, `attack_start`, `attack_end`, `expect`,
  `host`), and optionally `extra_starts`, `extra_ends` and `extra_detonations` (neighbouring
  detonations that bound the windows) and `rule_memory`;
- `alerts.json`: the alerts the SIEM returned, as a list of normalised alerts (`rule_id`, `name`,
  `@timestamp`, `original_time`, `event_ingested`, `host_name`, `host_id`, `winlog_computer_name`,
  `event_type`, `event_dataset`, `group_id`, `group_index`, `building_block_type`,
  `rule_version`);
- `expected.json`: use-case id to the verdict the night recorded.

It prints one line per use-case (verdict, id, latency) and then
`replay: N of M verdicts match expected.json`; exit 0 when all match, 1 when one differs, 2 when
the fixture is unreadable. Verdict fields in `inputs.json` are blanked before verification, so a
fixture cannot carry its own answer. `python3 run.py --record-night YYYY-MM-DD --out DIR` writes such
a fixture from a night's results and ledger (one read-only SIEM search per host), and
`python3 scrub_fixture.py SRC_DIR DST_DIR` writes a copy with host names, addresses and other lab
values replaced, refusing when it finds one it cannot replace, before you share it.

## Executors

An executor turns a use-case into a detonation. Each one needs the values below (the table
`LAB_KEYS_BY_EXECUTOR` in `config.py`, which `--preflight` reads).

| Executor | What it does | Needs |
|---|---|---|
| `winrm_command` | Runs the use-case's `cmd` or PowerShell command on the target over WinRM. Most use-cases. | `WIN_HOST`, `WIN_USER`, `WIN_PASS` |
| `windows_reversible` | A closed set of reversible Windows changes, each with a measured cleanup. | `WIN_*` |
| `hidden_user` | Creates and removes a hidden local account. | `WIN_*` |
| `rdp_keystroke` | Drives an RDP session with typed keystrokes (`xfreerdp3`, `xdotool`). | `WIN_*` |
| `caldera_command` | Runs the command as a CALDERA ability through a CALDERA agent on the target. | `CALDERA_SERVER`, `CALDERA_API_KEY`, `WIN_*` |
| `psremoting` | PowerShell remoting from a rotated source address. | `ATTACKER_IP`, `WIN_*`, `DEDUP_*` |
| `smb_write`, `rare_smb` | SMB writes to the target; an SMB connection to an unusual address. | `ATTACKER_IP`, `WIN_*` |
| `smb_exe_transfer`, `smb_ransom_note`, `smb_rename` | SMB file transfer, ransom-note writes and mass renames, from a rotated source address. | `ATTACKER_IP`, `WIN_*`, `DEDUP_*` |
| `remote_schtask`, `remote_service`, `dcomexec`, `wmiexec` | Remote task, service, DCOM and WMI execution (impacket), from a rotated source address. | `ATTACKER_IP`, `WIN_*`, `DEDUP_*` |
| `ad_directory`, `ad_network`, `ad_reversible` | Closed sets of reversible Active Directory changes and authentication paths on the domain controller. | `DC_*` |
| `dcsync`, `dcsync_ephemeral`, `kerberos_asreq`, `smb_multipath` | Bounded replication, Kerberos and SMB checks against the domain controller. | `DC_*` |

### Root for the network executors

The network executors that rotate source addresses (the rows above that need `DEDUP_*`) create a
macvlan network namespace per detonation on the interface that holds the default route, and run the
detonation inside it. That takes `sudo` for the `ip` forms `dedup.py` runs, and for nothing else. An
address is not reused for 96 hours. The WinRM executors need no `sudo` at all.

Grant exactly those forms in `/etc/sudoers.d/detonation-netns` (mode 0440; replace `labrunner` with the
account that runs the engine and `/usr/sbin/ip` with the output of `command -v ip`), and check the file
with `visudo -cf` before you install it:

```
Cmnd_Alias DETONATION_NETNS = \
    /usr/sbin/ip netns add dedup_*, \
    /usr/sbin/ip netns exec dedup_* *, \
    /usr/sbin/ip netns list, \
    /usr/sbin/ip netns delete dedup_*, \
    /usr/sbin/ip link add * link * type macvlan mode bridge, \
    /usr/sbin/ip link set * netns dedup_*, \
    /usr/sbin/ip addr add * dev *
labrunner ALL=(root) NOPASSWD: DETONATION_NETNS
```

**Read that rule as what it is: root.** `ip netns exec dedup_* *` runs whatever follows the namespace
name as root (the executors run `smbclient`, `bash` and `python3` there), and a `*` in a sudoers argument
matches anything. The rule keeps the account from running other `ip` forms; it does not keep it from
running any command as root. Give it to a dedicated account on a dedicated machine that holds nothing
else, never to the account you log in with. If that is not acceptable, do not grant it and leave the
network executors out: `python3 run.py --all --list` prints every use-case with its executor, `--id`
selects the ones you want, and `python3 run.py --preflight --executors winrm_command` checks only the
WinRM executor's values. The nightly selector (`--select-nightly`) does not filter by executor.

`rare_smb` also runs `sudo iptables -t nat` for one DNAT rule, removed afterwards. The rule above does
not cover it: leave `rare_smb` out as well, or add an `iptables` line you have read and accepted the
same way.

## Scheduling

No scheduler is included. A night is a few commands, and any scheduler can run them: cron, a systemd
timer, or a job on a runner inside the lab network. Powering the lab on and off and delivering the report
are yours to add. One cron line, from the engine folder, with the credentials file named in the
crontab's environment (see Configuration):

```
0 3 * * *  cd /path/to/engine && python3 run.py --select-nightly 3 | sed 's/^/--id /' | xargs -r python3 run.py; python3 run.py --recheck-pending
```

`--select-nightly 3` prints the ids of up to three use-cases from the safe pool (its summary line goes to
stderr, so cron mails it with any error); `sed` and `xargs` turn them into `--id` arguments, and `-r` runs
nothing when the list is empty. A run verifies against the SIEM unless you pass `--no-verify`. The last
command measures the rows that ended `PENDING` on an earlier night.
