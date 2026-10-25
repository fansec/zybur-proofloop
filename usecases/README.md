# Sample use-cases

This public directory intentionally contains five sanitised examples, not an operator's complete
rule catalogue. The examples show the Proofloop schema and execution contracts without publishing
customer coverage, lab details, validation history, or known detection gaps.

| Example | What it demonstrates |
|---|---|
| `credential-access/lsass-memory-dump-creation` | Endpoint prevention, owned-artifact cleanup, and a `PREVENTED` replay verdict. |
| `defense-evasion/endpoint-security-elastic-defend` | A reversible executor with cleanup managed by the executor. |
| `credential-access/creation-or-modification-of-domain-backup-dpapi-private-key` | A safe technique with an explicit cleanup command. |
| `discovery/query-registry-using-built-in-tools` | A read-only command that declares it leaves no artifact. |
| `persistence/wmi-subscription-not-enabled` | A supervised example whose disabled rule is excluded from detection scoring. |

These samples are demonstrations, not a coverage claim. Keep your production catalogue and its
generated lock file private when rule names, stable IDs, hosts, timestamps, or outcomes would reveal
security posture. Follow [the extension guide](../docs/extend.md) to create use-cases for your own
environment, then run `python3 engine/genlock.py` against your rule export to regenerate the bindings.
