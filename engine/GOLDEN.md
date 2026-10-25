# Verification contract

This document records the public engine's reproducible contract. It deliberately contains no
operator rule catalogue, live-lab history, customer identifiers, or production outcomes.

## The six verdicts

Every detonation receives one of six verdicts, keyed on the stable rule ID rather than a mutable
display name:

| Verdict | Meaning |
|---|---|
| `DETECTED` | A target rule fired on the target host inside the use-case window. |
| `PREVENTED` | The endpoint blocked the behaviour in the same window before the target rule fired. |
| `MISSED` | The rule was due, the SIEM answered, and no signal explains the absence of an alert. |
| `PENDING` | The target rule is not due yet and must be checked later. |
| `INCONCLUSIVE` | The run cannot be measured reliably, for example because the SIEM did not answer. |
| `ABORT` | The technique did not execute. |

When signals overlap, precedence is
`ABORT > INCONCLUSIVE > DETECTED > PREVENTED > PENDING > MISSED`. A later re-check may replace a
`PENDING` or late-arriving `MISSED` result when new evidence becomes available.

## Offline golden replay

The scrubbed fixture in `fixtures/replay/sample-night/` exercises the same correlation and
classification path as a live run without requiring a lab, SIEM, or credentials:

```bash
python3 run.py --replay fixtures/replay/sample-night
```

The final line must be:

```text
replay: 3 of 3 verdicts match expected.json
```

`inputs.json` contains three synthetic detonation records, `alerts.json` contains sanitised target
and background events, and `expected.json` holds the expected final verdict for each sample. A
non-zero exit means the verifier no longer reproduces that contract.

## Automated gate

Run the complete offline suite from this directory:

```bash
python3 -m unittest discover -p 'test_*.py'
```

CI runs that command on every push. The suite count is intentionally not pinned here because it
changes as the engine evolves.
