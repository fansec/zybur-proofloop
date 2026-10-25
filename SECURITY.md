# Security

## Reporting a vulnerability

Email **security@zybur.nl** with what you found, how to reproduce it, and the version or commit you
tested. Please do not open a public issue for a vulnerability. You will get an answer within five
working days, and a fix or a decision within thirty. Tell us how you want to be credited.

In scope: anything in this repository that could make Zybur Proofloop act on a host it was not pointed
at, leak a credential it was given, write a secret into the ledger, a results file or a report, or
let a crafted use-case, replay fixture or SIEM response run code on the machine that runs Zybur Proofloop.

## Threat model

- **Attack commands run on your own lab only.** The use-cases execute real attacker techniques.
  The engine refuses a target that is not in your lab registry (`LAB_HOSTS_FILE`), but it cannot
  know whether you own that host: that is your responsibility.
- **No production endpoint.** Never register a host that holds real data or serves real users.
  Several use-cases change security posture for a while (audit policy, Defender settings, UAC),
  and a supervised use-case can leave state behind if it is interrupted.
- **Credentials never in the tree.** Passwords and API keys come from the environment or from a
  credentials file outside the repository (`ZYBUR_CREDS_FILE`, `ZYBUR_ENV_ROOT`). The
  `.gitignore` refuses the usual names; do not commit around it.
- **The loop reads the SIEM with a read-only key.** Give the Elastic API key read access to the
  alert indices and nothing else. Verification never writes to the SIEM.
