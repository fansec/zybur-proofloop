# Contributing

Thank you for helping. Zybur Proofloop is small on purpose: a change is welcome when it makes a verdict
more honest, a use-case more useful, or the engine easier to run somewhere new.

## Before you open a pull request

1. Run the three checks CI runs, from `engine/`:

   ```
   python3 -m unittest discover -p 'test_*.py'
   python3 lint.py --no-resolve --export fixtures/rules_export.sample.ndjson --usecases ../usecases --lock ../usecases/_ruleid.lock.json
   python3 run.py --replay fixtures/replay/sample-night
   ```

2. A change to a verdict rule (`verify.py`, `result.py`, the windows in `run.py`) comes with a test
   that fails without it, and with a replay fixture when the behaviour came from a real night.
   Scrub a recorded night with `scrub_fixture.py` before you share it.
3. A new use-case follows [docs/extend.md](docs/extend.md): `lint.py` must pass, and a `safe`
   use-case must clean up after itself. Say in the description what was measured live and what was
   not.
4. Keep commits focused, and write commit messages that say why.

## Developer Certificate of Origin

Contributions are accepted under the Developer Certificate of Origin 1.1
(https://developercertificate.org). Sign off every commit:

```
git commit -s -m "engine: explain the change"
```

which adds a line `Signed-off-by: Your Name <you@example.com>`. By signing off you certify that:

> (a) The contribution was created in whole or in part by me and I have the right to submit it
> under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered
> under an appropriate open source license and I have the right under that license to submit that
> work with modifications, whether created in whole or in part by me, under the same open source
> license (unless I am permitted to submit under a different license), as indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who certified (a), (b) or
> (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public and that a record
> of the contribution (including all personal information I submit with it, including my sign-off)
> is maintained indefinitely and may be redistributed consistent with this project or the open
> source license(s) involved.

Contributions are licensed under the Apache License 2.0, like the rest of the repository.

## Conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
