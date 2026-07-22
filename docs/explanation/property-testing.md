# Why the security suite uses property tests

Much of Extra CODEOWNERS processes data that a contributor or a changing
GitHub API can influence: webhook bytes, CODEOWNERS syntax, TOML policy, paths,
pagination, and error metadata. Handwritten examples cover known cases well,
but they are poor at finding combinations nobody thought to write down.

The project therefore runs bounded property tests beside its ordinary unit and
integration tests. They search a larger synthetic input space; they do not
prove that every possible input has been examined.

## Why Hypothesis

[Hypothesis](https://hypothesis.readthedocs.io/en/latest/reference/api.html)
fits the existing pytest suite and provides three useful properties of its own:

- strategies can describe valid and invalid structured inputs
- a failure is reduced to a smaller counterexample
- explicit regression examples and bounded execution profiles live with the
  test.

The current properties exercise these trust-boundary contracts:

- malformed or incorrectly signed webhooks are rejected
- a CODEOWNERS document produces either valid rules or a structured failure;
  unsupported patterns do not silently become rules
- generated repository policy preserves label restrictions when combined with
  an enrolled organization App and respects the 1,000-pattern limit
- both sides of a rename retain their ownership requirements
- paginated GitHub lists stop only on a short page and fail at the caller's
  item bound
- GitHub diagnostics and rate-limit delays stay within their limits.

Each property asserts the security result, not merely “the parser did not
crash.” A malformed case must produce the documented rejection or preserve a
blocking decision.

## Profiles and limits

`tests/conftest.py` registers three profiles. The strategies in
`tests/test_security_properties.py` add their own size limits; generated
webhook bodies, for example, stop at 64 KiB, and arbitrary CODEOWNERS text
stops at 16,384 Unicode code points. Separate boundary tests cover the larger
application limits.

| Profile | Generated-example ceiling | Per-example deadline | Where it runs |
| --- | ---: | ---: | --- |
| `dev` | 50 | 500 ms | Normal local and full-suite tests |
| `ci` | 250 | 750 ms | Pull requests and `main` pushes |
| `scheduled` | 2,000 | 1,000 ms | Weekly exploratory run |

`max_examples` is a ceiling. Hypothesis may finish earlier when it exhausts a
finite strategy. Explicit `@example` cases run in addition to generated ones.

The hosted property-test job has a 45-minute limit and a 2 GiB virtual-memory
limit. A timeout, out-of-memory exit, unexpected exception, or failed property
fails the job. Those limits bound one test invocation; they say nothing about a
production process's worst-case memory use.

Run the pull-request profile from the repository root:

```bash
mise run test:property
```

Run the longer search when the machine can spare the work:

```bash
mise run test:property:scheduled
```

Both tasks print Hypothesis statistics. The scheduled profile deliberately
uses a new search rather than a persistent example database, so separate runs
explore different cases.

## Synthetic data only

Generators construct fictional values. An explicit `@example` must also be a
small, reviewed synthetic fixture. Never seed the suite with a real webhook,
API response, repository path set, organization identifier, token, private
key, or customer data.

The Hypothesis example database is disabled for every profile. CI does not
retain a generated corpus. It uploads only pytest's JUnit report for 14 days.
A minimized synthetic counterexample can appear in that report, so the report
is still treated as public project data.

When a generated failure exposes a useful boundary case, first turn it into a
small ordinary regression test, then fix the implementation. Do not replace
the minimized example with a real payload from the affected environment.

## What this approach does not cover

Coverage-guided tools such as Atheris or OSS-Fuzz could spend more compute on
byte-oriented parsers. They would also need a separate harness, corpus
lifecycle, runtime and sanitizer choices, and a privacy review. Today's main
surfaces are typed Python models and policy decisions, where semantic
generation provides more immediate value. Revisit that decision if the parser
surface or native extension use grows.

OpenSSF Scorecard does not currently recognize Python Hypothesis in its
Fuzzing check. The project accepts that measurement gap instead of choosing a
weaker test design for a score. Scorecard itself notes that undetected fuzzing
can still be valid in its
[Fuzzing check documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md#fuzzing).

Property tests are one layer. PostgreSQL concurrency, container, Helm,
webhook-recovery, and live GitHub tests cover boundaries they cannot model.
