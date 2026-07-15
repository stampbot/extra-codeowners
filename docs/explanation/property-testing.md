# Property testing of untrusted inputs

Extra CODEOWNERS uses bounded property tests to exercise inputs that an attacker
or a changing GitHub API can influence. The tests complement example-based unit
and integration tests. They do not establish that every possible input has been
examined.

## Decision

The project uses
[Hypothesis](https://hypothesis.readthedocs.io/en/latest/reference/api.html)
because it integrates directly with the existing Python and pytest suite,
shrinks failures to smaller examples, supports explicit regression examples,
and lets the project set per-profile example and deadline limits.

The first properties cover these trust-boundary contracts:

- malformed or incorrectly signed webhook bodies are rejected;
- CODEOWNERS parsing has an explicit valid document or structured failure
  outcome, and unsupported patterns cannot silently become rules;
- generated TOML policies preserve label narrowing, cross-scope enrollment,
  and the 1,000-pattern complexity limit;
- renames retain both old-path and new-path ownership requirements;
- GitHub list pagination stops only at a short page and fails when a caller's
  item limit is exceeded;
- GitHub API diagnostics and rate-limit delays remain bounded.

Properties assert security outcomes, not only the absence of an exception. A
new malformed case must either produce the documented structured rejection or
preserve the expected fail-closed decision.

## Execution profiles and resource bounds

The profiles below are registered in `tests/conftest.py`. Strategy sizes are
also capped in `tests/test_security_properties.py`; for example, webhook bodies
are at most 64 KiB and arbitrary CODEOWNERS text is at most 16,384 Unicode code
points in the generative suite. Existing boundary tests separately exercise the
application limits.

| Profile | Examples per property | Deadline per example | Use |
| --- | ---: | ---: | --- |
| `dev` | 50 | 500 ms | Normal local and full-suite runs |
| `ci` | 250 | 750 ms | Pull requests and pushes to `main` |
| `scheduled` | 2,000 | 1,000 ms | Weekly non-deterministic search |

The dedicated GitHub Actions job has a 45-minute job limit and a 2 GiB virtual
memory limit. A timeout, out-of-memory exit, unexpected exception, or violated
property fails the job. These runner limits bound one invocation; they are not
a claim about worst-case application memory use in production.

Run the pull-request profile from the repository root:

```bash
mise run test:property
```

Run the longer profile only on a machine where the additional work is
acceptable:

```bash
mise run test:property:scheduled
```

Both commands should finish with all property tests passing and print
Hypothesis statistics. The scheduled profile is intentionally non-deterministic
so separate runs explore different examples.

## Corpus and artifact privacy

Every generator constructs synthetic values. Explicit `@example` seeds are
sanitized strings already present in unit tests; no production webhook, API
response, repository content, token, private key, or customer identifier may be
added as a seed. Hypothesis's example database is disabled for all three
profiles, so generated examples are not persisted or uploaded as a corpus.

CI uploads only the pytest JUnit report. A failing report can contain a minimized
synthetic example, so the report is still treated as public project data and is
retained for 14 days. When a failure exposes a useful boundary case, add a
small, reviewed, synthetic example to the ordinary test suite before fixing the
implementation. Do not copy a real payload into a regression test.

## Alternatives and limits

Coverage-guided engines such as Atheris or an OSS-Fuzz integration could spend
more compute exploring byte-oriented parsers. They would also require a
separate harness, corpus lifecycle, sanitizer/runtime decisions, and a privacy
review. The current surfaces are predominantly typed Python models and policy
decisions, so Hypothesis gives useful semantic generation with less operational
machinery. Revisit coverage guidance if parser complexity or native extensions
grow.

OpenSSF Scorecard does not currently list Python Hypothesis among the property
testing integrations detected by its Fuzzing check. The project accepts that
measurement gap instead of selecting a weaker technical design for a score.
The upstream check explicitly notes that undetected fuzzing can still be valid:
[OpenSSF Scorecard Fuzzing check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#fuzzing).

This suite is not a proof of correctness. It does not replace the PostgreSQL,
container, Helm, webhook-recovery, or live GitHub contract tests.
