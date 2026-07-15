# Container distribution evidence

This directory contains the reviewed input to the container evidence collector.
`container-policy.json` is deliberately fail-closed: a package version, declared
license, Alpine origin commit, Python source archive, base image, or license-text
change requires a reviewed policy update.

Do not describe a passing collector as a legal-compliance determination. The
collector proves what it observed, which exact sources it preserved, and which
reviewed policy was applied. A maintainer must separately approve the recipient
delivery mechanism by updating `distribution_approval` in the policy.

That approval does not currently enable a tagged release. Publication remains
structurally disabled pending the privilege-separated pipeline in security issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28). Pull-request CI
artifacts are unsigned evidence for this review, not release assets.

Run the documented workflow in
[`docs/how-to/review-container-evidence.md`](../docs/how-to/review-container-evidence.md)
to inspect or update this evidence.
