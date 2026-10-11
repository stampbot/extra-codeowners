# Decision records

These architecture decision records (ADRs) explain choices that a later change
has to respect, and the alternatives each one beat. The pages elsewhere in this
manual describe how the system works now; a record here says why it works that
way.

Each file is named for the date the decision was made. A record isn't edited
once it's Accepted. A changed decision gets a new record that supersedes the
old one.

| Date | Decision | Status |
| --- | --- | --- |
| 2026-07-13 | [Delegate App approvals through a required check](2026-07-13-app-approvals-through-a-required-check.md) | Accepted |
| 2026-07-13 | [Store webhook work before acknowledging it](2026-07-13-store-webhook-work-first.md) | Accepted |
| 2026-07-15 | [Apply schema changes only through an explicit migrator](2026-07-15-explicit-schema-migrations.md) | Accepted |
| 2026-08-17 | [Build the runtime image on Debian slim](2026-08-17-debian-slim-runtime.md) | Accepted |
| 2026-08-17 | [Release every main commit from its CI run](2026-08-17-release-from-main-ci.md) | Accepted |

These first five were written in October 2026 to record decisions already in
effect. Their dates come from the commits and pull requests that made each
decision. Each record states the decision as it stands now, including later
refinements, and its Implementation row names the pull requests that added
them.
