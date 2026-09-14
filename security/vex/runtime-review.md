# Runtime vulnerability review — September 14, 2026

Seventeen of the eighteen CVEs blocking the reviewed image scans are not
reachable through the shipped service. We cannot yet exclude CVE-2026-5450 in
glibc. It remains `under_investigation`, so the vulnerability gate stays red.
That is an unresolved assessment, not a finding that the service is exploitable.

The [OpenVEX file](runtime.openvex.json) contains the individual CVEs, exact
package URLs, explanations, and Debian advisory links. It also retains the two
existing OpenSSL `fixed` statements. This review covers fixable High/Critical
findings from the September 14 scans, not every item in the raw inventory.

## Images examined

Both images are from `0.1.0-alpha.41`, source revision
`85ac496f9499d373dc6dfde9afc10832023a991c`.

| Platform | Image digest |
| --- | --- |
| linux/amd64 | `sha256:a205c98e47a94510219e8ff49f336c0f76dca7e93ecf813341cb06ff90d14251` |
| linux/arm64 | `sha256:4cffcd4d30af9afc4bcfa138b508e136a61d60e1ad3530f8ecf1848af2191898` |

Package versions were checked against the corresponding release inventories.
The images' canonical `os-release` files report `VERSION_ID=13` and
`DEBIAN_VERSION_FULL=13.6`. Grype uses the latter in package URLs. The inventory
collector now retains both values; the VEX publisher requires the claimed
identity to be present in the inventory, not merely share a major version.
Historical inventories without a full-version field still validate major-only
claims, but cannot validate a guessed point release.
Each scan reports 20 blocking package/CVE pairs: the two glibc CVEs appear for
both `libc6` and `libc-bin`, giving 18 distinct CVEs.

Grype v0.118.0 was run against both image archives with the same database built
on September 13, 2026. With `distro=debian-13`, none of the new VEX exclusions
matched. With the image-derived `debian-13.6` identities, the reviewed findings
move to the ignored list and CVE-2026-5450 remains a blocking High finding for
both glibc packages. No vulnerability or severity filter was broadened.

## Findings

| Debian package version | CVEs | Decision and reason |
| --- | --- | --- |
| `perl-base` `5.40.1-6` | 11, listed individually in VEX | Not affected. Neither the Python entrypoint nor the healthcheck starts Perl, and the service does not embed libperl. The affected Perl regex, archive, socket, serialization, and HTTP implementations are not used. |
| `gzip` `1.13-1` | CVE-2026-41992 | Not affected. No GNU gzip process is started. HTTP gzip decoding uses Python's zlib bindings. The reported bug requires a particular sequence of inputs to GNU gzip. |
| `libpcre2-8-0` `10.46-1~deb13u1` | CVE-2026-86145, CVE-2026-89161 | Not affected. This Debian library is outside the Python/native dependency graph on both architectures. See the private-wheel distinction below. |
| `libsqlite3-0` `3.46.1-7+deb13u1` | CVE-2026-11822, CVE-2026-11824 | Not affected. The affected FTS5 database-page processing requires FTS5 queries. Application schemas, migrations, and queries do not use FTS virtual tables, `MATCH`, or extension loading. There is no database-upload endpoint. This assessment includes the supported SQLite backend. |
| `libc6` and `libc-bin` `2.41-12+deb13u3` | CVE-2026-5928 | Not affected. The application does not use C wide-stream pushback. The native caller check is described below. |
| `libc6` and `libc-bin` `2.41-12+deb13u3` | CVE-2026-5450 | Under investigation. Native dependencies call `scanf` functions. No vulnerable format was identified, but that alone does not prove the path unreachable. |

### Native-library checks

We examined ELF dependencies and undefined symbols from every native file under
`/usr/local` and `/opt`, then followed their shared-library dependencies. This
deliberately includes unused standard-library and test extensions. Each image
had 138 files in that expanded dependency graph. The only unresolved libraries
were Tcl/Tk dependencies of the unused `_tkinter` module.

On amd64, a read-only, network-disabled import check loaded the application,
PostgreSQL driver, cryptography bindings, SQLite, greenlet, Pydantic, and HTTPX.
`/proc/self/maps` confirmed the loaded library paths. ARM64 was inspected
statically, not executed. Import checks are supporting evidence, not proof of
all request-time behavior; optional native loaders still require code review.

**PCRE2:** Python policy matching uses `re`, but that is not the whole dependency
graph. The ARM64 psycopg wheel bundles its own PCRE2 through its private SELinux
library. That library imports ordinary matching and serialization functions,
not `pcre2_dfa_match` or `pcre2_jit_match`. The amd64 wheel instead bundles PCRE1.
Neither resolves to the Debian PCRE2 library named in these findings. The VEX
products name only the Debian package; they do not exempt wheel-bundled copies.

**Wide-character pushback:** CPython 3.14.7 has no `ungetwc` call. The only
external importer of that symbol in either expanded native graph is
`libstdc++.so.6.0.33`. Its consumers are greenlet and greenlet's test extension;
their C++ imports are allocation, strings, exception support, and runtime
machinery, not wide streams. The amd64 disassembly places the `ungetwc` calls
in `__gnu_cxx::stdio_sync_filebuf<wchar_t>` methods. Python text decoding does
not use that stream implementation. This conclusion does not depend on an
operator retaining a particular locale setting.

**`scanf`:** CPython's source calls use fixed numeric or bounded string formats,
not the allocating character conversion described in
[CVE-2026-5450](https://security-tracker.debian.org/tracker/CVE-2026-5450).
The exact 3.14.7 source archive has SHA-256
`3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81`, matching the
image's CPython source record. Native importers also include CFFI, OpenSSL,
libpq, SELinux, keyutils, libuuid, and ncurses. A full-length string search of
both dependency graphs found no vulnerable format. It did find SELinux `%ms`
formats, which are a different conversion. Binary strings do not establish
format provenance, rule out constructed formats, or cover indirect calls.
We therefore leave this CVE unresolved. Excluding it needs a caller-level review
of the remaining native paths; updating to a digest with Debian's fixed glibc
package is the other way to clear it.

## Scope and maintenance

These conclusions apply to the shipped service's behavior, including its SQLite
backend. They do not cover arbitrary commands, custom Python code, native
plugins, or externally supplied databases. A change in those behaviors requires
another review even when package versions stay the same. Package updates stop
the old package URLs from matching and require an explicit statement update.

The statement was generated offline with
[Vexcalibur v0.7.0](https://github.com/vexcalibur-dev/vexcalibur/releases/tag/v0.7.0)
from reviewed local findings and versioned package identities. Vexcalibur
formats the assessment; it does not establish reachability. See the
[security policy](../../SECURITY.md#vulnerability-statements) for publication
and attestation details.
