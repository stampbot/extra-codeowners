# Runtime vulnerability review

## Installation retry cadence: November 11, 2026 UTC

The reconciler now tracks process-local polling deadlines and cycle membership.
It can wake earlier for a deferred installation while leaving healthy ones at
their normal interval. A cold leader can repeat discovery, but every physical
request still passes the existing authentication, quota and backpressure checks.
The shared lease and durable repository/pull cursors are unchanged.

This changes when existing API and database operations run, not their TLS,
compression or native-library paths. It adds no dependency, subprocess, FFI or
package-management entry point. Image and locked package versions are unchanged.
The 26 fixed statements and the APT and two zlib gzip-file writer exclusions
retain their existing scope and assessment dates. All 29 statement contents are
unchanged; only their reviewed runtime binding advances. No exclusion is added
for wheel-bundled OpenSSL or the separate certificate-processing investigation.

## Quota-header diagnostics: November 10, 2026 UTC

Quota-header parsing now returns a fixed rejection reason alongside its
existing result. The accepted ranges, resource check and reset-time boundary
are unchanged. Request spans record that reason without recording header
values. Rejected observations still cannot replace the shared quota balance;
HTTP 401 retains its existing early exclusion.
The latest-response state replaces earlier retry observations; this changes
diagnostic metadata, not the retry sequence or its quota effects.

This adds no request, dependency, SQL statement, TLS change, native-library
entry point, subprocess or compression path. The 26 fixed-package assessments
still name the same versions; the APT and two zlib gzip-file writer exclusions
retain their existing reachability limits. All 29 statement contents and
assessment dates are unchanged. Only the reviewed runtime binding advances.

## Budget deferral diagnostics: November 10, 2026 UTC

Budget exceptions now classify three existing admission branches with fixed
reason strings. The request span records the reason before it ends, and the
existing reconciliation/authority log events include it. Admission balances,
transactions, delays, queue behavior and GitHub requests are unchanged.

This adds Python string validation and existing trace/log attributes, not a
subprocess, native-library entry point, compression operation or TLS setting.
Dependencies and image inputs are unchanged. All 29 statement contents and
assessment dates are retained; only the reviewed runtime binding advances.
The APT and zlib gzip-file writer exclusions keep their existing scope and
limits, and fixed-package statements still identify the same package versions.

## zlib gzip-file writers: November 10, 2026 UTC

[CVE-2026-76844](https://security-tracker.debian.org/tracker/CVE-2026-76844)
and [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091)
concern stale input buffers in zlib's C `gz*` file-writer interface after a
write error or non-blocking stall. Debian reports the installed `zlib1g`
`1:1.3.dfsg+really1.3.1-1+b1` as vulnerable. This assessment doesn't dispute that
classification or claim the package is patched.

The discovery cache uses Python `zlib.compress` and `decompressobj` on bounded
in-memory bodies. CPython's zlib extensions import deflate/inflate and checksum
APIs, not `gz*` APIs. Python's gzip and HTTP decoding use those memory-oriented
bindings too; using gzip framing is not the same as calling C's gzip-file writer.

Both published alpha.75 native images were exported and all 778 regular ELF
files per architecture inspected with `readelf`. The only `gz*` importers were
`dpkg-deb` and `libapt-pkg`. The [caller table](zlib-2026-gzip-callers.json)
records their hashes and CPython's zlib imports. The service entrypoints, routes,
healthcheck and migrations neither start package-management programs nor load
APT. An amd64 import probe covering the application, Psycopg, SQLite, zlib and
gzip also loaded neither caller. ARM64 received static inspection, not execution.
Import tables are supporting evidence; the source review establishes which
programs the service actually invokes.

The two new `not_affected` statements use
`vulnerable_code_not_in_execute_path` and name only these Debian binaries on
amd64 and arm64 with the inventory's Debian 13.7 identity. They do not exempt
an entire image, wheel-bundled components or other zlib findings. The optional
source-package qualifier is omitted; binary version, architecture and
distribution still have to match one inventory entry. Vexcalibur 1.1.1 formatted
the reviewed local findings offline. It did not decide reachability.

The Dockerfile, base-image digest and dependency lock are unchanged. All 27
earlier statement contents and assessment dates are retained, and raw scanner
reports remain unfiltered. Operator-run package management, custom FFI or
plugins, arbitrary commands and execution after compromise are outside this
assessment. The existing runtime binding still requires review when code,
dependencies or image inputs change.

## Discovery validator retention: November 6, 2026 UTC

Discovery entries now expire after two idle hours rather than one. Their
byte and entry limits, bounded zlib decoding, authenticated HTTP revalidation
and quota accounting are unchanged. The change adds no dependency, database
operation, TLS option, subprocess or native-library entry point. APT remains
outside the service's execution path. The 26 `fixed` statements and the one
APT `not_affected` statement retain their assessments and dates; only the
reviewed runtime binding changes.

## APT package installation: November 5, 2026 UTC

[CVE-2026-109518](https://security-tracker.debian.org/tracker/CVE-2026-109518)
requires an APT package installation over manipulated HTTP, with redirects,
retries and hard-link reuse. Debian marks the installed `apt` and
`libapt-pkg7.0` 3.0.3 as vulnerable; trixie's 3.0.4 contains the fix.

The shipped entrypoint, healthcheck, migrations and application routes run
Python. The Dockerfile installs locked Python dependencies with uv, not APT.
The service neither starts APT nor exposes its acquisition API; GitHub HTTP
requests use HTTPX. The reviewed source contains no subprocess or FFI path to
APT. This supports `not_affected` with
`vulnerable_code_not_in_execute_path`, not component absence or a package fix.

The statement names both packages on amd64 and arm64, using the Debian 13.7
identities from the native reports and signed inventories. The 26 earlier
`fixed` statements retain their contents and assessment dates. Raw scanner
findings remain available, and there is no scanner ignore. The runtime binding
forces another review when application code, dependencies or Docker inputs
change.

APT remains installed and unpatched. This assessment does not cover an
operator installing packages, custom code or plugins, or arbitrary execution
after compromise. Non-root execution is defense in depth, not the basis for
the assessment. No container execution or new native-linkage inspection was
performed for this source-level acquisition-path review.

## Bounded reconciliation tracing: November 5, 2026 UTC

Reconciliation now exports a fixed-size summary and linked logical-request
roots through the existing OpenTelemetry SDK. Local context variables carry
sampling and phase totals; bounded private text uses Python string slicing
and the existing traceback formatter. The change adds no authorization reads,
database query, subprocess, native-library loading or TLS setting. Locked
dependencies and image inputs are unchanged. All 26 `fixed` statements and
their assessment dates remain unchanged; this review adds no exclusion.

## Discovery disconnect retry: November 5, 2026 UTC

The discovery client can repeat one authenticated GET after HTTPX reports a
remote protocol error. It shares the existing transient retry budget,
deadline, parser and quota guard. It adds no write, streaming or token-request
retry, and no new native-library entry point. Dependencies, package identities
and TLS configuration are unchanged. All 26 `fixed` statements and their
assessment dates remain unchanged; this source review adds no exclusion.

## Current runtime: November 2, 2026

The pinned Python 3.14.10 base replaces 3.14.8. This is Python's
[expedited security release](https://www.python.org/downloads/release/python-31410/)
for the compromised eMudhra intermediate keys. The locked certifi bundle is
also updated to 2026.10.19, and the digest-pinned uv build tool to 0.13.4.
These are package updates, not vulnerability exclusions. The Dockerfile still
doesn't upgrade operating-system packages at build time.

Both base architectures contain Debian 13.7 and `libpcre2-8-0`
`10.46-1~deb13u3`. Debian marks
[CVE-2026-103111 fixed in that version](https://security-tracker.debian.org/tracker/CVE-2026-103111).
The current VEX therefore records `fixed`, replacing the previous
`not_affected` assessment. The three earlier PCRE2 statements now identify
the same installed version. No reachability exclusion remains in the current
statement; raw findings still stay in the unfiltered scan reports.

The Python 3.12–3.14 environments retain Psycopg 3.3.4 and its reviewed source
recipe. The new uv resolver also locks Psycopg 3.3.6 for Python 3.15 and later
because 3.3.4 has no compatible wheels there. That future branch is not used
by the current runtime image and does not extend the tested Python matrix.

The page-cache storage change uses Python's existing zlib binding to encode
validated listing bodies. Admission still checks the raw representation's
size; decoding has a fixed output bound and rejects incomplete or trailing
data. A failed decode discards the entry, and HTTP reuse still requires an
authenticated conditional request. No package or library version changes.
All 26 current VEX statements remain `fixed`; this review adds no reachability
exclusion and makes no claim about the older, unpatched images.

The discovery retry change repeats one authenticated GET after a transient
server response, using the same HTTP client, deadline, quota guard and parser.
It adds no retry for writes or streamed reads and no dependency, native-library
or package change. All current `fixed` statements and their assessment dates
remain unchanged.

## Previous runtime: October 5, 2026

The Python 3.14.8 image included Debian's fixes for the nineteen findings
previously marked `not_affected`. Those statements changed to `fixed`, with the
package versions and Debian 13.7 identities found in that image. The VEX
also retained the earlier OpenSSL fixes and recorded four September OpenSSL
findings fixed by `3.5.7-1~deb13u3`.

PyJWT is updated to 2.15.1 and urllib3 to 2.8.0. These are locked package updates,
not exclusions. The Dockerfile still installs the locked graph without building
dependencies or upgrading Debian packages at build time.

One fixable High finding remained in that base: PCRE2
[`CVE-2026-103111`](https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-r9hj-j2rw-4q3m).
It requires the PCRE2 JIT API. Policy matching uses Python `re`; the service
doesn't call that API or load the named Debian library. The amd64 native
dependency graph was checked again after the update, and an import check
confirmed that its loaded libraries contain no PCRE2. ARM64 is checked
statically using the pinned base and checksum-verified wheels from `uv.lock`.
Its psycopg wheel uses a private PCRE2 library through private SELinux code,
which imports ordinary matching functions rather than JIT APIs.

That `not_affected` statement named only Debian's `libpcre2-8-0`
`10.46-1~deb13u2` on amd64 and arm64. It did not exempt wheel-bundled libraries,
custom FFI, native plugins, or arbitrary programs run inside the container.
Other scanner findings remain visible in the unfiltered release inventories.

## Historical assessment: September 14, 2026

The eighteen CVEs blocking the September 14, 2026 image scans were not reachable through
the shipped service. The final glibc assessment required a native caller review,
described below. All eighteen now have `not_affected` statements; this does not
mean the underlying packages are patched or that every scanner finding was
assessed. A September 19 addition covers one further PCRE2 finding, bringing
the total to nineteen `not_affected` statements for that older runtime.

The release's OpenVEX file contained the individual CVEs, exact
package URLs, explanations, and Debian advisory links. It also retained the two
existing OpenSSL `fixed` statements. This historical review covers fixable High/Critical
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
matched. The image-derived `debian-13.6` identities let the reviewed findings
match. CVE-2026-5450 initially stayed under investigation until the caller review
was complete. The severity threshold and unfiltered inventory are unchanged.

## Findings

| Debian package version | CVEs | Decision and reason |
| --- | --- | --- |
| `perl-base` `5.40.1-6` | 11, listed individually in VEX | Not affected. Neither the Python entrypoint nor the healthcheck starts Perl, and the service does not embed libperl. The affected Perl regex, archive, socket, serialization, and HTTP implementations are not used. |
| `gzip` `1.13-1` | CVE-2026-41992 | Not affected. No GNU gzip process is started. HTTP gzip decoding uses Python's zlib bindings. The reported bug requires a particular sequence of inputs to GNU gzip. |
| `libpcre2-8-0` `10.46-1~deb13u1` | CVE-2026-86145, CVE-2026-89161 | Not affected. This Debian library is outside the Python/native dependency graph on both architectures. See the private-wheel distinction below. |
| `libsqlite3-0` `3.46.1-7+deb13u1` | CVE-2026-11822, CVE-2026-11824 | Not affected. The affected FTS5 database-page processing requires FTS5 queries. Application schemas, migrations, and queries do not use FTS virtual tables, `MATCH`, or extension loading. There is no database-upload endpoint. This assessment includes the supported SQLite backend. |
| `libc6` and `libc-bin` `2.41-12+deb13u3` | CVE-2026-5928 | Not affected. The application does not use C wide-stream pushback. The native caller check is described below. |
| `libc6` and `libc-bin` `2.41-12+deb13u3` | CVE-2026-5450 | Not affected. The reviewed native callers use fixed numeric/string formats, not the vulnerable allocating character conversion. The general-purpose ncurses format-forwarding API is not exposed by the service. |

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
image's CPython source record. A string search alone did not justify an
exemption, because native libraries can construct or forward format strings.

We then reviewed calls through the native libraries' `scanf` PLT/GOT entries:
30 call sites on amd64 and 36 on ARM64. The
[caller record](glibc-2026-5450-callers.json) lists binary hashes, instruction
offsets, and format strings. It also covers nine calls within glibc on each
architecture. Three ARM64 format pointers spilled to the stack were followed
manually back to constant data, rather than trusting the linear disassembly
helper's candidate values.

The OpenSSL calls parse URL ports with `%u` or `%d`; the older ARM64 OpenSSL
copy uses a fixed four-part numeric format. CFFI/libffi, libpq, keyutils,
libuuid, and CPython likewise supply fixed formats. SELinux's allocating `%ms`
string conversions are not the affected `%mc` character conversion. None of
those callers supplies the operation that triggers this CVE.

The general format-forwarding path outside glibc is ncurses `vwscanw`. The
service does not use it, and CPython `_curses` does not expose `scanw` or
`vwscanw`. The glibc `fscanf` wrapper forwards the arguments reviewed at its
external callers; no dependency imports `fwscanf`. The service does not expose
an FFI or plugin interface through which repository data could select another
format-taking C function. These are the grounds for `not_affected`, not the
absence of a suspicious string or a promise that arbitrary code in this image
is safe.

## Scope and maintenance

### September 19 addition: PCRE2 pattern conversion

The September 19 scans added CVE-2026-89157 for Debian `libpcre2-8-0`
`10.46-1~deb13u1` on both architectures. The
[PCRE2 maintainer advisory](https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-q8g2-wprr-34m9)
describes an allocation overflow in `pcre2_pattern_convert()` on 32-bit
systems. It requires a large foreign-syntax pattern and PCRE2-managed output
allocation; ordinary pattern matching is not the affected operation.

Our release workflow publishes only `linux/amd64` and `linux/arm64`, both with
64-bit `size_t`. The Debian library is also outside the native dependency graph
reviewed above, and the service does not call this conversion API. The base
image and locked dependencies have not changed since that review. These are
the grounds for `not_affected`; the package itself remains unpatched.

The Vexcalibur-generated statement names only this Debian package version on
amd64 and arm64. It does not exempt private wheel libraries, 32-bit builds, or
arbitrary programs run inside the container. Debian lists `10.46-1~deb13u2` as
fixed in its [security tracker](https://security-tracker.debian.org/tracker/CVE-2026-89157).
The normal base-image update can pick up that fix without adding package
upgrades to the Dockerfile.

### Review boundaries

The September 19 target-branch policy change adds authenticated GitHub reference
reads through the existing HTTPX client, validates their JSON responses, and
uses the resolved commit for policy and CODEOWNERS. It does not change the
base image, locked dependencies, native-library loading, or database queries.
The new parsing uses Python's JSON, string, and regular-expression operations;
it introduces no subprocess, FFI, FTS5, or native format-string entrypoint.
The package-specific reachability conclusions above still apply. The VEX
runtime binding records this source review; its vulnerability statements are
unchanged.

The earlier cache partition change kept the existing byte cache and HTTP
revalidation paths. It separates storage budgets and adds fixed-label metrics;
it did not compress, deserialize new formats, or change dependencies. The
same reachability conclusions apply.

The authority discovery change skips duplicate jobs after checking enrollment
through the existing GitHub client. It uses the same Python validation and
database queue methods, with no new native calls or dependencies. The existing
reachability assessments therefore still apply.

The October 4 authority budget change shares branch and policy reads within a
repository attempt and schedules background discovery against the existing
quota reserve. Its database changes use ordinary SQLAlchemy `EXISTS`, `CASE`,
and row updates to preserve direct-event wakeups. It adds no SQLite FTS tables,
`MATCH` queries, extension loading, subprocesses, FFI, or native format-string
calls. Dependencies and image inputs are unchanged, so the package-specific
assessments above still apply.

The authority cursor migration adds one integer column and backfills it through
SQLAlchemy. Discovery checkpoints use ordinary row updates. Sharing the policy
observation during check invalidation changes only which existing Python API
reads are repeated; neither change adds a native input path.

The October 7 authority-page fix replaces a PR-number ordering comparison with
a page-local Python set that detects duplicates. It changes neither HTTP
transport nor native-library loading, database queries, dependencies, or image
inputs. It adds no PCRE2 or other native API entrypoint. The existing package
versions and vulnerability statements therefore remain unchanged; only the
reviewed source binding is refreshed.

These conclusions apply to the shipped service's behavior, including its SQLite
backend. They do not cover arbitrary commands, custom Python code, native
plugins, or externally supplied databases. A change in those behaviors requires
another review even when package versions stay the same. The runtime hash
manifest in the VEX file makes CI stop when application, dependency, or build
inputs change; a maintainer must review the change before recording new hashes.
Package updates also stop the old package URLs from matching. Python bytecode
caches are excluded from both the Docker context and the source binding.

The statement was generated offline with
[Vexcalibur v0.7.0](https://github.com/vexcalibur-dev/vexcalibur/releases/tag/v0.7.0)
from reviewed local findings and versioned package identities, then bound to
the runtime inputs with `tools/release_vex.py bind-runtime`. Vexcalibur formats
the assessment; neither tool establishes reachability. See the
[security policy](../../SECURITY.md#vulnerability-statements) for publication
and attestation details.
