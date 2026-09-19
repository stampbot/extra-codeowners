# Runtime vulnerability review

The eighteen CVEs blocking the September 14, 2026 image scans are not reachable through
the shipped service. The final glibc assessment required a native caller review,
described below. All eighteen now have `not_affected` statements; this does not
mean the underlying packages are patched or that every scanner finding was
assessed. A September 19 addition covers one further PCRE2 finding, bringing
the total to nineteen `not_affected` statements.

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

The subsequent cache partition change keeps the existing byte cache and HTTP
revalidation paths. It separates storage budgets and adds fixed-label metrics;
it does not compress, deserialize new formats, or change dependencies. The
same reachability conclusions apply.

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
