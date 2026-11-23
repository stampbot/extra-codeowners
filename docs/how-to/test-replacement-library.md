# Test a replacement library in the image

If you're replacing Psycopg's bundled `libcrypt` or `libkeyutils`, check
that the binary wheel loads your file before you try it with a database.
Use a disposable container with its network disabled. This test doesn't
change the image or your running app.

Use Bash, Docker on Linux, and `jq`. The Docker host must be able to run
the image's architecture. In a scratch directory, put `image-reference.txt`
and `distribution-inventory-<arch>.json` from the same verified release.
Use the [release verification instructions](../reference/source-archives.md#verify-a-cpython-source-bundle)
to authenticate the inventory. Use the [release provenance verifier][verify]
to check the image signature and platform digest, then pull the image by
the digest in `image-reference.txt` for the desired platform.

Put your trusted replacement at `replacement.so` in this directory. It
must be an ABI-compatible Linux shared library for the selected image
architecture. A shared library runs code in the container when it's loaded,
so don't test a binary from an untrusted source.

## Mount the file over the wheel's copy

Set `arch` to `amd64` or `arm64` and `library` to `libcrypt` or `libkeyutils`.
Don't guess the filename from a different image: the wheel includes a hash
in the name, and the suffix can differ between platforms.

```bash
set -euo pipefail
arch=amd64
library=libcrypt
image=$(<image-reference.txt)
target=$(jq -er --arg library "$library" --arg arch "$arch" '
  if .image.architecture != $arch then error("inventory architecture mismatch")
  else [.python.native_files[]
        | select(.kind == "regular")
        | .path
        | select(test("/psycopg_binary\\.libs/" + $library + "-[0-9a-f]+\\.so\\.1(\\.[0-9]+)*$"))]
  | if length == 1 then "/" + .[0] else error("expected one wheel library") end end
' "distribution-inventory-$arch.json")
test -f "$PWD/replacement.so"

docker run --rm -i --platform "linux/$arch" --pull never --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env PSYCOPG_IMPL=binary --entrypoint /opt/venv/bin/python \
  --mount "type=bind,source=$PWD/replacement.so,target=$target,readonly" \
  "$image" -I -B - "$target" <<'PY'
import os
import sys

from psycopg import pq

pq.Conninfo.parse(b"host=db.example.invalid dbname=fixture")
replacement = os.stat(sys.argv[1])
device = os.major(replacement.st_dev), os.minor(replacement.st_dev)
with open("/proc/self/maps", encoding="utf-8") as mappings:
    for mapping in mappings:
        _, perms, _, mapped_device, inode, *_ = mapping.split(maxsplit=5)
        major, minor = (int(part, 16) for part in mapped_device.split(":"))
        if "x" in perms and (major, minor) == device and int(inode) == replacement.st_ino:
            break
    else:
        raise SystemExit("replacement library was not loaded")
print(f"Loaded replacement with Psycopg {pq.__impl__}, libpq {pq.version()}")
PY
```

Look for `Loaded replacement with Psycopg binary` and a libpq version.
If it fails, check the selected inventory, the library's architecture and
its ABI before trying again. Keep the bind mount out of your deployment
until you've run your own database integration tests. This probe parses a
connection string without connecting, so it can't establish database
compatibility.

We tested both library paths on both release platforms in
[alpha.101](https://github.com/stampbot/extra-codeowners/issues/18#issuecomment-7094543063).
For source and build recipes, see [Source archives](../reference/source-archives.md).

[verify]: https://github.com/stampbot/extra-codeowners/blob/main/.github/scripts/verify-release-provenance.sh
