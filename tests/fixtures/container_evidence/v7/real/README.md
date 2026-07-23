# Real container-evidence fixtures

These fixtures preserve upstream bytes that exposed gaps in the schema 7
validator. Tests decode files ending in `.b64` in memory and pin the decoded
SHA-256 digest, so an accidental fixture change fails loudly.

## CFFI and libffi

`cffi-2.1.0-cp314-musllinux-x86_64.whl.b64` is the
`cffi-2.1.0-cp314-cp314-musllinux_1_2_x86_64.whl` file published on PyPI:

<https://files.pythonhosted.org/packages/b3/c1/6dbd291ee2ae5a50a034aa057207081f545923bbf15dad4511e985aafff5/cffi-2.1.0-cp314-cp314-musllinux_1_2_x86_64.whl>

Its decoded SHA-256 digest is
`dbf7c7a88e2bac086f06d14577332760bdeecc42bdec8ac4077f6260557d9326`.
The wheel contains CFFI's license, but its native extension also appears to
include libffi 3.4.6 statically. `libffi-3.4.6.LICENSE` preserves the exact
notice from the upstream 3.4.6 tag:

<https://raw.githubusercontent.com/libffi/libffi/v3.4.6/LICENSE>

The notice has SHA-256 digest
`67894089811f93fca47a76f85e017da6f8582d4ba0905963c6e0f1ad6df7a195`.

We keep the notice beside the wheel because libffi's license requires it with
copies or substantial portions of the software. This addresses the repository
fixture only. It does not establish which libffi archive built the wheel, so
the `unproven-libffi-build-input` policy omission remains open.

## Rust evidence

The other files are exact `Cargo.lock` and CycloneDX documents extracted from
the Pydantic Core 2.46.4 and Cryptography 48.0.1 artifacts pinned in
[`container-policy.json`](../../../../../.compliance/container-policy.json).
The tests pin each decoded file's digest and use it only to exercise parsing
and source-accounting behavior. The crate fixtures under `crates/` retain their
own source-carried license and notice files inside each archive.
