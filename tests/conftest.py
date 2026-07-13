from __future__ import annotations

from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session")
def private_key() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


@pytest.fixture(autouse=True)
def clear_extra_codeowners_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in tuple(__import__("os").environ):
        if name.startswith("EXTRA_CODEOWNERS_"):
            monkeypatch.delenv(name, raising=False)
    yield
