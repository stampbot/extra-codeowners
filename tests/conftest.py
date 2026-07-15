from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import HealthCheck, settings

_SHARED_HEALTH_CHECKS = [HealthCheck.function_scoped_fixture]
settings.register_profile(
    "dev",
    derandomize=False,
    deadline=500,
    max_examples=50,
    database=None,
    suppress_health_check=_SHARED_HEALTH_CHECKS,
)
settings.register_profile(
    "ci",
    derandomize=True,
    deadline=750,
    max_examples=250,
    database=None,
    suppress_health_check=_SHARED_HEALTH_CHECKS,
)
settings.register_profile(
    "scheduled",
    derandomize=False,
    deadline=1000,
    max_examples=2000,
    database=None,
    suppress_health_check=_SHARED_HEALTH_CHECKS,
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))


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
