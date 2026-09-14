import ast
import re
from pathlib import Path


def test_http_reference_lists_every_application_metric() -> None:
    tree = ast.parse(Path("extra_codeowners/metrics.py").read_text(encoding="utf-8"))
    defined = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"Counter", "Gauge", "Histogram"}
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    reference = Path("docs/reference/http-api.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"^\| `(extra_codeowners_[a-z_]+)` \|", reference, re.MULTILINE))
    assert defined
    assert defined == documented


def test_budget_deferral_is_distinguished_from_provider_limits() -> None:
    reference = Path("docs/reference/http-api.md").read_text(encoding="utf-8")
    row = next(
        line
        for line in reference.splitlines()
        if line.startswith("| `extra_codeowners_shared_head_invalidations_total`")
    )
    assert "`budget_deferred`" in row
    assert "`rate_limited`" in row
