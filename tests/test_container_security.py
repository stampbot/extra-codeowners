import ast
from pathlib import Path


def test_openvex_excluded_standard_library_paths_are_not_imported() -> None:
    forbidden = {"html.parser", "tarfile"}
    imported: set[str] = set()

    for source_path in Path("extra_codeowners").rglob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(f"{node.module}.{alias.name}" for alias in node.names)

    assert imported.isdisjoint(forbidden), (
        "OpenVEX executable-path evidence is invalid; remove the affected VEX statement "
        f"before introducing these imports: {sorted(imported & forbidden)}"
    )
