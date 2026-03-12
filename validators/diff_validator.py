from __future__ import annotations

from pathlib import Path

from filelock_ai.paths import dedupe_repo_paths
from validators.plan_validator import _extract_path_token, _looks_like_path


class DiffValidationError(Exception):
    """Raised when diff input cannot be parsed."""


def load_changed_files(path: str) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        raise DiffValidationError(
            f"Diff file not found: {path}. "
            "Hint: pass a valid diff/file-list path, e.g. 'filelock-ai validate diff.txt'."
        )

    lines = file_path.read_text(encoding="utf-8").splitlines()
    candidates: list[str] = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "/dev/null":
            continue

        path_candidate = _extract_path_token(line)
        if path_candidate and _looks_like_path(path_candidate):
            candidates.append(path_candidate)

    return dedupe_repo_paths(candidates)
