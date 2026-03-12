from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from filelock_ai.paths import dedupe_repo_paths, normalize_repo_path

_GIT_STATUS = {"M", "A", "D", "R", "C", "T", "U", "??"}
_PATH_HINT_KEYS = {
    "path",
    "paths",
    "file",
    "files",
    "filepath",
    "filename",
    "changed_file",
    "changed_files",
    "modified_files",
    "target",
    "source",
    "destination",
}
_KNOWN_FILENAMES = {"Dockerfile", "Makefile", "pyproject.toml", "package.json", "go.mod"}


class PlanValidationError(Exception):
    """Raised when plan input cannot be parsed."""


def load_plan_json(path: str) -> Any:
    file_path = Path(path)
    if not file_path.exists():
        raise PlanValidationError(
            f"Plan file not found: {path}. "
            "Hint: pass a valid plan JSON file path, e.g. 'filelock-ai check plan.json'."
        )

    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PlanValidationError(
            f"Invalid JSON in '{path}' at line {exc.lineno}, column {exc.colno}. "
            "Hint: validate JSON syntax (commas, quotes, brackets)."
        ) from exc


def extract_changed_files(plan: Any) -> list[str]:
    candidates: list[str] = []

    if isinstance(plan, dict):
        for key in ("changed_files", "files", "paths", "modified_files"):
            if key in plan:
                _collect_from_value(plan[key], candidates)

    _walk(plan, candidates, parent_key="")

    return dedupe_repo_paths(candidates)


def _walk(value: Any, candidates: list[str], parent_key: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_lower = str(key).lower()
            if any(hint in key_lower for hint in _PATH_HINT_KEYS):
                _collect_from_value(nested, candidates)
            _walk(nested, candidates, key_lower)
        return

    if isinstance(value, list):
        for item in value:
            _walk(item, candidates, parent_key)
        return

    if isinstance(value, str):
        if parent_key in _PATH_HINT_KEYS or _looks_like_path(value):
            maybe_path = _extract_path_token(value)
            if maybe_path:
                candidates.append(maybe_path)


def _collect_from_value(value: Any, candidates: list[str]) -> None:
    if isinstance(value, list):
        for item in value:
            _collect_from_value(item, candidates)
        return

    if isinstance(value, dict):
        _walk(value, candidates, parent_key="")
        return

    if isinstance(value, str):
        maybe_path = _extract_path_token(value)
        if maybe_path and _looks_like_path(maybe_path):
            candidates.append(maybe_path)


def _extract_path_token(value: str) -> str | None:
    line = value.strip()
    if not line:
        return None

    if "\\t" in line and "\t" not in line:
        line = line.replace("\\t", "\t")

    if line.startswith("diff --git "):
        # diff --git a/path b/path
        parts = line.split()
        if len(parts) >= 4:
            return _strip_diff_prefix(parts[3], from_diff=True)

    tabbed = line.split("\t")
    if len(tabbed) >= 2 and tabbed[0].strip() in _GIT_STATUS:
        return _strip_diff_prefix(tabbed[1].strip(), from_diff=True)

    spaced = line.split()
    if len(spaced) >= 2 and spaced[0] in _GIT_STATUS:
        return _strip_diff_prefix(spaced[1].strip(), from_diff=True)

    if line.startswith("+++ ") or line.startswith("--- "):
        return _strip_diff_prefix(line[4:].strip(), from_diff=True)

    return normalize_repo_path(line)


def _strip_diff_prefix(path: str, *, from_diff: bool) -> str:
    cleaned = path.strip().strip('"')
    if from_diff and (cleaned.startswith("a/") or cleaned.startswith("b/")):
        cleaned = cleaned[2:]
    return normalize_repo_path(cleaned)


def _looks_like_path(value: str) -> bool:
    text = value.strip()
    if not text or "\n" in text or "://" in text:
        return False
    if text in _KNOWN_FILENAMES:
        return True
    if "/" in text or "\\" in text:
        return True
    if re.search(r"\.[A-Za-z0-9]{1,10}$", text):
        return True
    return False
