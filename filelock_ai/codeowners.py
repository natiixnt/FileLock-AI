from __future__ import annotations

import re
from pathlib import Path

from filelock_ai.paths import normalize_repo_path


class CodeownersError(Exception):
    """Raised when CODEOWNERS parsing fails."""


def load_codeowners_tag_patterns(
    codeowners_path: str,
    *,
    tag_prefix: str = "owner_",
) -> dict[str, tuple[str, ...]]:
    path = Path(codeowners_path)
    if not path.exists():
        raise CodeownersError(f"CODEOWNERS file not found: {codeowners_path}")

    lines = path.read_text(encoding="utf-8").splitlines()
    collected: dict[str, list[str]] = {}

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            raise CodeownersError(
                f"Invalid CODEOWNERS line {lineno}: expected '<pattern> <owner...>' format."
            )

        pattern_raw = parts[0]
        owners = [token for token in parts[1:] if token.startswith("@")]  # ignore emails/users without @
        if not owners:
            continue

        pattern = _normalize_codeowners_pattern(pattern_raw)
        if not pattern:
            continue

        for owner in owners:
            tag_name = f"{tag_prefix}{_sanitize_owner(owner)}"
            collected.setdefault(tag_name, []).append(pattern)

    return {tag: _dedupe(tuple(patterns)) for tag, patterns in collected.items()}


def _normalize_codeowners_pattern(pattern: str) -> str:
    normalized = pattern.strip().replace("\\", "/")
    if not normalized:
        return ""

    normalized = normalized.lstrip("/")
    if normalized.endswith("/"):
        normalized = f"{normalized}**"

    # Preserve wildcard expressions as-is, otherwise normalize path-like inputs.
    if any(token in normalized for token in ["*", "?", "["]):
        return normalized
    return normalize_repo_path(normalized)


def _sanitize_owner(owner: str) -> str:
    # @org/team-name -> org_team_name
    value = owner.lstrip("@").lower()
    return re.sub(r"[^a-z0-9]+", "_", value).strip("_") or "unknown"


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return tuple(out)
