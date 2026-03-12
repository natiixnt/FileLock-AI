from __future__ import annotations

from typing import Iterable


def normalize_repo_path(value: str) -> str:
    text = str(value).strip().strip('"').strip("'").replace("\\", "/")
    if not text:
        return ""

    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        text = text[2:]

    text = text.lstrip("/")

    parts: list[str] = []
    for part in text.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)

    return "/".join(parts)


def dedupe_repo_paths(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        normalized = normalize_repo_path(raw)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out
