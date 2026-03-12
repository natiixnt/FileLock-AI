from __future__ import annotations

from typing import Iterable

_BUILTIN_TAG_PACKS: dict[str, dict[str, tuple[str, ...]]] = {
    "baseline": {
        "auth": (
            "**/auth/**",
            "services/auth/**",
            "src/security/**",
        ),
        "infra": (
            "infra/**",
            "terraform/**",
            "k8s/**",
            "deploy/**",
            "platform/**",
            ".github/workflows/**",
        ),
        "migrations": (
            "**/migrations/**",
            "**/db/migrate/**",
        ),
        "secrets": (
            "**/.env*",
            "**/secrets/**",
            "**/*secret*",
            "**/*.pem",
            "**/*.key",
        ),
    }
}


def available_tag_packs() -> tuple[str, ...]:
    return tuple(sorted(_BUILTIN_TAG_PACKS.keys()))


def load_tag_pack_patterns(pack_names: Iterable[str]) -> dict[str, tuple[str, ...]]:
    merged: dict[str, tuple[str, ...]] = {}
    for raw_name in pack_names:
        name = str(raw_name).strip().lower()
        if not name:
            continue
        if name not in _BUILTIN_TAG_PACKS:
            raise ValueError(
                f"Unknown tag pack '{raw_name}'. Available packs: {sorted(_BUILTIN_TAG_PACKS.keys())}"
            )

        pack = _BUILTIN_TAG_PACKS[name]
        for tag, patterns in pack.items():
            existing = merged.get(tag, ())
            merged[tag] = _dedupe(existing + patterns)

    return merged


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return tuple(out)
