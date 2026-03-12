from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_ACTIONS = {"allowed", "blocked", "manual_approval", "readonly"}


class PolicyError(Exception):
    """Raised when a policy file is invalid."""


@dataclass(frozen=True)
class Rule:
    name: str
    action: str
    path_globs: tuple[str, ...] = field(default_factory=tuple)
    file_extensions: tuple[str, ...] = field(default_factory=tuple)
    directories: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Policy:
    version: int
    default_action: str
    rules: tuple[Rule, ...]
    tag_patterns: dict[str, tuple[str, ...]]
    source_path: str


def load_policy(policy_path: str) -> Policy:
    path = Path(policy_path)
    if not path.exists():
        raise PolicyError(
            f"Policy file not found: {policy_path}. "
            "Hint: run 'filelock-ai init-policy --profile startup-app'."
        )

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        line = getattr(getattr(exc, "problem_mark", None), "line", None)
        column = getattr(getattr(exc, "problem_mark", None), "column", None)
        location = ""
        if line is not None and column is not None:
            location = f" (line {line + 1}, column {column + 1})"
        raise PolicyError(
            f"Invalid YAML in policy file '{policy_path}'{location}. "
            "Hint: check indentation and ':' separators."
        ) from exc

    if not isinstance(raw, dict):
        raise PolicyError("Policy must be a YAML object at the top level.")

    version = _parse_version(raw.get("version", None))

    default_action = str(raw.get("default_action", "manual_approval")).strip()
    if default_action not in VALID_ACTIONS:
        raise PolicyError(
            f"Invalid default_action '{default_action}' in '{policy_path}'. "
            f"Valid values: {sorted(VALID_ACTIONS)}. "
            "Hint: set one of the valid actions under 'default_action'."
        )

    tags_raw = raw.get("tag_definitions", raw.get("tags", {}))
    tag_patterns = _parse_tag_patterns(tags_raw)

    rules_raw = raw.get("rules", [])
    if not isinstance(rules_raw, list):
        raise PolicyError("'rules' must be a list.")

    rules: list[Rule] = []
    for idx, rule_raw in enumerate(rules_raw, start=1):
        if not isinstance(rule_raw, dict):
            raise PolicyError(f"Rule #{idx} must be an object.")

        action = str(rule_raw.get("action", "")).strip()
        if action not in VALID_ACTIONS:
            raise PolicyError(
                f"Rule #{idx} in '{policy_path}' has invalid action '{action}'. "
                f"Valid values: {sorted(VALID_ACTIONS)}. "
                "Hint: update the rule's 'action' value."
            )

        name = str(rule_raw.get("name", f"rule_{idx}")).strip() or f"rule_{idx}"
        path_globs = _to_tuple(rule_raw, ["path_glob", "path_globs", "paths", "glob"])
        file_extensions = _normalize_extensions(
            _to_tuple(rule_raw, ["file_extension", "extensions", "ext"])
        )
        directories = _normalize_directories(_to_tuple(rule_raw, ["directory", "directories", "dir"]))
        rule_tags = _to_tuple(rule_raw, ["tags", "tag"])

        rules.append(
            Rule(
                name=name,
                action=action,
                path_globs=path_globs,
                file_extensions=file_extensions,
                directories=directories,
                tags=tuple(t.lower().strip() for t in rule_tags if t.strip()),
            )
        )

    return Policy(
        version=version,
        default_action=default_action,
        rules=tuple(rules),
        tag_patterns=tag_patterns,
        source_path=str(path),
    )


def _parse_version(raw_version: Any) -> int:
    if raw_version is None:
        raise PolicyError(
            "Missing required policy 'version'. "
            "Hint: run 'filelock-ai migrate-policy <input> --output filelock-policy.yaml'."
        )

    try:
        version = int(raw_version)
    except (TypeError, ValueError) as exc:
        raise PolicyError(
            f"Invalid policy version '{raw_version}'. Expected integer version 1. "
            "Hint: set 'version: 1'."
        ) from exc

    if version != 1:
        raise PolicyError(
            f"Unsupported policy version '{version}'. Supported versions: [1]. "
            "Hint: run 'filelock-ai migrate-policy <input> --output filelock-policy.yaml'."
        )

    return version


def _parse_tag_patterns(raw: Any) -> dict[str, tuple[str, ...]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError("'tag_definitions' (or top-level 'tags') must be an object.")

    parsed: dict[str, tuple[str, ...]] = {}
    for tag, patterns in raw.items():
        tag_name = str(tag).lower().strip()
        if not tag_name:
            continue
        values = _to_str_list(patterns)
        parsed[tag_name] = tuple(v.strip() for v in values if v.strip())
    return parsed


def _to_tuple(data: dict[str, Any], keys: list[str]) -> tuple[str, ...]:
    for key in keys:
        if key in data:
            values = _to_str_list(data[key])
            return tuple(v.strip() for v in values if v.strip())
    return ()


def _to_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, (str, int, float)):
                result.append(str(item))
            else:
                raise PolicyError(f"Expected string-compatible list value, got '{type(item).__name__}'.")
        return result
    raise PolicyError(f"Expected string or list, got '{type(value).__name__}'.")


def _normalize_extensions(extensions: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for ext in extensions:
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        normalized.append(ext)
    return tuple(normalized)


def _normalize_directories(directories: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for directory in directories:
        directory = directory.replace("\\", "/").strip().strip("/")
        if directory:
            normalized.append(directory)
    return tuple(normalized)
