from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from filelock_ai.paths import normalize_repo_path

VALID_ACTIONS = {"allowed", "blocked", "manual_approval", "readonly"}
_ACTION_ALIASES = {
    "allow": "allowed",
}


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
    branches: tuple[str, ...] = field(default_factory=tuple)
    environments: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Policy:
    version: int
    default_action: str
    case_sensitive: bool
    symlink_action: str
    rules: tuple[Rule, ...]
    tag_patterns: dict[str, tuple[str, ...]]
    source_path: str
    source_paths: tuple[str, ...]
    root_dir: str


def load_policy(policy_path: str) -> Policy:
    path = Path(policy_path)
    merged_raw, source_paths = _load_policy_raw(path, stack=[])

    version = _parse_version(merged_raw.get("version", None))

    default_action = _parse_action(
        merged_raw.get("default_action", "manual_approval"),
        context=f"default_action in '{policy_path}'",
    )
    case_sensitive = _parse_bool(merged_raw.get("case_sensitive", False), "case_sensitive")

    symlink_action = _parse_action(
        merged_raw.get("symlink_policy", "blocked"),
        context="symlink_policy",
    )

    tags_raw = merged_raw.get("tag_definitions", merged_raw.get("tags", {}))
    tag_patterns = _parse_tag_patterns(tags_raw)

    rule_groups_raw = merged_raw.get("rule_groups", {})
    rules_raw = _expand_rules(merged_raw.get("rules", []), rule_groups_raw)

    rules: list[Rule] = []
    for idx, rule_raw in enumerate(rules_raw, start=1):
        if not isinstance(rule_raw, dict):
            raise PolicyError(f"Rule #{idx} must be an object.")

        action = _parse_action(rule_raw.get("action", ""), context=f"rule #{idx}")

        name = str(rule_raw.get("name", f"rule_{idx}")).strip() or f"rule_{idx}"
        path_globs = _normalize_patterns(_to_tuple(rule_raw, ["path_glob", "path_globs", "paths", "glob"]))
        file_extensions = _normalize_extensions(
            _to_tuple(rule_raw, ["file_extension", "extensions", "ext"])
        )
        directories = _normalize_directories(_to_tuple(rule_raw, ["directory", "directories", "dir"]))
        rule_tags = _to_tuple(rule_raw, ["tags", "tag"])
        branches = _normalize_patterns(_to_tuple(rule_raw, ["branches", "branch"]))
        environments = _normalize_patterns(_to_tuple(rule_raw, ["environments", "environment", "env"]))

        rules.append(
            Rule(
                name=name,
                action=action,
                path_globs=path_globs,
                file_extensions=file_extensions,
                directories=directories,
                tags=tuple(t.lower().strip() for t in rule_tags if t.strip()),
                branches=branches,
                environments=environments,
            )
        )

    return Policy(
        version=version,
        default_action=default_action,
        case_sensitive=case_sensitive,
        symlink_action=symlink_action,
        rules=tuple(rules),
        tag_patterns=tag_patterns,
        source_path=str(path),
        source_paths=tuple(source_paths),
        root_dir=str(path.resolve().parent),
    )


def _load_policy_raw(path: Path, stack: list[Path]) -> tuple[dict[str, Any], list[str]]:
    if not path.exists():
        raise PolicyError(
            f"Policy file not found: {path}. "
            "Hint: run 'filelock-ai init-policy --profile startup-app'."
        )

    resolved = path.resolve()
    if resolved in stack:
        cycle = " -> ".join(str(p) for p in [*stack, resolved])
        raise PolicyError(f"Policy include cycle detected: {cycle}")

    stack.append(resolved)
    try:
        raw = _read_yaml_object(path)
        merged: dict[str, Any] = {}
        merged_sources: list[str] = []

        includes = _to_str_list(raw.get("include", []))
        for include_entry in includes:
            include_path = Path(include_entry)
            if not include_path.is_absolute():
                include_path = path.parent / include_path
            included_raw, included_sources = _load_policy_raw(include_path, stack)
            merged = _merge_policy_raw(merged, included_raw)
            merged_sources.extend(included_sources)

        merged = _merge_policy_raw(merged, raw)
        merged.pop("include", None)
        merged_sources.append(str(resolved))
        return merged, _dedupe_list(merged_sources)
    finally:
        stack.pop()


def _read_yaml_object(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        line = getattr(getattr(exc, "problem_mark", None), "line", None)
        column = getattr(getattr(exc, "problem_mark", None), "column", None)
        location = ""
        if line is not None and column is not None:
            location = f" (line {line + 1}, column {column + 1})"
        raise PolicyError(
            f"Invalid YAML in policy file '{path}'{location}. "
            "Hint: check indentation and ':' separators."
        ) from exc

    if not isinstance(raw, dict):
        raise PolicyError(f"Policy '{path}' must be a YAML object at the top level.")
    return raw


def _merge_policy_raw(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)

    for key, value in incoming.items():
        if key in {"rules", "tag_definitions", "tags", "rule_groups", "include"}:
            continue
        out[key] = value

    base_tags = base.get("tag_definitions", base.get("tags", {}))
    in_tags = incoming.get("tag_definitions", incoming.get("tags", {}))
    merged_tags = _merge_mapping_of_any(base_tags, in_tags, field_name="tag_definitions")
    if merged_tags:
        out["tag_definitions"] = merged_tags

    base_groups = base.get("rule_groups", {})
    in_groups = incoming.get("rule_groups", {})
    merged_groups = _merge_mapping_of_any(base_groups, in_groups, field_name="rule_groups")
    if merged_groups:
        out["rule_groups"] = merged_groups

    merged_rules: list[Any] = []
    for source, field in ((base, "rules"), (incoming, "rules")):
        if field not in source:
            continue
        value = source[field]
        if not isinstance(value, list):
            raise PolicyError(f"'{field}' must be a list.")
        merged_rules.extend(value)
    out["rules"] = merged_rules

    return out


def _merge_mapping_of_any(left: Any, right: Any, *, field_name: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for value in (left, right):
        if value in (None, {}):
            continue
        if not isinstance(value, dict):
            raise PolicyError(f"'{field_name}' must be an object.")
        for key, item in value.items():
            out[str(key)] = item
    return out


def _expand_rules(rules_raw: Any, rule_groups_raw: Any) -> list[dict[str, Any]]:
    if not isinstance(rules_raw, list):
        raise PolicyError("'rules' must be a list.")

    if rule_groups_raw in (None, {}):
        groups: dict[str, list[dict[str, Any]]] = {}
    else:
        if not isinstance(rule_groups_raw, dict):
            raise PolicyError("'rule_groups' must be an object mapping group names to rule lists.")
        groups = {}
        for group_name, group_rules_raw in rule_groups_raw.items():
            if not isinstance(group_rules_raw, list):
                raise PolicyError(f"rule_groups.{group_name} must be a list of rules.")
            parsed_group: list[dict[str, Any]] = []
            for idx, group_rule in enumerate(group_rules_raw, start=1):
                if not isinstance(group_rule, dict):
                    raise PolicyError(f"rule_groups.{group_name}[{idx}] must be an object.")
                parsed_group.append(dict(group_rule))
            groups[str(group_name)] = parsed_group

    expanded: list[dict[str, Any]] = []
    for idx, rule_item in enumerate(rules_raw, start=1):
        if not isinstance(rule_item, dict):
            raise PolicyError(f"Rule #{idx} must be an object.")

        group_refs = _to_tuple(rule_item, ["use_group", "use_groups"])
        if not group_refs:
            expanded.append(dict(rule_item))
            continue

        allowed_keys = {"use_group", "use_groups", "name_prefix"}
        extra = set(rule_item.keys()) - allowed_keys
        if extra:
            raise PolicyError(
                f"Rule #{idx} uses group references but also has unsupported keys: {sorted(extra)}"
            )

        name_prefix = str(rule_item.get("name_prefix", ""))
        for group_name in group_refs:
            if group_name not in groups:
                raise PolicyError(f"Rule #{idx} references unknown rule group '{group_name}'.")
            for group_rule in groups[group_name]:
                clone = dict(group_rule)
                if name_prefix and "name" in clone:
                    clone["name"] = f"{name_prefix}{clone['name']}"
                expanded.append(clone)

    return expanded


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


def _parse_action(raw_action: Any, *, context: str) -> str:
    action = str(raw_action).strip().lower()
    action = _ACTION_ALIASES.get(action, action)
    if action not in VALID_ACTIONS:
        raise PolicyError(
            f"Invalid action '{raw_action}' in {context}. Valid values: {sorted(VALID_ACTIONS)}. "
            "Hint: update the action value."
        )
    return action


def _parse_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0"}:
            return False
    raise PolicyError(f"'{field_name}' must be a boolean (true/false).")


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
        parsed[tag_name] = _normalize_patterns(tuple(v.strip() for v in values if v.strip()))
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


def _normalize_patterns(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        item = value.strip().replace("\\", "/")
        if not item:
            continue

        negated = item.startswith("!")
        body = item[1:] if negated else item

        while "//" in body:
            body = body.replace("//", "/")
        if body.startswith("./"):
            body = body[2:]
        while body.startswith("/"):
            body = body[1:]

        final = f"!{body}" if negated else body
        if final and final != "!":
            normalized.append(final)
    return tuple(normalized)


def _normalize_extensions(extensions: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for ext in extensions:
        ext = ext.strip()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        normalized.append(ext)
    return tuple(normalized)


def _normalize_directories(directories: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for directory in directories:
        directory = normalize_repo_path(directory)
        if directory:
            normalized.append(directory)
    return tuple(normalized)


def _dedupe_list(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
