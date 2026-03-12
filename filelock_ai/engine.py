from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import PurePosixPath

from filelock_ai.paths import dedupe_repo_paths, normalize_repo_path
from filelock_ai.policy import Policy, Rule

_ACTION_PRIORITY = {
    "allowed": 0,
    "manual_approval": 1,
    "readonly": 2,
    "blocked": 3,
}


@dataclass(frozen=True)
class FileDecision:
    path: str
    action: str
    matched_rule: str | None
    tags: tuple[str, ...]

    @property
    def category(self) -> str:
        if self.action in {"blocked", "readonly"}:
            return "blocked"
        if self.action == "manual_approval":
            return "approval_required"
        return "allowed"


@dataclass(frozen=True)
class EvaluationReport:
    allowed: tuple[FileDecision, ...]
    blocked: tuple[FileDecision, ...]
    approval_required: tuple[FileDecision, ...]

    def exit_code(self) -> int:
        if self.blocked:
            return 1
        if self.approval_required:
            return 2
        return 0

    def as_dict(self) -> dict[str, list[dict[str, object]]]:
        return {
            "allowed_changes": [_decision_to_dict(d) for d in self.allowed],
            "blocked_changes": [_decision_to_dict(d) for d in self.blocked],
            "approval_required_changes": [_decision_to_dict(d) for d in self.approval_required],
        }


def evaluate_changes(policy: Policy, paths: list[str]) -> EvaluationReport:
    unique_paths = dedupe_repo_paths(paths)

    decisions: list[FileDecision] = [evaluate_path(policy, path) for path in unique_paths]

    allowed: list[FileDecision] = []
    blocked: list[FileDecision] = []
    approval: list[FileDecision] = []

    for decision in decisions:
        if decision.category == "allowed":
            allowed.append(decision)
        elif decision.category == "blocked":
            blocked.append(decision)
        else:
            approval.append(decision)

    return EvaluationReport(
        allowed=tuple(allowed),
        blocked=tuple(blocked),
        approval_required=tuple(approval),
    )


def evaluate_path(policy: Policy, raw_path: str) -> FileDecision:
    path = normalize_repo_path(raw_path)
    file_tags = infer_tags(path, policy)

    matched: list[Rule] = [r for r in policy.rules if rule_matches(path, file_tags, r)]

    if matched:
        winner = sorted(
            matched,
            key=lambda r: (_ACTION_PRIORITY.get(r.action, -1), policy.rules.index(r)),
            reverse=True,
        )[0]
        return FileDecision(path=path, action=winner.action, matched_rule=winner.name, tags=file_tags)

    return FileDecision(path=path, action=policy.default_action, matched_rule=None, tags=file_tags)


def infer_tags(path: str, policy: Policy) -> tuple[str, ...]:
    tags: list[str] = []
    for tag, patterns in policy.tag_patterns.items():
        if any(fnmatch(path, pattern) for pattern in patterns):
            tags.append(tag)
    return tuple(sorted(tags))


def rule_matches(path: str, file_tags: tuple[str, ...], rule: Rule) -> bool:
    if rule.path_globs and not any(fnmatch(path, pattern) for pattern in rule.path_globs):
        return False

    suffix = PurePosixPath(path).suffix.lower()
    if rule.file_extensions and suffix not in rule.file_extensions:
        return False

    if rule.directories and not any(_is_in_directory(path, directory) for directory in rule.directories):
        return False

    if rule.tags and not any(tag in file_tags for tag in rule.tags):
        return False

    return True


def _is_in_directory(path: str, directory: str) -> bool:
    normalized_dir = directory.replace("\\", "/").strip("/")
    return path == normalized_dir or path.startswith(f"{normalized_dir}/")


def normalize_path(value: str) -> str:
    # Backward-compatible wrapper: prefer normalize_repo_path everywhere.
    return normalize_repo_path(value)


def _dedupe_paths(paths: list[str]) -> list[str]:
    return dedupe_repo_paths(paths)


def _decision_to_dict(decision: FileDecision) -> dict[str, object]:
    payload: dict[str, object] = {
        "path": decision.path,
        "action": decision.action,
        "tags": list(decision.tags),
    }
    if decision.matched_rule:
        payload["matched_rule"] = decision.matched_rule
    return payload
