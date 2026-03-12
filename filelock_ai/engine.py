from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

from filelock_ai.paths import dedupe_repo_paths, normalize_repo_path
from filelock_ai.policy import Policy, Rule

_ACTION_PRIORITY = {
    "allowed": 0,
    "manual_approval": 1,
    "readonly": 2,
    "blocked": 3,
}


@dataclass(frozen=True)
class EvaluationContext:
    branch: str | None = None
    environment: str | None = None


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


def evaluate_changes(
    policy: Policy,
    paths: list[str],
    *,
    context: EvaluationContext | None = None,
) -> EvaluationReport:
    effective_context = context or EvaluationContext()
    unique_paths = dedupe_repo_paths(paths)

    decisions: list[FileDecision] = [
        evaluate_path(policy, path, context=effective_context) for path in unique_paths
    ]

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


def evaluate_path(
    policy: Policy,
    raw_path: str,
    *,
    context: EvaluationContext | None = None,
) -> FileDecision:
    effective_context = context or EvaluationContext()
    path = normalize_repo_path(raw_path)
    if not path:
        return FileDecision(path="", action=policy.default_action, matched_rule=None, tags=())

    file_tags = infer_tags(path, policy)

    symlink_hit = _find_symlink_segment(path, policy.root_dir)
    if symlink_hit and policy.symlink_action != "allowed":
        return FileDecision(
            path=path,
            action=policy.symlink_action,
            matched_rule=f"symlink-guard:{symlink_hit}",
            tags=file_tags,
        )

    matched: list[Rule] = [
        r
        for r in policy.rules
        if rule_matches(path, file_tags, r, policy=policy, context=effective_context)
    ]

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
        if _match_glob_set(path, patterns, case_sensitive=policy.case_sensitive):
            tags.append(tag)
    return tuple(sorted(tags))


def rule_matches(
    path: str,
    file_tags: tuple[str, ...],
    rule: Rule,
    *,
    policy: Policy,
    context: EvaluationContext,
) -> bool:
    if rule.path_globs and not _match_glob_set(path, rule.path_globs, case_sensitive=policy.case_sensitive):
        return False

    suffix = PurePosixPath(path).suffix
    if rule.file_extensions:
        if policy.case_sensitive:
            if suffix not in rule.file_extensions:
                return False
        else:
            rule_exts = {ext.lower() for ext in rule.file_extensions}
            if suffix.lower() not in rule_exts:
                return False

    if rule.directories and not any(
        _is_in_directory(path, directory, case_sensitive=policy.case_sensitive) for directory in rule.directories
    ):
        return False

    if rule.tags and not any(tag in file_tags for tag in rule.tags):
        return False

    if rule.branches:
        if not context.branch:
            return False
        if not any(_glob_match(context.branch, pattern, case_sensitive=policy.case_sensitive) for pattern in rule.branches):
            return False

    if rule.environments:
        if not context.environment:
            return False
        if not any(
            _glob_match(context.environment, pattern, case_sensitive=policy.case_sensitive)
            for pattern in rule.environments
        ):
            return False

    return True


def _match_glob_set(path: str, patterns: tuple[str, ...], *, case_sensitive: bool) -> bool:
    positives = tuple(pattern for pattern in patterns if not pattern.startswith("!"))
    negatives = tuple(pattern[1:] for pattern in patterns if pattern.startswith("!"))

    if positives and not any(_glob_match(path, pattern, case_sensitive=case_sensitive) for pattern in positives):
        return False

    if negatives and any(_glob_match(path, pattern, case_sensitive=case_sensitive) for pattern in negatives):
        return False

    return True


def _glob_match(value: str, pattern: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return fnmatch(value, pattern)
    return fnmatch(value.lower(), pattern.lower())


def _is_in_directory(path: str, directory: str, *, case_sensitive: bool) -> bool:
    normalized_dir = normalize_repo_path(directory)
    if not normalized_dir:
        return False

    if case_sensitive:
        return path == normalized_dir or path.startswith(f"{normalized_dir}/")

    lowered_path = path.lower()
    lowered_dir = normalized_dir.lower()
    return lowered_path == lowered_dir or lowered_path.startswith(f"{lowered_dir}/")


def _find_symlink_segment(path: str, root_dir: str) -> str | None:
    current = Path(root_dir)
    traversed: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        traversed.append(segment)
        current = current / segment
        try:
            if current.exists() and current.is_symlink():
                return "/".join(traversed)
        except OSError:
            # If the filesystem check fails, treat as unknown and continue policy matching.
            continue
    return None


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
