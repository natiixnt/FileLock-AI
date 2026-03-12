from __future__ import annotations

from dataclasses import dataclass

from filelock_ai.policy import Policy, Rule

_ACTION_PRIORITY = {
    "allowed": 0,
    "manual_approval": 1,
    "readonly": 2,
    "blocked": 3,
}


@dataclass(frozen=True)
class LintWarning:
    code: str
    message: str
    rule_index: int | None = None
    rule_name: str | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "code": self.code,
            "message": self.message,
        }
        if self.rule_index is not None:
            payload["rule_index"] = self.rule_index
        if self.rule_name is not None:
            payload["rule_name"] = self.rule_name
        return payload


def lint_policy(policy: Policy) -> list[LintWarning]:
    warnings: list[LintWarning] = []
    emitted: set[tuple[str, int | None, str]] = set()

    def emit(warning: LintWarning) -> None:
        key = (warning.code, warning.rule_index, warning.message)
        if key in emitted:
            return
        emitted.add(key)
        warnings.append(warning)

    first_seen_name: dict[str, int] = {}
    for idx, rule in enumerate(policy.rules, start=1):
        if rule.name in first_seen_name:
            emit(
                LintWarning(
                    code="DUPLICATE_RULE_NAME",
                    message=(
                        f"Rule name '{rule.name}' duplicates rule #{first_seen_name[rule.name]}. "
                        "Rule names should be unique for clear audit output."
                    ),
                    rule_index=idx,
                    rule_name=rule.name,
                )
            )
        else:
            first_seen_name[rule.name] = idx

    for idx, rule in enumerate(policy.rules, start=1):
        for tag in rule.tags:
            if tag not in policy.tag_patterns:
                emit(
                    LintWarning(
                        code="CONTRADICTORY_SELECTORS",
                        message=(
                            f"Rule references unknown tag '{tag}'. Define it in 'tag_definitions' "
                            "or remove it from the rule."
                        ),
                        rule_index=idx,
                        rule_name=rule.name,
                    )
                )

        if rule.path_globs and rule.directories and _is_path_directory_contradiction(rule):
            emit(
                LintWarning(
                    code="CONTRADICTORY_SELECTORS",
                    message=(
                        "Rule combines 'path_glob' and 'directory' selectors that do not overlap. "
                        "This rule will never match."
                    ),
                    rule_index=idx,
                    rule_name=rule.name,
                )
            )

    rules = list(policy.rules)
    for idx, rule in enumerate(rules):
        for later_idx in range(idx + 1, len(rules)):
            later = rules[later_idx]
            if later.action != rule.action:
                continue
            if _is_selectorless(later) or _same_selectors(rule, later):
                emit(
                    LintWarning(
                        code="UNREACHABLE_RULE",
                        message=(
                            f"Rule is shadowed by later rule #{later_idx + 1} with the same action. "
                            "Earlier rule will never be the winning match."
                        ),
                        rule_index=idx + 1,
                        rule_name=rule.name,
                    )
                )
                break

    selectorless = [(idx + 1, rule) for idx, rule in enumerate(rules) if _is_selectorless(rule)]
    if selectorless:
        strongest_priority = max(_ACTION_PRIORITY[rule.action] for _, rule in selectorless)
        strongest_rules = [
            (idx, rule) for idx, rule in selectorless if _ACTION_PRIORITY[rule.action] == strongest_priority
        ]
        strongest_list = ", ".join(f"#{idx} ({rule.action})" for idx, rule in strongest_rules)

        for idx, rule in enumerate(rules, start=1):
            if _ACTION_PRIORITY[rule.action] < strongest_priority:
                emit(
                    LintWarning(
                        code="UNREACHABLE_RULE",
                        message=(
                            f"A selectorless stronger rule ({strongest_list}) always wins over this rule. "
                            "This rule can never determine the final action."
                        ),
                        rule_index=idx,
                        rule_name=rule.name,
                    )
                )

    return warnings


def _same_selectors(left: Rule, right: Rule) -> bool:
    return (
        left.path_globs == right.path_globs
        and left.file_extensions == right.file_extensions
        and left.directories == right.directories
        and left.tags == right.tags
    )


def _is_selectorless(rule: Rule) -> bool:
    return not (rule.path_globs or rule.file_extensions or rule.directories or rule.tags)


def _is_path_directory_contradiction(rule: Rule) -> bool:
    # Conservative check: only flag as contradictory when all glob prefixes are literal and
    # none can overlap any configured directory.
    literal_prefixes = [_literal_prefix(glob) for glob in rule.path_globs]
    if any(prefix == "" for prefix in literal_prefixes):
        return False

    for prefix in literal_prefixes:
        for directory in rule.directories:
            if _prefixes_overlap(prefix, directory):
                return False
    return True


def _literal_prefix(glob: str) -> str:
    out: list[str] = []
    for ch in glob.strip().lstrip("./"):
        if ch in {"*", "?", "["}:
            break
        out.append(ch)
    return "".join(out).strip("/")


def _prefixes_overlap(left: str, right: str) -> bool:
    left_n = left.replace("\\", "/").strip("/")
    right_n = right.replace("\\", "/").strip("/")
    if not left_n or not right_n:
        return False
    return (
        left_n == right_n
        or left_n.startswith(f"{right_n}/")
        or right_n.startswith(f"{left_n}/")
    )
