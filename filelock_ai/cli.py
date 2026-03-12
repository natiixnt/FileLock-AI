from __future__ import annotations

import argparse
from datetime import UTC, datetime
from importlib import resources
import json
import shutil
import sys
from pathlib import Path

import yaml

from filelock_ai.engine import EvaluationContext, EvaluationReport, evaluate_changes, evaluate_path
from filelock_ai.linting import LintWarning, lint_policy
from filelock_ai.policy import PolicyError, load_policy
from filelock_ai.schema_validation import SchemaValidationError, validate_policy_against_schema
from filelock_ai.tag_packs import available_tag_packs
from validators.diff_validator import DiffValidationError, load_changed_files
from validators.plan_validator import PlanValidationError, extract_changed_files, load_plan_json

_POLICY_PROFILES = {
    "startup-app": "startup_app.yaml",
    "enterprise-backend": "enterprise_backend.yaml",
    "monorepo": "monorepo.yaml",
}
_FAIL_ON_CHOICES = ("blocked_or_approval", "blocked", "never")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        return run_check(args)
    if args.command == "validate":
        return run_validate(args)
    if args.command == "validate-policy":
        return run_validate_policy(args)
    if args.command == "lint-policy":
        return run_lint_policy(args)
    if args.command == "explain":
        return run_explain(args)
    if args.command == "init-policy":
        return run_init_policy(args)
    if args.command == "migrate-policy":
        return run_migrate_policy(args)

    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filelock-ai",
        description="Policy-first file access checks for coding agent plans and diffs.",
    )

    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser("check", help="Check changed files from a plan JSON file.")
    check_parser.add_argument("plan", help="Path to plan JSON file.")
    check_parser.add_argument(
        "--policy",
        default="filelock-policy.yaml",
        help="Path to YAML policy file. Default: filelock-policy.yaml",
    )
    check_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown", "sarif"],
        default="text",
        help="Output format. Default: text",
    )
    _add_context_args(check_parser)
    _add_exit_behavior_args(check_parser)

    validate_parser = subparsers.add_parser(
        "validate", help="Validate changed files from a diff or file list text file."
    )
    validate_parser.add_argument("diff", help="Path to diff text or changed-file list.")
    validate_parser.add_argument(
        "--policy",
        default="filelock-policy.yaml",
        help="Path to YAML policy file. Default: filelock-policy.yaml",
    )
    validate_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown", "sarif"],
        default="text",
        help="Output format. Default: text",
    )
    _add_context_args(validate_parser)
    _add_exit_behavior_args(validate_parser)

    validate_policy_parser = subparsers.add_parser(
        "validate-policy", help="Validate policy file against JSON schema and engine semantics."
    )
    validate_policy_parser.add_argument(
        "policy",
        nargs="?",
        default="filelock-policy.yaml",
        help="Path to YAML policy file. Default: filelock-policy.yaml",
    )
    validate_policy_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format. Default: text",
    )

    lint_parser = subparsers.add_parser("lint-policy", help="Lint policy quality and consistency.")
    lint_parser.add_argument(
        "--policy",
        default="filelock-policy.yaml",
        help="Path to YAML policy file. Default: filelock-policy.yaml",
    )
    lint_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format. Default: text",
    )
    lint_parser.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero exit code when warnings are found.",
    )

    explain_parser = subparsers.add_parser(
        "explain", help="Explain how a single file path is classified by the policy."
    )
    explain_parser.add_argument("path", help="File path to evaluate.")
    explain_parser.add_argument(
        "--policy",
        default="filelock-policy.yaml",
        help="Path to YAML policy file. Default: filelock-policy.yaml",
    )
    explain_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format. Default: text",
    )
    _add_context_args(explain_parser)

    init_parser = subparsers.add_parser("init-policy", help="Create a starter policy file.")
    init_parser.add_argument(
        "--profile",
        choices=sorted(_POLICY_PROFILES.keys()),
        default="startup-app",
        help="Starter policy profile to use.",
    )
    init_parser.add_argument(
        "--output",
        default="filelock-policy.yaml",
        help="Output policy file path. Default: filelock-policy.yaml",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it exists.",
    )
    init_parser.add_argument(
        "--with-tag-pack",
        dest="tag_packs",
        action="append",
        choices=available_tag_packs(),
        help="Optional built-in tag pack to enable (can be passed multiple times).",
    )

    migrate_parser = subparsers.add_parser(
        "migrate-policy", help="Migrate a legacy policy file to the latest supported version."
    )
    migrate_parser.add_argument("input", help="Path to input policy YAML.")
    migrate_parser.add_argument(
        "--output",
        help="Path to output migrated policy. If omitted, writes to '<input>.v1.yaml'.",
    )
    migrate_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it exists.",
    )

    return parser


def _add_exit_behavior_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="blocked_or_approval",
        help="Fail condition for exit code. Default: blocked_or_approval",
    )
    parser.add_argument(
        "--exit-code-ok",
        type=int,
        default=0,
        help="Exit code when check is considered successful. Default: 0",
    )
    parser.add_argument(
        "--exit-code-blocked",
        type=int,
        default=1,
        help="Exit code when blocked changes are present and fail-on triggers. Default: 1",
    )
    parser.add_argument(
        "--exit-code-approval",
        type=int,
        default=2,
        help="Exit code when approval-required changes are present and fail-on triggers. Default: 2",
    )


def _add_context_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--branch",
        help="Optional git branch context for branch-scoped policy rules.",
    )
    parser.add_argument(
        "--environment",
        help="Optional environment context for environment-scoped policy rules.",
    )


def run_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
        plan = load_plan_json(args.plan)
        changed_files = extract_changed_files(plan)
    except (PolicyError, PlanValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    context = _build_context(args)
    report = evaluate_changes(policy, changed_files, context=context)
    _render_report(report, args.format)
    return _resolve_exit_code(
        report,
        fail_on=args.fail_on,
        exit_code_ok=args.exit_code_ok,
        exit_code_blocked=args.exit_code_blocked,
        exit_code_approval=args.exit_code_approval,
    )


def run_validate(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
        changed_files = load_changed_files(args.diff)
    except (PolicyError, DiffValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    context = _build_context(args)
    report = evaluate_changes(policy, changed_files, context=context)
    _render_report(report, args.format)
    return _resolve_exit_code(
        report,
        fail_on=args.fail_on,
        exit_code_ok=args.exit_code_ok,
        exit_code_blocked=args.exit_code_blocked,
        exit_code_approval=args.exit_code_approval,
    )


def run_validate_policy(args: argparse.Namespace) -> int:
    try:
        _, schema_issues = validate_policy_against_schema(args.policy)
    except SchemaValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    semantic_error: str | None = None
    if not schema_issues:
        try:
            load_policy(args.policy)
        except PolicyError as exc:
            semantic_error = str(exc)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "policy": args.policy,
                    "valid": not schema_issues and semantic_error is None,
                    "schema_issues": [issue.as_dict() for issue in schema_issues],
                    "semantic_error": semantic_error,
                },
                indent=2,
            )
        )
    else:
        print(f"Policy: {args.policy}")
        if schema_issues:
            print(f"Schema issues ({len(schema_issues)}):")
            for issue in schema_issues:
                print(f"  - path={issue.path} schema={issue.schema_path}: {issue.message}")
        else:
            print("Schema issues (0):")
            print("  - none")

        if semantic_error:
            print("Semantic validation:")
            print(f"  - error: {semantic_error}")
        else:
            print("Semantic validation:")
            print("  - ok")

    return 0 if not schema_issues and semantic_error is None else 1


def run_lint_policy(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    warnings = lint_policy(policy)
    _render_lint_warnings(warnings, output_format=args.format, policy_path=args.policy)
    if warnings and args.strict:
        return 1
    return 0


def run_explain(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    context = _build_context(args)
    decision = evaluate_path(policy, args.path, context=context)
    payload = {
        "path": decision.path,
        "action": decision.action,
        "category": decision.category,
        "matched_rule": decision.matched_rule,
        "tags": list(decision.tags),
        "risk_severity": decision.risk_severity,
        "default_action": policy.default_action,
        "used_default": decision.matched_rule is None,
        "branch": context.branch,
        "environment": context.environment,
    }

    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"Path: {payload['path']}")
        print(f"Action: {payload['action']} ({payload['category']})")
        print(f"Matched Rule: {payload['matched_rule'] or 'none (default policy action)'}")
        print(f"Tags: {','.join(payload['tags']) if payload['tags'] else 'none'}")
        print(f"Default Action: {payload['default_action']}")

    return 0


def run_init_policy(args: argparse.Namespace) -> int:
    profile_file = _POLICY_PROFILES[args.profile]
    target = Path(args.output)

    if target.exists() and not args.force:
        print(f"error: output file already exists: {target} (use --force to overwrite)", file=sys.stderr)
        return 1

    template = resources.files("filelock_ai").joinpath("policy_templates").joinpath(profile_file)

    target.parent.mkdir(parents=True, exist_ok=True)
    with resources.as_file(template) as source:
        shutil.copyfile(source, target)

    if args.tag_packs:
        try:
            raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            print(f"error: generated template YAML is invalid: {exc}", file=sys.stderr)
            return 1
        if not isinstance(raw, dict):
            print("error: generated template is not a policy object", file=sys.stderr)
            return 1

        existing = raw.get("tag_packs", [])
        if isinstance(existing, str):
            existing_packs = [existing]
        elif isinstance(existing, list):
            existing_packs = [str(item) for item in existing]
        else:
            existing_packs = []

        merged = _dedupe_items([*existing_packs, *args.tag_packs])
        raw["tag_packs"] = merged
        target.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    print(f"Created policy from '{args.profile}' profile: {target}")
    return 0


def run_migrate_policy(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"error: input policy file not found: {input_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else input_path.with_suffix(".v1.yaml")
    if output_path.exists() and not args.force:
        print(f"error: output file already exists: {output_path} (use --force to overwrite)", file=sys.stderr)
        return 1

    try:
        raw = yaml.safe_load(input_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        print(f"error: invalid YAML in '{input_path}': {exc}", file=sys.stderr)
        return 1

    if not isinstance(raw, dict):
        print("error: policy must be a YAML object at top level", file=sys.stderr)
        return 1

    current_version = raw.get("version")
    if current_version in (None, ""):
        raw["version"] = 1
    else:
        try:
            version_int = int(current_version)
        except (TypeError, ValueError):
            print(f"error: invalid policy version '{current_version}'", file=sys.stderr)
            return 1
        if version_int != 1:
            print(
                f"error: unsupported policy version '{version_int}'. "
                "This scaffold currently supports migration to v1 only.",
                file=sys.stderr,
            )
            return 1
        raw["version"] = 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    print(f"Migrated policy to version 1: {output_path}")
    return 0


def _render_report(report: EvaluationReport, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(report.as_dict(), indent=2))
        return
    if output_format == "markdown":
        print(_report_to_markdown(report))
        return
    if output_format == "sarif":
        print(json.dumps(_report_to_sarif(report), indent=2))
        return

    _print_section("Allowed Changes", report.allowed)
    _print_section("Blocked Changes", report.blocked)
    _print_section("Approval-Required Changes", report.approval_required)


def _print_section(title: str, entries: tuple) -> None:
    print(f"{title} ({len(entries)}):")
    if not entries:
        print("  - none")
        return

    for entry in entries:
        rule = f" [{entry.matched_rule}]" if entry.matched_rule else ""
        tags = f" tags={','.join(entry.tags)}" if entry.tags else ""
        severity = f" severity={entry.risk_severity}" if entry.risk_severity else ""
        print(f"  - {entry.path}{rule}{tags}{severity}")


def _render_lint_warnings(
    warnings: list[LintWarning],
    *,
    output_format: str,
    policy_path: str,
) -> None:
    if output_format == "json":
        print(
            json.dumps(
                {
                    "policy": policy_path,
                    "warning_count": len(warnings),
                    "warnings": [warning.as_dict() for warning in warnings],
                },
                indent=2,
            )
        )
        return

    print(f"Policy Lint Warnings ({len(warnings)}):")
    if not warnings:
        print("  - none")
        return

    for warning in warnings:
        location = ""
        if warning.rule_index is not None:
            location = f" rule#{warning.rule_index}"
        print(f"  - [{warning.code}]{location}: {warning.message}")


def _report_to_markdown(report: EvaluationReport) -> str:
    lines = [
        "| Category | Path | Action | Matched Rule | Tags | Severity |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    def add_rows(category: str, entries: tuple) -> None:
        for entry in entries:
            lines.append(
                f"| {category} | `{entry.path}` | `{entry.action}` | "
                f"`{entry.matched_rule or '-'}` | `{','.join(entry.tags) if entry.tags else '-'}` | "
                f"`{entry.risk_severity or '-'}` |"
            )

    add_rows("allowed", report.allowed)
    add_rows("blocked", report.blocked)
    add_rows("approval_required", report.approval_required)

    if len(lines) == 2:
        lines.append("| none | - | - | - | - | - |")
    return "\n".join(lines)


def _report_to_sarif(report: EvaluationReport) -> dict[str, object]:
    rules = [
        {
            "id": "FILELOCK_BLOCKED",
            "shortDescription": {"text": "Blocked file modification"},
            "help": {"text": "This file path is blocked by policy and cannot be modified."},
        },
        {
            "id": "FILELOCK_APPROVAL_REQUIRED",
            "shortDescription": {"text": "Manual approval required"},
            "help": {"text": "This file path requires manual approval before modification."},
        },
    ]

    results: list[dict[str, object]] = []
    for decision in report.blocked:
        results.append(
            _sarif_result(
                rule_id="FILELOCK_BLOCKED",
                level="error",
                decision_path=decision.path,
                action=decision.action,
                matched_rule=decision.matched_rule,
                tags=decision.tags,
                risk_severity=decision.risk_severity,
            )
        )
    for decision in report.approval_required:
        results.append(
            _sarif_result(
                rule_id="FILELOCK_APPROVAL_REQUIRED",
                level="warning",
                decision_path=decision.path,
                action=decision.action,
                matched_rule=decision.matched_rule,
                tags=decision.tags,
                risk_severity=decision.risk_severity,
            )
        )

    artifact_uris = sorted({d.path for d in report.blocked} | {d.path for d in report.approval_required})
    artifacts = [{"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}} for uri in artifact_uris]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FileLock AI",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(UTC).isoformat(),
                    }
                ],
                "results": results,
                "artifacts": artifacts,
            }
        ],
    }


def _sarif_result(
    *,
    rule_id: str,
    level: str,
    decision_path: str,
    action: str,
    matched_rule: str | None,
    tags: tuple[str, ...],
    risk_severity: str | None,
) -> dict[str, object]:
    rule_text = matched_rule or "default_action"
    tags_text = ",".join(tags) if tags else "none"
    severity_text = risk_severity or "none"
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": (
                f"Path '{decision_path}' classified as '{action}' "
                f"(matched_rule={rule_text}, tags={tags_text}, severity={severity_text})."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": decision_path,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        ],
    }


def _resolve_exit_code(
    report: EvaluationReport,
    *,
    fail_on: str,
    exit_code_ok: int,
    exit_code_blocked: int,
    exit_code_approval: int,
) -> int:
    if report.blocked:
        if fail_on in {"blocked_or_approval", "blocked"}:
            return exit_code_blocked
        return exit_code_ok

    if report.approval_required:
        if fail_on == "blocked_or_approval":
            return exit_code_approval
        return exit_code_ok

    return exit_code_ok


def _build_context(args: argparse.Namespace) -> EvaluationContext:
    branch = getattr(args, "branch", None)
    environment = getattr(args, "environment", None)
    return EvaluationContext(branch=branch, environment=environment)


def _dedupe_items(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = str(item).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
