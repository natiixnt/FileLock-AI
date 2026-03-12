from pathlib import Path

import pytest

from filelock_ai.engine import EvaluationContext, evaluate_changes
from filelock_ai.policy import load_policy


def write_policy(path: Path, content: str) -> str:
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_blocked_beats_allowed(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: manual_approval
rules:
  - name: allow-src
    action: allowed
    directory: ["src"]
  - name: block-private-keys
    action: blocked
    file_extension: [".pem"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["src/main.py", "src/dev.pem"])

    assert [item.path for item in report.allowed] == ["src/main.py"]
    assert [item.path for item in report.blocked] == ["src/dev.pem"]
    assert not report.approval_required


def test_readonly_counts_as_blocked(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
rules:
  - name: readonly-infra
    action: readonly
    directory: ["infra"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["infra/main.tf", "src/app.py"])

    assert [item.path for item in report.blocked] == ["infra/main.tf"]
    assert [item.path for item in report.allowed] == ["src/app.py"]


def test_tag_matching(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
tag_definitions:
  migrations:
    - "**/migrations/**"
rules:
  - name: migrations-review
    action: manual_approval
    tags: ["migrations"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["services/orders/migrations/001_init.sql", "src/app.py"])

    assert [item.path for item in report.approval_required] == ["services/orders/migrations/001_init.sql"]
    assert [item.path for item in report.allowed] == ["src/app.py"]


def test_default_action_applies_when_no_rule_matches(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: manual_approval
rules:
  - name: allow-tests
    action: allowed
    directory: ["tests"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["scripts/release.sh"])

    assert not report.allowed
    assert [item.path for item in report.approval_required] == ["scripts/release.sh"]


def test_path_normalization_is_canonical_in_engine(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
rules:
  - name: block-infra
    action: blocked
    directory: ["infra"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(
        policy,
        [
            "./src//api/../app.py",
            "src/app.py",
            "C:\\\\infra\\\\prod.tf",
            "infra/./prod.tf",
        ],
    )

    assert [item.path for item in report.allowed] == ["src/app.py"]
    assert [item.path for item in report.blocked] == ["infra/prod.tf"]


def test_negated_glob_blocks_except_explicit_allow_path(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
rules:
  - name: block-src-except-public
    action: blocked
    path_glob: ["src/**", "!src/public/**"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["src/private/app.py", "src/public/app.py"])

    assert [item.path for item in report.blocked] == ["src/private/app.py"]
    assert [item.path for item in report.allowed] == ["src/public/app.py"]


def test_branch_and_environment_scoped_rule(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
rules:
  - name: review-main-prod
    action: manual_approval
    directory: ["src"]
    branch: ["main"]
    environment: ["prod*"]
""",
    )

    policy = load_policy(policy_path)
    prod_context = EvaluationContext(branch="main", environment="production")
    dev_context = EvaluationContext(branch="feature/auth", environment="dev")

    prod_report = evaluate_changes(policy, ["src/app.py"], context=prod_context)
    dev_report = evaluate_changes(policy, ["src/app.py"], context=dev_context)

    assert [item.path for item in prod_report.approval_required] == ["src/app.py"]
    assert [item.path for item in dev_report.allowed] == ["src/app.py"]


def test_case_sensitive_mode_affects_directory_matching(tmp_path: Path) -> None:
    sensitive_path = write_policy(
        tmp_path / "sensitive.yaml",
        """
version: 1
case_sensitive: true
default_action: allowed
rules:
  - name: lock-src-capitalized
    action: blocked
    directory: ["Src"]
""",
    )
    insensitive_path = write_policy(
        tmp_path / "insensitive.yaml",
        """
version: 1
case_sensitive: false
default_action: allowed
rules:
  - name: lock-src-capitalized
    action: blocked
    directory: ["Src"]
""",
    )

    sensitive_policy = load_policy(sensitive_path)
    insensitive_policy = load_policy(insensitive_path)

    sensitive_report = evaluate_changes(sensitive_policy, ["src/app.py", "Src/app.py"])
    insensitive_report = evaluate_changes(insensitive_policy, ["src/app.py", "Src/app.py"])

    assert [item.path for item in sensitive_report.blocked] == ["Src/app.py"]
    assert [item.path for item in insensitive_report.blocked] == ["src/app.py", "Src/app.py"]


def test_symlink_guard_blocks_changes_when_symlink_policy_blocked(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "file.txt").write_text("x", encoding="utf-8")
    try:
        (tmp_path / "linked").symlink_to(tmp_path / "real")
    except OSError:
        pytest.skip("Symlinks are not available in this environment")

    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
symlink_policy: blocked
default_action: allowed
rules: []
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["linked/file.txt"])

    assert [item.path for item in report.blocked] == ["linked/file.txt"]
    assert report.blocked[0].matched_rule == "symlink-guard:linked"


def test_include_and_rule_group_expansion(tmp_path: Path) -> None:
    base = tmp_path / "base.yaml"
    base.write_text(
        """
version: 1
default_action: allowed
rule_groups:
  lock_infra:
    - name: lock-infra
      action: blocked
      directory: ["infra"]
""",
        encoding="utf-8",
    )

    main = tmp_path / "main.yaml"
    main.write_text(
        """
include: ["base.yaml"]
version: 1
default_action: allowed
rules:
  - use_group: lock_infra
    name_prefix: "base:"
  - name: allow-src
    action: allowed
    directory: ["src"]
""",
        encoding="utf-8",
    )

    policy = load_policy(str(main))
    report = evaluate_changes(policy, ["infra/main.tf", "src/app.py"])

    assert any(rule.name == "base:lock-infra" for rule in policy.rules)
    assert [item.path for item in report.blocked] == ["infra/main.tf"]
    assert [item.path for item in report.allowed] == ["src/app.py"]


def test_builtin_tag_pack_applies_default_tags(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
tag_packs: [baseline]
rules:
  - name: block-secrets
    action: blocked
    tags: ["secrets"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["config/.env.local"])

    assert [item.path for item in report.blocked] == ["config/.env.local"]
    assert "secrets" in report.blocked[0].tags


def test_tag_severity_gates_escalate_action(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
tag_definitions:
  secrets: ["secrets/**"]
  infra: ["infra/**"]
tag_severity:
  secrets: critical
  infra: high
severity_gates:
  approval_at_or_above: medium
  block_at_or_above: critical
rules: []
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["infra/main.tf", "secrets/prod.key"])

    assert [item.path for item in report.approval_required] == ["infra/main.tf"]
    assert [item.path for item in report.blocked] == ["secrets/prod.key"]
    assert report.blocked[0].risk_severity == "critical"
    assert report.approval_required[0].risk_severity == "high"


def test_codeowners_tags_can_drive_rules(tmp_path: Path) -> None:
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text(
        """
/payments/** @org/payments-team
""",
        encoding="utf-8",
    )
    policy_path = write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
codeowners:
  enabled: true
  file: .github/CODEOWNERS
  tag_prefix: owner_
rules:
  - name: owner-review
    action: manual_approval
    tags: ["owner_org_payments_team"]
""",
    )

    policy = load_policy(policy_path)
    report = evaluate_changes(policy, ["payments/api/routes.py"])

    assert [item.path for item in report.approval_required] == ["payments/api/routes.py"]
    assert "owner_org_payments_team" in report.approval_required[0].tags
