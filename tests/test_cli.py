import json
from pathlib import Path

from filelock_ai.cli import main


def test_init_policy_creates_file(tmp_path: Path) -> None:
    output = tmp_path / "filelock-policy.yaml"

    code = main(["init-policy", "--profile", "startup-app", "--output", str(output)])

    assert code == 0
    assert output.exists()
    assert "default_action" in output.read_text(encoding="utf-8")


def test_check_command_blocks_secret_file(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: allowed
tag_definitions:
  secrets: ["**/*.pem"]
rules:
  - name: block-secrets
    action: blocked
    tags: ["secrets"]
""",
        encoding="utf-8",
    )

    plan_path = tmp_path / "plan.json"
    plan_path.write_text('{"changed_files": ["src/app.py", "keys/prod.pem"]}', encoding="utf-8")

    code = main([
        "check",
        str(plan_path),
        "--policy",
        str(policy_path),
        "--format",
        "json",
    ])

    assert code == 1


def test_check_fail_on_blocked_allows_approval_only(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: manual_approval
rules: []
""",
        encoding="utf-8",
    )

    plan_path = tmp_path / "plan.json"
    plan_path.write_text('{"changed_files": ["src/app.py"]}', encoding="utf-8")

    code = main([
        "check",
        str(plan_path),
        "--policy",
        str(policy_path),
        "--fail-on",
        "blocked",
    ])

    assert code == 0


def test_check_supports_custom_exit_codes(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: allowed
rules:
  - name: block-infra
    action: blocked
    directory: ["infra"]
""",
        encoding="utf-8",
    )

    plan_path = tmp_path / "plan.json"
    plan_path.write_text('{"changed_files": ["infra/main.tf"]}', encoding="utf-8")

    code = main([
        "check",
        str(plan_path),
        "--policy",
        str(policy_path),
        "--exit-code-blocked",
        "42",
    ])

    assert code == 42


def test_explain_command_outputs_json(tmp_path: Path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: allowed
tag_definitions:
  infra: ["infra/**"]
rules:
  - name: protect-infra
    action: readonly
    tags: ["infra"]
""",
        encoding="utf-8",
    )

    code = main([
        "explain",
        "infra/main.tf",
        "--policy",
        str(policy_path),
        "--format",
        "json",
    ])
    captured = capsys.readouterr()

    assert code == 0
    assert '"path": "infra/main.tf"' in captured.out
    assert '"action": "readonly"' in captured.out
    assert '"matched_rule": "protect-infra"' in captured.out


def test_migrate_policy_adds_version(tmp_path: Path) -> None:
    input_policy = tmp_path / "legacy.yaml"
    output_policy = tmp_path / "migrated.yaml"
    input_policy.write_text(
        """
default_action: allowed
rules: []
""",
        encoding="utf-8",
    )

    code = main([
        "migrate-policy",
        str(input_policy),
        "--output",
        str(output_policy),
    ])

    assert code == 0
    assert "version: 1" in output_policy.read_text(encoding="utf-8")


def test_validate_policy_command_accepts_valid_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: manual_approval
rules: []
""",
        encoding="utf-8",
    )

    code = main([
        "validate-policy",
        str(policy_path),
        "--format",
        "json",
    ])

    assert code == 0


def test_validate_policy_command_rejects_schema_errors(tmp_path: Path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: maybe
rules:
  - action: blocked
""",
        encoding="utf-8",
    )

    code = main([
        "validate-policy",
        str(policy_path),
        "--format",
        "json",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 1
    assert payload["valid"] is False
    assert payload["schema_issues"]
    assert payload["semantic_error"] is None


def test_lint_policy_detects_warnings_and_strict_fails(tmp_path: Path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: manual_approval
tag_definitions:
  infra: ["infra/**"]
rules:
  - name: duplicate
    action: allowed
    tags: ["unknown_tag"]
  - name: duplicate
    action: blocked
  - name: unreachable-allowed
    action: allowed
    directory: ["src"]
""",
        encoding="utf-8",
    )

    code = main([
        "lint-policy",
        "--policy",
        str(policy_path),
        "--strict",
        "--format",
        "json",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 1
    assert payload["warning_count"] >= 3
    assert any(item["code"] == "DUPLICATE_RULE_NAME" for item in payload["warnings"])
    assert any(item["code"] == "CONTRADICTORY_SELECTORS" for item in payload["warnings"])
    assert any(item["code"] == "UNREACHABLE_RULE" for item in payload["warnings"])


def test_lint_policy_no_warnings_passes(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: manual_approval
tag_definitions:
  infra: ["infra/**"]
rules:
  - name: protect-infra
    action: readonly
    tags: ["infra"]
  - name: allow-src
    action: allowed
    directory: ["src"]
""",
        encoding="utf-8",
    )

    code = main([
        "lint-policy",
        "--policy",
        str(policy_path),
        "--strict",
    ])
    assert code == 0


def test_check_markdown_output_format(tmp_path: Path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: allowed
rules:
  - name: block-infra
    action: blocked
    directory: ["infra"]
""",
        encoding="utf-8",
    )

    plan_path = tmp_path / "plan.json"
    plan_path.write_text('{"changed_files": ["src/app.py", "infra/main.tf"]}', encoding="utf-8")

    code = main([
        "check",
        str(plan_path),
        "--policy",
        str(policy_path),
        "--format",
        "markdown",
    ])
    captured = capsys.readouterr()

    assert code == 1
    assert "| Category | Path | Action | Matched Rule | Tags |" in captured.out
    assert "`infra/main.tf`" in captured.out


def test_check_sarif_output_format(tmp_path: Path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: manual_approval
rules:
  - name: block-infra
    action: blocked
    directory: ["infra"]
""",
        encoding="utf-8",
    )

    plan_path = tmp_path / "plan.json"
    plan_path.write_text('{"changed_files": ["infra/main.tf", "src/app.py"]}', encoding="utf-8")

    code = main([
        "check",
        str(plan_path),
        "--policy",
        str(policy_path),
        "--format",
        "sarif",
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 1
    assert payload["version"] == "2.1.0"
    results = payload["runs"][0]["results"]
    assert any(result["ruleId"] == "FILELOCK_BLOCKED" for result in results)
    assert any(result["ruleId"] == "FILELOCK_APPROVAL_REQUIRED" for result in results)


def test_check_invalid_policy_error_has_hint(tmp_path: Path, capsys) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: blocked
rules:
  - name: broken
    action: allowed
    directory: ["src"
""",
        encoding="utf-8",
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text('{"changed_files": ["src/app.py"]}', encoding="utf-8")

    code = main([
        "check",
        str(plan_path),
        "--policy",
        str(policy_path),
    ])
    captured = capsys.readouterr()

    assert code == 1
    assert "line" in captured.err
    assert "Hint:" in captured.err
