from pathlib import Path

from filelock_ai.engine import evaluate_changes
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
