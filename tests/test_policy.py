from pathlib import Path

import pytest

from filelock_ai.policy import PolicyError, load_policy


def test_load_policy_requires_version(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
default_action: allowed
rules: []
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="Missing required policy 'version'"):
        load_policy(str(policy_path))


def test_load_policy_rejects_unsupported_version(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 2
default_action: allowed
rules: []
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="Unsupported policy version"):
        load_policy(str(policy_path))


def test_load_policy_accepts_version_one(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: allowed
rules: []
""",
        encoding="utf-8",
    )

    policy = load_policy(str(policy_path))
    assert policy.version == 1
