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


def test_load_policy_rejects_unknown_tag_pack(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: allowed
tag_packs: [does-not-exist]
rules: []
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="Unknown tag pack"):
        load_policy(str(policy_path))


def test_load_policy_detects_include_cycle(tmp_path: Path) -> None:
    a = tmp_path / "a.yaml"
    b = tmp_path / "b.yaml"
    a.write_text(
        """
version: 1
default_action: allowed
include: ["b.yaml"]
rules: []
""",
        encoding="utf-8",
    )
    b.write_text(
        """
version: 1
default_action: allowed
include: ["a.yaml"]
rules: []
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="include cycle"):
        load_policy(str(a))


def test_load_policy_rejects_invalid_severity_gate_order(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: allowed
severity_gates:
  approval_at_or_above: high
  block_at_or_above: medium
rules: []
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="block_at_or_above cannot be lower"):
        load_policy(str(policy_path))
