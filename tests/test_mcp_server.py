from pathlib import Path

import pytest

from filelock_ai.engine import EvaluationContext
from filelock_ai.mcp_server import MCPServerError, evaluate_mcp_request
from filelock_ai.policy import load_policy


def _write_policy(path: Path, content: str) -> str:
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_mcp_request_with_changed_files(tmp_path: Path) -> None:
    policy_path = _write_policy(
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

    response = evaluate_mcp_request(
        policy,
        {"changed_files": ["src/app.py", "infra/main.tf"]},
        default_context=EvaluationContext(branch="main", environment="prod"),
    )

    assert response["ok"] is True
    assert response["summary"]["blocked"] == 1
    assert response["summary"]["allowed"] == 1
    assert response["context"]["branch"] == "main"


def test_mcp_request_with_plan_adapter(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
rules:
  - name: review-src
    action: manual_approval
    directory: ["src"]
""",
    )
    policy = load_policy(policy_path)

    response = evaluate_mcp_request(
        policy,
        {
            "adapter": "openai_responses",
            "plan": {
                "output": [
                    {
                        "type": "tool_call",
                        "arguments": '{"changed_files": ["src/app.py"]}',
                    }
                ]
            },
        },
    )

    assert response["adapter"] == "openai_responses"
    assert response["summary"]["approval_required"] == 1


def test_mcp_request_requires_valid_payload(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "policy.yaml",
        """
version: 1
default_action: allowed
rules: []
""",
    )
    policy = load_policy(policy_path)

    with pytest.raises(MCPServerError, match="must include one of"):
        evaluate_mcp_request(policy, {"foo": "bar"})
