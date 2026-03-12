import pytest

from filelock_ai.adapters import AdapterError, normalize_plan


@pytest.mark.parametrize(
    ("adapter_name", "payload", "expected"),
    [
        (
            "generic_json",
            {"changed_files": ["./src/app.py", "infra/main.tf"]},
            ["src/app.py", "infra/main.tf"],
        ),
        (
            "openai_responses",
            {
                "output": [
                    {
                        "type": "tool_call",
                        "arguments": '{"changed_files": ["src/api.py", "src/../infra/main.tf"]}',
                    }
                ]
            },
            ["src/api.py", "infra/main.tf"],
        ),
        (
            "anthropic_messages",
            {
                "messages": [
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "input": {"changed_files": ["apps/web/index.ts", "apps/web/index.ts"]},
                            }
                        ],
                    }
                ]
            },
            ["apps/web/index.ts"],
        ),
    ],
)
def test_adapter_contract_extracts_normalized_changed_files(adapter_name, payload, expected) -> None:
    normalized = normalize_plan(payload, adapter_name=adapter_name)

    assert normalized.adapter == adapter_name
    assert normalized.changed_files == expected


def test_adapter_auto_detection_prefers_openai() -> None:
    payload = {
        "output": [
            {
                "type": "tool_call",
                "arguments": '{"changed_files": ["src/main.py"]}',
            }
        ]
    }

    normalized = normalize_plan(payload, adapter_name="auto")
    assert normalized.adapter == "openai_responses"
    assert normalized.changed_files == ["src/main.py"]


def test_unknown_adapter_raises() -> None:
    with pytest.raises(AdapterError, match="Unknown adapter"):
        normalize_plan({"changed_files": ["src/main.py"]}, adapter_name="unknown")
