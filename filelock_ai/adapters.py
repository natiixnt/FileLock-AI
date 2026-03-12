from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from filelock_ai.paths import dedupe_repo_paths
from validators.plan_validator import extract_changed_files


class AdapterError(Exception):
    """Raised when adapter selection or parsing fails."""


@dataclass(frozen=True)
class NormalizedPlan:
    adapter: str
    changed_files: list[str]


class BasePlanAdapter:
    name: str = "base"

    def matches(self, payload: Any) -> bool:
        return False

    def extract(self, payload: Any) -> list[str]:
        raise NotImplementedError


class GenericJsonAdapter(BasePlanAdapter):
    name = "generic_json"

    def matches(self, payload: Any) -> bool:
        return isinstance(payload, (dict, list))

    def extract(self, payload: Any) -> list[str]:
        return extract_changed_files(payload)


class OpenAIResponsesAdapter(BasePlanAdapter):
    name = "openai_responses"

    def matches(self, payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        return any(key in payload for key in ["output", "response", "tool_calls"])

    def extract(self, payload: Any) -> list[str]:
        candidates = [path for path in extract_changed_files(payload) if not _looks_like_inline_json(path)]

        for obj in _iter_objects(payload):
            if not isinstance(obj, dict):
                continue

            # Common shape: tool/function call with JSON string arguments.
            for key in ["arguments", "input_json", "json"]:
                if key not in obj or not isinstance(obj[key], str):
                    continue
                parsed = _try_parse_json(obj[key])
                if parsed is not None:
                    candidates.extend(extract_changed_files(parsed))

        return dedupe_repo_paths(candidates)


class AnthropicMessagesAdapter(BasePlanAdapter):
    name = "anthropic_messages"

    def matches(self, payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        if "anthropic_version" in payload:
            return True
        if "messages" in payload and isinstance(payload["messages"], list):
            return True
        if "content" in payload and isinstance(payload["content"], list):
            return True
        return False

    def extract(self, payload: Any) -> list[str]:
        candidates = extract_changed_files(payload)

        for obj in _iter_objects(payload):
            if not isinstance(obj, dict):
                continue

            # Common block: {"type": "tool_use", "input": {...}}
            if obj.get("type") == "tool_use" and "input" in obj:
                candidates.extend(extract_changed_files(obj["input"]))

        return dedupe_repo_paths(candidates)


_ADAPTERS: dict[str, BasePlanAdapter] = {
    GenericJsonAdapter.name: GenericJsonAdapter(),
    OpenAIResponsesAdapter.name: OpenAIResponsesAdapter(),
    AnthropicMessagesAdapter.name: AnthropicMessagesAdapter(),
}

_AUTO_ORDER = [
    _ADAPTERS[AnthropicMessagesAdapter.name],
    _ADAPTERS[OpenAIResponsesAdapter.name],
    _ADAPTERS[GenericJsonAdapter.name],
]


def available_adapters() -> tuple[str, ...]:
    return tuple(["auto", *_ADAPTERS.keys()])


def normalize_plan(payload: Any, adapter_name: str = "auto") -> NormalizedPlan:
    selected_name = adapter_name.strip().lower()
    if selected_name == "auto":
        adapter = _detect_adapter(payload)
    else:
        adapter = _ADAPTERS.get(selected_name)
        if adapter is None:
            raise AdapterError(
                f"Unknown adapter '{adapter_name}'. Available adapters: {list(available_adapters())}"
            )

    changed_files = dedupe_repo_paths(adapter.extract(payload))
    return NormalizedPlan(adapter=adapter.name, changed_files=changed_files)


def _detect_adapter(payload: Any) -> BasePlanAdapter:
    for adapter in _AUTO_ORDER:
        if adapter.matches(payload):
            return adapter
    return _ADAPTERS[GenericJsonAdapter.name]


def _iter_objects(value: Any):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _iter_objects(nested)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_objects(item)


def _try_parse_json(value: str) -> Any | None:
    text = value.strip()
    if not text:
        return None
    if text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _looks_like_inline_json(value: str) -> bool:
    text = str(value).strip()
    return (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]"))
