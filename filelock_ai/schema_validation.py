from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator


class SchemaValidationError(Exception):
    """Raised for fatal schema validation problems (I/O or parser errors)."""


@dataclass(frozen=True)
class SchemaIssue:
    message: str
    path: str
    schema_path: str

    def as_dict(self) -> dict[str, str]:
        return {
            "message": self.message,
            "path": self.path,
            "schema_path": self.schema_path,
        }


def validate_policy_against_schema(policy_path: str) -> tuple[Any, list[SchemaIssue]]:
    path = Path(policy_path)
    if not path.exists():
        raise SchemaValidationError(
            f"Policy file not found: {policy_path}. "
            "Hint: run 'filelock-ai init-policy --profile startup-app'."
        )

    try:
        policy_data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        line = getattr(getattr(exc, "problem_mark", None), "line", None)
        column = getattr(getattr(exc, "problem_mark", None), "column", None)
        location = f" at line {line + 1}, column {column + 1}" if line is not None and column is not None else ""
        raise SchemaValidationError(
            f"Invalid YAML in '{policy_path}'{location}. Hint: check indentation and ':' separators."
        ) from exc

    schema = _load_policy_schema()
    validator = Draft202012Validator(schema)
    sorted_errors = sorted(validator.iter_errors(policy_data), key=lambda err: list(err.path))

    issues: list[SchemaIssue] = []
    for err in sorted_errors:
        instance_path = "/".join(str(part) for part in err.path)
        schema_path = "/".join(str(part) for part in err.schema_path)
        issues.append(
            SchemaIssue(
                message=err.message,
                path=f"/{instance_path}" if instance_path else "/",
                schema_path=f"/{schema_path}" if schema_path else "/",
            )
        )

    return policy_data, issues


def _load_policy_schema() -> dict[str, Any]:
    schema_resource = resources.files("filelock_ai").joinpath("policy_schema/filelock-policy.schema.json")
    with resources.as_file(schema_resource) as schema_path:
        return json.loads(schema_path.read_text(encoding="utf-8"))
