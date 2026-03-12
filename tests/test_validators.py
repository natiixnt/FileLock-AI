from pathlib import Path

import pytest

from validators.diff_validator import load_changed_files
from validators.plan_validator import PlanValidationError, extract_changed_files, load_plan_json


def test_extract_changed_files_from_plan_json(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        """
{
  "summary": "touch files",
  "changes": [
    {"file": "src/app.py"},
    {"path": "infra/main.tf"}
  ],
  "changed_files": ["docs/readme.md"]
}
""",
        encoding="utf-8",
    )

    plan = load_plan_json(str(plan_path))
    files = extract_changed_files(plan)

    assert files == ["docs/readme.md", "src/app.py", "infra/main.tf"]


def test_load_changed_files_from_diff_text(tmp_path: Path) -> None:
    diff_path = tmp_path / "diff.txt"
    diff_path.write_text(
        """
M\tsrc/main.py
A\tinfra/main.tf
diff --git a/docs/old.md b/docs/new.md
""",
        encoding="utf-8",
    )

    files = load_changed_files(str(diff_path))
    assert files == ["src/main.py", "infra/main.tf", "docs/new.md"]


def test_plan_json_error_includes_line_and_hint(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("{\"changed_files\": [\"src/app.py\",]}", encoding="utf-8")

    with pytest.raises(PlanValidationError, match="line"):
        load_plan_json(str(plan_path))


def test_extract_changed_files_normalizes_paths(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        """
    {
      "changed_files": [
        "./src//api/../app.py",
        "src/app.py",
        "C:\\\\infra\\\\main.tf",
        "../docs/readme.md"
      ]
    }
""",
        encoding="utf-8",
    )

    plan = load_plan_json(str(plan_path))
    files = extract_changed_files(plan)

    assert files == ["src/app.py", "infra/main.tf", "docs/readme.md"]


def test_diff_validator_normalizes_and_handles_diff_prefixes(tmp_path: Path) -> None:
    diff_path = tmp_path / "diff.txt"
    diff_path.write_text(
        """
M\t./src//api/../app.py
A\tb/infra/./main.tf
diff --git a/apps/foo/../bar.ts b/apps/bar.ts
a/custom/path.txt
""",
        encoding="utf-8",
    )

    files = load_changed_files(str(diff_path))
    assert files == ["src/app.py", "infra/main.tf", "apps/bar.ts", "a/custom/path.txt"]
