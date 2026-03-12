#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: emit_filelock_annotations.py <result-json-path>", file=sys.stderr)
        return 2

    result_path = Path(sys.argv[1])
    if not result_path.exists():
        print(f"result file not found: {result_path}", file=sys.stderr)
        return 1

    payload = json.loads(result_path.read_text(encoding="utf-8"))

    for item in payload.get("blocked_changes", []):
        path = item.get("path", "")
        action = item.get("action", "blocked")
        rule = item.get("matched_rule", "default_action")
        severity = item.get("risk_severity")
        severity_part = f", severity={severity}" if severity else ""
        print(
            f"::error file={path}::FileLock AI blocked change ({action}) via {rule}{severity_part}."
        )

    for item in payload.get("approval_required_changes", []):
        path = item.get("path", "")
        action = item.get("action", "manual_approval")
        rule = item.get("matched_rule", "default_action")
        severity = item.get("risk_severity")
        severity_part = f", severity={severity}" if severity else ""
        print(
            f"::warning file={path}::FileLock AI requires manual approval ({action}) via {rule}{severity_part}."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
