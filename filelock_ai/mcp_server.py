from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from filelock_ai.adapters import AdapterError, normalize_plan
from filelock_ai.engine import EvaluationContext, evaluate_changes
from filelock_ai.paths import dedupe_repo_paths
from filelock_ai.policy import Policy


class MCPServerError(Exception):
    """Raised when request payload is invalid."""


def evaluate_mcp_request(
    policy: Policy,
    payload: dict[str, Any],
    *,
    default_context: EvaluationContext | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise MCPServerError("Request body must be a JSON object.")

    context = default_context or EvaluationContext()
    branch = payload.get("branch", context.branch)
    environment = payload.get("environment", context.environment)
    request_context = EvaluationContext(
        branch=str(branch) if branch is not None else None,
        environment=str(environment) if environment is not None else None,
    )

    adapter_used = "manual"
    if "changed_files" in payload:
        changed_files_raw = payload["changed_files"]
        if not isinstance(changed_files_raw, list):
            raise MCPServerError("'changed_files' must be a list of paths.")
        changed_files = dedupe_repo_paths([str(item) for item in changed_files_raw])
    elif "plan" in payload:
        adapter_name = str(payload.get("adapter", "auto"))
        try:
            normalized = normalize_plan(payload["plan"], adapter_name)
        except AdapterError as exc:
            raise MCPServerError(str(exc)) from exc
        changed_files = normalized.changed_files
        adapter_used = normalized.adapter
    elif "path" in payload:
        changed_files = dedupe_repo_paths([str(payload["path"])])
    else:
        raise MCPServerError("Request must include one of: changed_files, plan, or path.")

    report = evaluate_changes(policy, changed_files, context=request_context)
    report_dict = report.as_dict()

    return {
        "ok": True,
        "adapter": adapter_used,
        "context": {
            "branch": request_context.branch,
            "environment": request_context.environment,
        },
        "summary": {
            "allowed": len(report.allowed),
            "blocked": len(report.blocked),
            "approval_required": len(report.approval_required),
            "exit_code": report.exit_code(),
        },
        "decisions": report_dict,
    }


def run_mcp_server(
    *,
    policy: Policy,
    host: str,
    port: int,
    default_context: EvaluationContext | None = None,
) -> None:
    context = default_context or EvaluationContext()

    class _Handler(BaseHTTPRequestHandler):
        def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "service": "filelock-ai-mcp",
                    },
                )
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in {"/check", "/v1/check"}:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(content_length)
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid JSON body"})
                return

            try:
                response = evaluate_mcp_request(policy, payload, default_context=context)
            except MCPServerError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return

            self._send_json(HTTPStatus.OK, response)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"FileLock AI MCP server listening on http://{host}:{port}")
    print("Endpoints: GET /health, POST /check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
