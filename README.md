# FileLock AI

## One-line Hook
FileLock AI is a firewall for coding agents: it enforces file edit policy before changes land.

## Example Policy
```yaml
version: 1
default_action: manual_approval

tag_definitions:
  infra:
    - "infra/**"
    - ".github/workflows/**"
  migrations:
    - "**/migrations/**"
  secrets:
    - "**/.env*"
    - "**/*.pem"
    - "**/*.key"

rules:
  - name: block-secrets
    action: blocked
    tags: ["secrets"]

  - name: protect-infra
    action: readonly
    tags: ["infra"]

  - name: review-migrations
    action: manual_approval
    tags: ["migrations"]

  - name: allow-app-code
    action: allowed
    directory: ["src", "tests"]
    file_extension: [".py", ".ts"]
```

## Example Blocked Output
```text
$ filelock-ai check plan.json --policy filelock-policy.yaml
Allowed Changes (1):
  - src/api/routes.py [allow-app-code]
Blocked Changes (1):
  - infra/main.tf [protect-infra] tags=infra
Approval-Required Changes (1):
  - services/orders/migrations/002_add_index.sql [review-migrations] tags=migrations
```

## Why Teams Need Edit Restrictions
- Agent speed increases blast radius when a plan is wrong.
- Infra, auth, migration, and secret paths require stricter control than feature code.
- Prompt-only controls are not enforceable; policy checks are.
- A deterministic gate is required for CI and automated agent workflows.
- Edit policy creates a clear contract between repository owners and agents.

## Install
```bash
git clone <your-repo-url>
cd FileLock-AI
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quickstart
```bash
# 1) Generate a starter policy
filelock-ai init-policy --profile startup-app

# 2) Validate a plan JSON
filelock-ai check examples/plan.json --policy filelock-policy.yaml

# 3) Validate a diff or changed-file list
filelock-ai validate examples/diff.txt --policy filelock-policy.yaml

# 4) Explain one path decision
filelock-ai explain infra/main.tf --policy filelock-policy.yaml

# 5) Lint policy quality
filelock-ai lint-policy --policy filelock-policy.yaml --strict

# 6) Validate policy against JSON schema
filelock-ai validate-policy filelock-policy.yaml --format json

# 7) Pass branch/environment context
filelock-ai check examples/plan.json --policy filelock-policy.yaml --branch main --environment prod

# 8) Initialize with built-in risk tags
filelock-ai init-policy --profile startup-app --with-tag-pack baseline

# 9) Use explicit plan adapter
filelock-ai check plan.json --adapter openai_responses

# 10) Run MCP endpoint for pre-edit checks
filelock-ai mcp-server --policy filelock-policy.yaml --host 127.0.0.1 --port 8787
```

Exit codes:
- `0`: all changes allowed
- `1`: one or more blocked changes
- `2`: no blocked changes, but approval-required changes exist
- configurable via `--fail-on`, `--exit-code-ok`, `--exit-code-blocked`, `--exit-code-approval`
- report formats for `check`/`validate`: `text`, `json`, `markdown`, `sarif`

## Policy Syntax
Top-level keys:
- `version`: required policy version (`1`)
- `default_action`: fallback when no rule matches (`allowed`, `manual_approval`, `readonly`, `blocked`)
- `case_sensitive`: optional bool for case-sensitive path matching (default: `false`)
- `symlink_policy`: action when path traverses a symlink (`blocked` default)
- `include`: include one or many policy files (relative paths supported)
- `tag_definitions`: map of tag name to glob patterns
- `tag_packs`: optional built-in risk tag packs (currently: `baseline`)
- `tag_severity`: map `tag -> low|medium|high|critical`
- `severity_gates`: optional severity escalation gates
  - `approval_at_or_above`
  - `block_at_or_above`
- `codeowners`: optional CODEOWNERS-based tag mapping
  - `enabled`
  - `file`
  - `tag_prefix`
- `rule_groups`: reusable named groups of rules
- `rules`: ordered list of rules

Rule keys:
- `name`: display name in output
- `action`: one of `allowed`, `manual_approval`, `readonly`, `blocked`
- `path_glob`: path glob matcher(s)
- `file_extension`: extension matcher(s), e.g. `.py` or `py`
- `directory`: directory prefix matcher(s)
- `tags`: tag matcher(s) from `tag_definitions`
- `branch` / `branches`: optional branch pattern(s)
- `environment` / `environments` / `env`: optional environment pattern(s)

Rule group references inside `rules`:
- `use_group`
- `use_groups`
- `name_prefix`

Matching behavior:
- A rule matches only when all selectors present in that rule match (AND behavior).
- `path_glob` supports negation patterns with `!`, e.g. `["src/**", "!src/public/**"]`.
- If multiple rules match, the strictest action wins: `blocked` > `readonly` > `manual_approval` > `allowed`.
- If multiple matching rules have the same action level, the later rule in the file wins.

Input formats:
- `check`: plan JSON (supports adapter selection: `auto`, `generic_json`, `openai_responses`, `anthropic_messages`)
- `validate`: diff text or plain changed-file list

MCP endpoint:
- `GET /health`
- `POST /check` with one of:
  - `changed_files`
  - `plan` + optional `adapter`
  - `path`
- response contains decision buckets and per-file explain metadata.

Migration:
- `filelock-ai migrate-policy old-policy.yaml --output filelock-policy.yaml`

JSON Schema:
- `policy/schema/filelock-policy.schema.json`
- CLI validation: `filelock-ai validate-policy filelock-policy.yaml`
- Conflict resolution:
  - Explicit `tag_definitions` override CODEOWNERS-derived tags.
  - CODEOWNERS-derived tags override `tag_packs`.

Output buckets:
- `allowed_changes`
- `blocked_changes`
- `approval_required_changes`

## Roadmap
- Parse unified diffs at hunk level to enforce line- and block-scoped policy.
- Add optional branch/environment policy overlays (e.g., stricter on `main`).
- Add first-class CI integration helpers (GitHub Actions, GitLab CI, Jenkins).
- Add signed approval workflow for `manual_approval` paths.
- Add policy simulation mode for dry-run rollout on existing repositories.

## Contributions
- Open an issue for design proposals or bugs.
- Submit focused pull requests with tests in `tests/`.
- Keep policy behavior backward-compatible or document migration steps.
- For new rule types, include parser, engine, and CLI coverage.
