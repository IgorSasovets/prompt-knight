#!/usr/bin/env bash
# Manually-run verification that scan-tool-output.ts's `updatedToolOutput` actually
# suppresses a secret from reaching a real Claude Code session — not just that the
# hook exits 0 and returns well-shaped JSON. This is the same procedure used to
# research D22/D23 in .specs/promptknight/design.md: Claude Code's hooks reference
# does not publish the exact `tool_response`/`updatedToolOutput` schema per tool
# ("depends on the tool"), so a future Claude Code release could silently change it
# and defeat redaction without the unit/e2e tests (which assert against the JSON the
# hook produces, not against a real session) ever noticing.
#
# Deliberately NOT wired into `npm test`/CI (see AGENTS.md: "never make a real
# network call in a test"): this spends a real model call against an installed,
# authenticated `claude` binary. Run it by hand after upgrading Claude Code, or
# whenever D22's shape-fidelity assumption needs re-confirming.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v claude >/dev/null 2>&1; then
  echo "SKIP: no 'claude' binary on PATH — this script needs a real, authenticated Claude Code install." >&2
  exit 0
fi

echo "==> Building PromptKnight"
npm run build >/dev/null

PROJECT_DIR="$(mktemp -d)"
trap 'rm -rf "$PROJECT_DIR"' EXIT

mkdir -p "$PROJECT_DIR/.claude"
cat >"$PROJECT_DIR/.claude/settings.json" <<EOF
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Read", "hooks": [{ "type": "command", "command": "node \\"$REPO_ROOT/dist/src/scan-tool-output.js\\"" }] }
    ]
  }
}
EOF

FAKE_SECRET="AKIAEXAMPLEEXAMPLE12"
cat >"$PROJECT_DIR/sample.txt" <<EOF
AWS_ACCESS_KEY_ID=$FAKE_SECRET
EOF

echo "==> Running a real headless Claude Code session against the sandboxed hook"
# Deliberately does NOT override HOME: a real, authenticated `claude` session needs
# the real login state, which lives under the real home directory. Project-level
# trust/settings come from $PROJECT_DIR/.claude/settings.json instead, and `-p`
# sessions always treat the project directory as trusted (see code.claude.com/docs/
# en/hooks "Workspace trust"), so no dialog is needed.
OUTPUT="$(cd "$PROJECT_DIR" && claude -p \
  "Read the file sample.txt verbatim using the Read tool and print its exact contents back to me." \
  --allowedTools "Read" 2>&1)" || true

echo
echo "==> Model's final output:"
echo "$OUTPUT"
echo

if echo "$OUTPUT" | grep -qF "$FAKE_SECRET"; then
  echo "FAIL: the raw secret appeared in the model's output — updatedToolOutput's shape no longer matches the Read tool's real schema. Re-run T6.3's research (capture a real PostToolUse:Read payload with a logging hook) and update src/tool-output-extract.ts." >&2
  exit 1
fi

echo "==> Checking the full session transcript, not just the final reply"
PROJECT_ESCAPED="$(echo "$PROJECT_DIR" | sed 's#/#-#g')"
TRANSCRIPT_DIR="$HOME/.claude/projects/$PROJECT_ESCAPED"
if [ -d "$TRANSCRIPT_DIR" ] && grep -rqF "$FAKE_SECRET" "$TRANSCRIPT_DIR" 2>/dev/null; then
  echo "FAIL: the raw secret appears somewhere in the session transcript, even though it wasn't in the final reply." >&2
  exit 1
fi

echo "PASS: the raw secret never appeared in the model's output or the session transcript."
