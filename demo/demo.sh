#!/usr/bin/env bash
# Runs the real compiled hook script against a few sample prompts and prints what
# happens — the actual, reproducible "block in action," meant to be run under a
# terminal recorder (asciinema, vhs, etc.) to produce a real demo GIF. See README.md
# in this directory for how to turn a recording of this into one.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building PromptKnight"
npm run build >/dev/null

DEMO_HOME="$(mktemp -d)"
DEMO_PROJECT="$(mktemp -d)"
trap 'rm -rf "$DEMO_HOME" "$DEMO_PROJECT"' EXIT

run_hook() {
  local prompt="$1"
  local payload
  payload=$(node -e 'console.log(JSON.stringify({session_id:"demo",transcript_path:"/tmp/demo.jsonl",cwd:process.argv[1],permission_mode:"default",hook_event_name:"UserPromptSubmit",prompt:process.argv[2]}))' "$DEMO_PROJECT" "$prompt")
  HOME="$DEMO_HOME" node "$REPO_ROOT/dist/src/scan-prompt.js" <<<"$payload"
}

echo
echo "==> Prompt 1: an ordinary request"
echo '    "Can you refactor the login handler to use async/await?"'
if run_hook "Can you refactor the login handler to use async/await?"; then
  echo "    -> allowed (exit 0)"
fi

echo
echo "==> Prompt 2: a prompt that accidentally includes a live-looking AWS key"
echo '    "Here'"'"'s my key AKIAABCDEFGHIJKLMNOP, can you use it to deploy?"'
set +e
run_hook "Here's my key AKIAABCDEFGHIJKLMNOP, can you use it to deploy?"
status=$?
set -e
echo
echo "    -> blocked (exit $status) — the raw key never appears above, only the category"

echo
echo "==> Audit log (redacted preview, never the raw secret):"
cat "$DEMO_HOME/.prompt-knight/logs/detections.jsonl"
