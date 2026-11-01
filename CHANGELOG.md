# Changelog

All notable changes to PromptKnight are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project doesn't yet
follow strict semantic versioning (no release has been tagged), so entries are
grouped by build phase rather than by version.

## [1.1.0]

### Phase 6 — Tool-output channel (closes Open Decision OD2)

- Added a `PreToolUse` hook (`src/scan-tool-input.ts`, matcher `Read|Grep`): a
  cheap, deterministic deny-by-path pre-filter against `toolOutput.denyPathPatterns`
  (`.env`, `*.pem`, `.ssh/*`, etc.), active only in `block` mode. Fails open on any
  internal error — it's defense-in-depth, not the enforcement boundary.
- Added a `PostToolUse` hook (`src/scan-tool-output.ts`, matcher `Read|Grep|Bash`):
  runs the existing Tier 1/gitleaks/Tier 2 pipeline over each tool's extracted
  content (Read's file content; Grep's matched lines in `content` mode; Bash's
  `stdout`/`stderr` independently) and, on a block decision, redacts in place via
  `hookSpecificOutput.updatedToolOutput` — verified empirically that this is the
  only mechanism that actually stops content from reaching the model; a top-level
  `decision:"block"` alone does not.
- Added `src/glob-match.ts`: a hand-rolled, non-exponential-blowup glob matcher for
  `denyPathPatterns`, deliberately not a regex so this user-configurable list never
  needs to go through `checkRedosSafety()`.
- Added `src/tool-output-extract.ts`: per-tool `tool_response` ↔ scannable-text
  conversion and exact-shape rebuild — only the extracted field is ever overwritten,
  every sibling key is preserved untouched.
- Added `redactByOffsets()` to `src/validation.ts`: splices a detection into text
  only if its offset is independently verified against the text first. Tier 2
  detections carry a synthetic `index:0, length:0` placeholder and always fail this
  check, which is by design — the caller falls back to a full-field placeholder
  instead of silently leaving a Tier 2 catch unredacted.
- Added the `toolOutput` config block (`enabled: true` by default, `tools: ["Read",
  "Grep", "Bash"]`, `denyPathPatterns`) to `src/types.ts`'s `SECURE_DEFAULTS` and
  `config/default.json`.
- Extended `feedback-logger.ts`'s `logDetections()` with an optional `channel`/`tool`
  tag so tool-output detections are distinguishable from prompt-channel ones in the
  audit log.
- Registered both new hooks in `hooks/hooks.json`.
- Wired `src/scan-tool-output.ts` into the self-improvement loop and per-pattern
  stats (`recordPatternActivity`, `logFeedback`) for full parity with the prompt
  channel — a tool-output Tier 2 catch now feeds `feedback.jsonl`/
  `pattern-stats.json` exactly like a prompt-channel one does, rather than only
  being audit-logged.
- Remaining, explicitly documented gap (Open Decision OD3): MCP tool outputs,
  `WebFetch`, `NotebookEdit` content, and the `@file`-mention bypass (no hook fires
  for those at all) are still out of scope — see `docs/security.md`.

## [v1.0.0]

### Phase 5+ — Packaging, docs, and the gitleaks auto-installer

- Added `.claude-plugin/marketplace.json` (self-hosted single-plugin marketplace,
  `source: "."`) and an icon, so `claude plugin marketplace add` +
  `claude plugin install` actually works.
- Added `LICENSE` (MIT) and `plugin.json`'s `license` field.
- Added `docs/` (installation, configuration reference, architecture, the
  self-improvement loop, security considerations) and trimmed `README.md` to a
  landing page that links into it.
- Added `config/samples/{devops,devsecops}.json` as ready-to-copy starting configs.
- Added CI (`.github/workflows/ci.yml`): typecheck, lint, test across macOS, Linux,
  and Windows.
- Added ESLint (`eslint.config.js`, dev-only).
- Added `demo/demo.sh`, a runnable script that reproduces a real block for anyone
  who wants to record their own demo GIF.
- Added `src/gitleaks-installer.ts` + `src/archive-extract.ts`: a separate,
  user-invoked CLI (`node dist/src/gitleaks-installer.js`) that detects a missing
  gitleaks binary, asks for confirmation, downloads a pinned release, verifies it
  by SHA-256, extracts it (hand-rolled zero-dep tar.gz/zip readers), installs it to
  `~/.prompt-knight/bin/`, and writes a verified config. Deliberately outside the
  hook — see `docs/security.md` for why.

### Phase 4 — Self-improvement loop

- Added `src/pattern-suggester.ts`: groups similar Tier 2 catches by a normalized
  structural shape and proposes a candidate regex per group.
- Added `src/review-patterns.ts`: the human-in-the-loop CLI
  (`node dist/src/review-patterns.js`) that approves/skips/edits suggestions before
  anything is written to `patterns/custom.json`.
- Added `src/pattern-stats.ts`: per-pattern match/suppression counters persisted
  across hook invocations.
- Extended `tier2-ollama.ts`'s response schema with a redaction-bounded `evidence`
  field, and `feedback-logger.ts` with a separate opt-in `feedback.jsonl` log —
  needed so the loop has something to generalize a pattern from.
- Added `feedback.minHitsForSuggestion` and `feedback.evidencePreviewChars` config
  fields.

### Phase 3 — Tier 2 (Ollama semantic analysis)

- Added `src/tier2-ollama.ts`: localhost-locked HTTP client, JSON-Schema-constrained
  request, hand-rolled response validation, confidence gating.
- Tier 2 is escalate-only (can add a detection, never remove one) and fails closed
  in `block` mode on a request failure, open-with-warning in `warn`/`audit`.
- Renamed `enforcement.decide()`'s third parameter from `internalError` to
  `unresolvedRisk` to honestly describe its now-dual purpose.
- Fixed a gap: `maxPromptBytes` truncation wasn't being applied to the gitleaks
  path from Phase 2 — now shared across every detector.

### Phase 2 — gitleaks supplement

- Added `src/gitleaks-adapter.ts`: binary discovery, version+checksum verification,
  out-of-process invocation (temp file + `gitleaks dir`, no shell, no network),
  JSON report parsing, graceful degradation on any failure.
- Added cross-source detection merging and deduplication
  (`tier1-engine.ts: dedupeDetections`).

### Phase 1 — MVP

- Initial `UserPromptSubmit` hook (`src/scan-prompt.ts`), Tier 1 regex engine with
  8 built-in secret categories, ReDoS safety checks plus a worker-thread timeout
  backstop for custom patterns, 3-tier config loading with path sandboxing,
  `block`/`warn`/`audit` enforcement modes with mode-dependent fail-open/closed
  posture, and a redacted, permission-hardened JSONL audit log.
- Zero runtime npm dependencies in the core detection path.
