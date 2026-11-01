# Agent instructions for PromptKnight

This file is the single source of truth for coding agents working in this repo
(Claude Code, Cursor, Copilot, or anything else that reads `AGENTS.md`). If another
file in this repo (e.g. `CLAUDE.md`) gives tool-specific instructions, it should
point back here rather than duplicating any of this.

PromptKnight is a client-side DLP plugin for Claude Code: a `UserPromptSubmit` hook
that scans prompts for secrets/PII before they reach Claude, plus a `PreToolUse`/
`PostToolUse` hook pair that scans `Read`/`Grep`/`Bash` tool output the same way. See
[`README.md`](README.md) for what it does and [`docs/architecture.md`](docs/architecture.md)
for the module map. The canonical design record — architecture rationale, the STRIDE
threat model, the decision log, requirement/task traceability — is
[`.specs/promptknight/`](.specs/promptknight/); `design.md` wins when anything
disagrees with it, and a change to the design should be propagated there first.

## Commands

```bash
npm install
npm run build       # tsc -> dist/
npm run typecheck   # tsc --noEmit
npm run lint        # eslint src test
npm test            # builds, then runs node:test against dist/test/*.test.js
```

Run `lint`, `typecheck`, and `test` before considering any change done — not just
`build`. CI (`.github/workflows/ci.yml`) runs all three across macOS, Linux, and
Windows on every push/PR.

## Non-negotiable constraints

These are load-bearing design decisions, not style preferences. Don't work around
them without raising it explicitly first.

- **Zero runtime npm dependencies.** Nothing under `src/` may `require`/`import` a
  package from `dependencies` — only Node's own built-ins. `devDependencies`
  (`typescript`, `eslint`, etc.) are fine; they never ship. If a feature needs
  something a built-in doesn't provide (archive extraction, HTTP, hashing), hand-roll
  it — see `src/archive-extract.ts` and `src/redos-check.ts` for the house style:
  narrowly scoped to the actual need, not a general-purpose reimplementation of the
  library you're avoiding.
- **`dist/` is committed, not gitignored.** The plugin ships compiled JS so installs
  need no build step (REQ-DIST-03). After any `src/` change, run `npm run build` and
  commit the result alongside it — a PR that changes `src/` without a matching
  `dist/` change is incomplete.
- **Every config default is the secure option** (block mode, a tier off, redaction
  on, nothing auto-activated, localhost-only). A new config field needs a secure
  default in three places that must stay in sync: `src/types.ts`'s `SECURE_DEFAULTS`,
  `config/default.json`, and `docs/configuration.md`'s reference table.
- **Every user-configurable file path gets sandboxed** before it's read or written —
  reuse `resolveSandboxedPath()` / `isPathWithin()` from `src/config-loader.ts`,
  don't write a new path-containment check from scratch.
- **Every regex that comes from outside the shipped `patterns/builtin.json`
  (custom patterns, a self-improvement suggestion, anything a human or a model
  could influence) goes through `checkRedosSafety()` (`src/redos-check.ts`) before
  it's ever compiled**, and gets re-validated again at the point of approval if a
  human can edit it in between (see `review-patterns.ts`'s approve/edit loop).
- **No raw secret value is ever written anywhere** — not a log, not a block/warn
  message, not a thrown error. Route every user-facing or logged value through
  `redactPreview()` (`src/validation.ts`); don't re-implement truncation ad hoc.
- **No hook (`src/scan-prompt.ts`, `src/scan-tool-input.ts`, `src/scan-tool-output.ts`)
  can make network calls or ask for interactive input.** None has a TTY (stdin is
  the JSON payload) and REQ-SEC-05 scopes "no network" to the core detection path
  specifically. Anything that needs either of those — provisioning a tool,
  reviewing suggestions — becomes a separate, explicitly-invoked CLI instead
  (precedent: `review-patterns.ts`, `gitleaks-installer.ts`), never something
  bolted onto a hook path.
- **A detector's own failure degrades gracefully; it never gets to silently bypass
  enforcement.** Follow the existing split: an unverified/unreachable optional
  detector (gitleaks) skips and logs without affecting the decision; a detector
  whose *request* genuinely fails (Tier 2) forces the mode-dependent fail-open/closed
  posture via `enforcement.decide()`'s `unresolvedRisk` flag. Know which bucket a
  new failure mode belongs in — they're deliberately different, not interchangeable.

## Keep CHANGELOG.md current

**Every change that touches `src/`, `config/`, `patterns/`, or adds/removes a
file an installer or user would notice gets a `CHANGELOG.md` entry, in the same
change, not as a follow-up.** Add it under `## [Unreleased]`, in the phase/feature
subsection it belongs to (start a new subsection for genuinely new work). Follow
the existing entries' style: one bullet per notable change, written for someone
reading the project's history later, not a restatement of the diff. A doc-only fix
or a test added for existing behavior doesn't need one; a new file, a new config
field, a changed default, or a changed failure/security posture always does.

## Testing conventions

- **Never make a real network call in a test.** Two patterns are already in use,
  pick whichever fits:
  - *Dependency injection*: pass a stub implementation of the thing that would call
    out (see `downloadArchive(url, hash, fetchImpl)` in `gitleaks-installer.ts`).
  - *In-process stub server*: `http.createServer` bound to `127.0.0.1` on an
    ephemeral port, standing in for a real service (see `tier2-ollama.test.ts`).
- **A subprocess spawned from inside a test may not have network access, even to
  loopback, in a sandboxed CI/agent environment** — this was a real, debugged
  finding (see `test/scan-prompt.e2e.test.ts`'s Tier 2 escalation test), not a
  theoretical one. If an end-to-end test spawns the hook as a child process and it
  needs network, make the test self-detect that condition and skip with a clear
  reason — don't assume network "just works" for a grandchild process.
- **Design cross-platform logic as pure, parameterized functions** so every target
  platform is unit-tested from whichever one machine happens to run the suite —
  don't gate platform-specific logic behind `process.platform` checks inside the
  function itself if it can take `platform`/`arch` as arguments instead (see
  `detectPlatformKey()` in `gitleaks-installer.ts`). Reserve
  `{ skip: process.platform === "win32" }`-style test skips for assertions that
  are genuinely only meaningful on one OS (POSIX file permission bits, for example).
- Tests compile alongside `src/` into `dist/test/` and run via
  `node --test dist/test/*.test.js` (wired up as `npm test`'s script, which runs
  `npm run build` first via `pretest`).

## When a pinned value (hash, version) is involved

Never invent a checksum, version string, or similar pinned value. If you need one
(a new gitleaks release to support, a new pinned dependency), fetch it from the
actual authoritative source — a project's real published checksums file, the real
release API — and record where it came from. `gitleaks-installer.ts`'s
`PINNED_GITLEAKS_RELEASES` table and its comment are the house precedent: real
values, fetched once, with an explicit note on how to refresh them later.

## Research before implementing

Before building against an external contract (a hook's stdin/stdout schema, a CLI
tool's exact flags and output format, an HTTP API's request/response shape),
verify it against the real documentation or source rather than assuming — this
project has repeatedly found real discrepancies this way (e.g. `gitleaks stdin`
turned out not to support a JSON report at all, which changed the whole adapter
design in Phase 2). Document what you verified and what you deliberately chose
where the spec left it open, the way `docs/security.md` and the inline comments
across `src/` already do — a design decision without its reasoning recorded is a
decision the next person (human or agent) will second-guess or silently redo.

## Git

Don't commit unless the person you're working with asks you to, and don't assume
one approval covers the next change too.
