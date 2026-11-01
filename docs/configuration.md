# Configuration reference

## Precedence

Configuration loads from three locations, merged key-by-key in increasing
precedence — a later file overrides only the keys it actually sets, nested objects
merge rather than replace wholesale:

| Priority | Location | Scope |
|---|---|---|
| 1 (lowest) | `config/default.json`, shipped inside the plugin | Secure defaults |
| 2 | `~/.prompt-knight/config.json` | Every project on this machine |
| 3 (highest) | `.prompt-knight.json` in a project's root | That project only |

If a file is malformed JSON, PromptKnight falls back to the last valid configuration
(not necessarily the hardcoded default — a valid lower-precedence tier still applies)
and logs a `config_error` operational event. If none of the three files exist at all,
every default is the secure option — see below.

Two file paths in this schema — `tier1.customPatternsFile` and `gitleaks.configPath`
— are themselves user-configurable, and are sandboxed to the plugin directory, your
user config directory (`~/.prompt-knight/`), and the project root: any path
resolving outside those three is refused and logged, never silently read.
`logging.logDir` is sandboxed even more tightly, to `~/.prompt-knight/` specifically,
since D12's rationale is that the plugin directory itself may be read-only.

## Ready-made starting points

Rather than writing a config from scratch, copy one of [`config/samples/`](../config/samples/):

- **`devops.json`** — `audit` mode, Tier 1 only. Nothing is ever blocked; every
  detection is just logged, for teams who want visibility before they enforce.
- **`devsecops.json`** — `block` mode, every tier on. Needs you to fill in gitleaks'
  pinned version/checksum and have Ollama actually running before enabling in
  `block` mode — see the comments in [`config/samples/README.md`](../config/samples/README.md).

## Full schema

### Top level

| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | `"block" \| "warn" \| "audit"` | `"block"` | See [Enforcement modes](#enforcement-modes) |
| `maxPromptBytes` | number | `1048576` | Every detector (Tier 1, gitleaks, Tier 2) only ever sees text truncated to this many UTF-8 bytes — a resource bound shared across all three, and across both the prompt channel and each extracted tool-output field, not just Tier 1 on prompts |

### `tier1` — regex engine

| Key | Type | Default | Notes |
|---|---|---|---|
| `tier1.enabled` | boolean | `true` | Turns the whole regex tier off if `false` |
| `tier1.patterns.aws_keys` | boolean | `true` | AWS access key IDs |
| `tier1.patterns.aws_secrets` | boolean | `true` | AWS secret keys following a key-name assignment |
| `tier1.patterns.aws_accounts` | boolean | `true` | 12-digit AWS account IDs in an assignment context |
| `tier1.patterns.aws_arns` | boolean | `true` | Full AWS ARNs |
| `tier1.patterns.db_strings` | boolean | `true` | Postgres/MySQL/MongoDB/Redis/MSSQL URIs with embedded credentials |
| `tier1.patterns.jwt_tokens` | boolean | `true` | Three-part base64url JWTs |
| `tier1.patterns.npm_tokens` | boolean | `true` | NPM registry tokens and legacy `_authToken=` lines |
| `tier1.patterns.private_ips` | boolean | `true` | RFC 1918 private IPv4 addresses |
| `tier1.customPatternsFile` | string | `"patterns/custom.json"` | Extra patterns, loaded alongside the built-ins; sandboxed (see above). This is also where [the self-improvement loop](self-improvement.md) writes approved patterns |
| `tier1.patternTimeoutMs` | number | `50` | Per-pattern time budget. Enforced with a real, worker-thread-backed abort for custom/user patterns (the actual threat surface); built-in patterns are trusted/reviewed and only measured post-hoc for observability |
| `tier1.allowlist` | string[] | `[]` | Literal substrings — if a candidate detection's matched text contains one, it's suppressed. Applies across every tier, not just Tier 1 |

### `gitleaks` — Tier 1 supplement

| Key | Type | Default | Notes |
|---|---|---|---|
| `gitleaks.enabled` | boolean | `false` | Opt-in |
| `gitleaks.binaryPath` | string | `"gitleaks"` | A bare name is searched on `PATH`; a path containing a separator or an absolute path is used literally |
| `gitleaks.pinnedVersion` | string | `"8.x.y"` | Must match `gitleaks version`'s output before gitleaks will run |
| `gitleaks.expectedSha256` | string | `""` | Must match the SHA-256 of the resolved binary. **Ships empty on purpose** — see [Known limitations](security.md) |
| `gitleaks.configPath` | string \| null | `null` | Optional custom gitleaks ruleset, sandboxed like `customPatternsFile` |
| `gitleaks.timeoutMs` | number | `5000` | Subprocess timeout |

Any verification failure (binary absent, checksum/version mismatch, a spawn error,
or a timeout) is an unconditional skip-and-continue: gitleaks' finding for that scan
is simply empty, logged as a `gitleaks_error` event, and Tier 1's built-in patterns
keep enforcing normally. Unlike Tier 2 (below), this never forces a block.

### `tier2` — Ollama semantic analysis

| Key | Type | Default | Notes |
|---|---|---|---|
| `tier2.enabled` | boolean | `false` | Opt-in; needs a local Ollama instance |
| `tier2.ollamaUrl` | string | `"http://localhost:11434"` | Must resolve to a loopback address (`localhost`, `127.0.0.0/8`, `::1`) unless `allowNonLocal` is `true` |
| `tier2.allowNonLocal` | boolean | `false` | Explicit opt-in to send prompt content to a non-local Ollama endpoint. Logs a `tier2_nonlocal_warning` event every time it's exercised |
| `tier2.model` | string | `"llama3.2:3b"` | Any model you've pulled in Ollama (`ollama pull <model>`) |
| `tier2.timeoutMs` | number | `15000` | Request timeout |
| `tier2.confidenceThreshold` | number | `0.7` | A model response reporting PII below this confidence is discarded, not escalated |
| `tier2.fallbackOnError` | string | `"mode-dependent"` | Documents the failure posture below; not independently configurable |

**Failure posture is mode-dependent and deliberately strict**: if the Ollama request
times out, the connection fails, or the server returns a non-2xx status, PromptKnight
treats this the same as an internal error — in `block` mode, it blocks the prompt
even if nothing else was detected, because it can't verify the prompt is safe. In
`warn`/`audit` mode it fails open with a warning instead. **This means enabling Tier 2
in `block` mode requires Ollama to actually be reachable** — confirm it's running
before flipping `tier2.enabled: true` in a `block`-mode config.

A response that comes back but fails schema validation, or that is below
`confidenceThreshold`, is a *different*, softer case: it's discarded quietly and
never escalates, but it does not trigger the fail-closed behavior above — the
request itself succeeded.

Tier 2 can only ever **escalate** a decision — add a detection — never remove or
downgrade one from Tier 1 or gitleaks, even if a prompt-injection attempt embedded in
the scanned text tries to talk the model into reporting no PII found.

### `logging`

| Key | Type | Default | Notes |
|---|---|---|---|
| `logging.enabled` | boolean | `true` | Audit trail at `~/.prompt-knight/logs/detections.jsonl` |
| `logging.logDir` | string | `"~/.prompt-knight/logs"` | Sandboxed to `~/.prompt-knight/` specifically |
| `logging.logFile` | string | `"detections.jsonl"` | |
| `logging.redactValues` | boolean | `true` | `false` writes the full matched value — your own explicit risk, never the default |
| `logging.previewChars` | number | `4` | Max characters of a detected value ever written to a log or a block/warn message. `0` disables previews entirely |

If the log destination is ever unwritable, PromptKnight continues enforcing
normally and just skips logging for that call, with a one-time warning — a logging
failure never blocks or allows a prompt it otherwise wouldn't have.

### `feedback` — the self-improvement loop

| Key | Type | Default | Notes |
|---|---|---|---|
| `feedback.enabled` | boolean | `false` | Opt-in; gates all of the below, including per-pattern effectiveness tracking |
| `feedback.suggestPatterns` | boolean | `true` | Reserved for future use — pattern suggestion is currently always available via `review-patterns.js` once `enabled` is true |
| `feedback.autoExtendPatterns` | boolean | `false` | Stays `false`. Nothing is ever auto-activated; every pattern needs explicit human approval via the review CLI regardless of this flag's intent |
| `feedback.minHitsForSuggestion` | number | `3` | Minimum similar-shaped Tier 2 catches before a candidate regex is proposed — fewer samples is overfitting |
| `feedback.evidencePreviewChars` | number | `64` | Redacted excerpt length kept specifically for pattern derivation, in a separate `feedback.jsonl` log — deliberately longer than `logging.previewChars`, which is too short to generalize a regex from |

See [the self-improvement loop](self-improvement.md) for the full workflow.

### `toolOutput` — the Read/Grep/Bash channel

| Key | Type | Default | Notes |
|---|---|---|---|
| `toolOutput.enabled` | boolean | `true` | On by default — see [Enforcement modes](#enforcement-modes) for how `mode` applies to this channel |
| `toolOutput.tools` | string[] | `["Read", "Grep", "Bash"]` | Which `PostToolUse` tool names get content-scanned. Narrowing this does not affect the `PreToolUse` deny-by-path pre-filter below, which only ever applies to `Read`/`Grep` regardless |
| `toolOutput.denyPathPatterns` | string[] | `[".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "*.p12", "*.pfx", ".aws/credentials", ".ssh/*"]` | Glob patterns (hand-rolled matcher, not regex — see `design.md` D21) checked against `Read`/`Grep`'s target path *before* the read happens, in `block` mode only. A pattern with no `/` matches the basename anywhere; a pattern with `/` matches that many trailing path segments |

This channel closes Open Decision OD2: it scans what a *tool* reads into context —
`Read`'s file content, `Grep`'s matched lines (only in `output_mode:"content"`), and
`Bash`'s `stdout`/`stderr` independently — through the exact same Tier 1/gitleaks/
Tier 2 pipeline described above, reusing every toggle on this page unchanged. It does
**not** cover MCP tool outputs, `WebFetch`, `NotebookEdit` content, or the
`@file`-mention bypass — see [security.md](security.md) for that remaining gap
(Open Decision OD3).

## Enforcement modes

- **`block`**: exits code `2` — the prompt never reaches Claude. The reason is
  category plus a redacted preview, never the raw value. On the `toolOutput`
  channel, `block` instead redacts the detected content in place via
  `updatedToolOutput` (or, if a detection can't be safely isolated — any Tier 2
  catch, since Tier 2 reports a category without a real offset — withholds the whole
  field) and ends the turn with a warning, since the tool call has already run by
  the time `PostToolUse` fires.
- **`warn`**: the prompt proceeds, with a `systemMessage` describing what was
  flagged. On the `toolOutput` channel, the content passes through unmodified with
  an `additionalContext` note instead.
- **`audit`**: the prompt proceeds silently; detections are only logged, nothing is
  shown to the user. Same on the `toolOutput` channel — content passes through,
  detections are logged with `channel:"tool_output"` and a `tool` field.

If a detector crashes unexpectedly (not a planned failure path like gitleaks being
unverified, but a genuine bug or environment problem), PromptKnight fails **closed**
in `block` mode and **open with a warning** in `warn`/`audit` mode — a scanner crash
is never allowed to become a silent bypass.
