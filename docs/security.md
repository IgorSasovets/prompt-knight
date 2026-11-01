# Security considerations

PromptKnight handles attacker-controllable input (the prompt text), loads
user-supplied configuration and patterns, and shells out to external tools. The full
STRIDE threat model and the requirement that traces each mitigation lives in
[`.specs/promptknight/design.md`](../.specs/promptknight/design.md) §4. This page is
the practical summary: what's genuinely hardened, and — just as important — what's a
heuristic or a documented assumption rather than a formal guarantee.

## What's hardened

- **Every default is the secure option**: `block` mode, Tier 1 only, gitleaks and
  Tier 2 off, Ollama localhost-only, redaction on, nothing auto-activated.
- **Path sandboxing**: every user-configurable file path (`tier1.customPatternsFile`,
  `gitleaks.configPath`, `logging.logDir`) is canonicalized and checked against a set
  of permitted roots before it's ever read or written; anything outside is refused
  and logged, never silently followed.
- **No shell interpolation**: the gitleaks subprocess is invoked via an argument
  array, never a shell string, and prompt content reaches it through a temp file, not
  command-line interpolation.
- **Subprocess integrity**: gitleaks is verified against both a pinned version
  (`gitleaks version` output) and a SHA-256 checksum of the actual binary file before
  it's ever invoked. Either check failing means it's skipped, not run anyway.
- **Resource bounds**: every detector sees the prompt truncated to `maxPromptBytes`;
  custom regex patterns run under a real worker-thread timeout that can `terminate()`
  a runaway match, not just a best-effort measurement.
- **No raw values leak**: block/warn messages and the audit log carry only a category
  and a short redacted preview (`logging.previewChars`, default 4) — this is enforced
  through one shared helper (`redactPreview`), not re-implemented per call site.
- **Fail-safe on crash**: an unexpected internal error fails *closed* in `block` mode
  and *open with a warning* in `warn`/`audit` mode — a scanner crash never becomes a
  silent bypass.
- **Tool-output redaction only ever touches the field it read**: the `PostToolUse`
  hook (`scan-tool-output.ts`) rebuilds a tool's `tool_response` by cloning it and
  overwriting only the extracted field (e.g. Read's `file.content`), never
  reconstructing the shape from scratch — verified empirically (not just assumed from
  the docs) that this is what makes `updatedToolOutput` actually suppress the
  content, since Claude Code silently discards a shape-mismatched replacement and
  falls back to the original, unredacted output.
- **Tool-output redaction never trusts an unverifiable offset**: a detection is only
  spliced into the surrounding text if `text.slice(index, index+length)` still
  equals the detection's own matched value; a batch containing even one detection
  that fails this check (every Tier 2 finding does, by construction — see below)
  falls back to withholding the whole field rather than risk a partial, silently
  wrong redaction.

## What's a heuristic, not a formal proof

**The ReDoS safety check is conservative, not a formal prover.** It rejects the
well-known catastrophic-backtracking shapes — nested unbounded quantifiers like
`(a+)+`, overlapping alternation under a quantifier, absurd quantifier bounds — by
walking the pattern's source text. A pattern engineered to defeat this specific
heuristic while still being slow is theoretically possible; this is why custom
patterns additionally run under a real, preemptible worker-thread timeout rather than
relying on the static check alone.

**Pattern suggestions are a rough generalization**, not a proven-correct regex — see
[self-improvement.md](self-improvement.md). This is the entire reason approval is a
mandatory human step.

## What relies on a dependency's documented behavior, not an enforced sandbox

**gitleaks' "no network" posture is gitleaks' own behavior, not something
PromptKnight enforces** (no network namespace, no firewall rule around the
subprocess). This is exactly the property that made gitleaks the choice over
trufflehog in the first place — trufflehog's signature feature is live credential
verification, which makes outbound calls to third-party APIs, which would make a DLP
tool itself a quiet exfiltration channel. gitleaks does pure local regex/entropy
scanning with no such feature. If you need a stronger network-isolation guarantee
than "this tool doesn't do that," run it under your own sandboxing (a container with
no network, a restrictive seccomp profile, etc.) — PromptKnight doesn't provide one.

## What's an honest gap, not a hidden one

- **Channel scope — narrower than before, still not total.** PromptKnight now covers
  two channels: the `UserPromptSubmit` prompt text, and (since the tool-output
  phase) `Read`/`Grep`/`Bash` tool output via `PreToolUse`/`PostToolUse` hooks. It
  still does **not** inspect MCP tool outputs, `WebFetch` fetches, `NotebookEdit`
  content, or anything referenced with an `@file` mention in a prompt — Claude Code
  inserts `@`-mentioned content directly, without any tool call, so no hook fires
  for it at all (not a PromptKnight limitation specifically — no hook *can* see it).
  If this matters for your threat model, set `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1`
  (Claude Code v2.1.299+) to force those reads through `Read` instead, where
  PromptKnight's `PostToolUse` hook does see them. Pair PromptKnight with
  server-side DLP and CI secret-scanning for comprehensive coverage regardless —
  this was stated as a limitation in the original design brief and, narrowed to what
  remains, is preserved here rather than quietly dropped (see `design.md`'s Open
  Decision OD3).
- **A tool-output false positive in `block` mode ends the agentic turn, not just a
  re-prompt.** The prompt channel's `block` mode just means the user re-types; the
  tool-output channel's `block` mode means a mid-task `Read`/`Grep`/`Bash` call gets
  its result redacted or withheld and the turn stops. This channel defaults to
  **on** anyway (every other default in this project is the secure option), but it's
  a real, accepted tradeoff — see `design.md` decision D24 — not a free lunch.
- **`gitleaks.expectedSha256` ships empty on purpose.** Hardcoding a real release's
  hash would silently rot — gitleaks publishes many platform/arch binaries and the
  hash changes every release. gitleaks stays off until you supply your own installed
  binary's version and checksum (`gitleaks version`, `shasum -a 256 $(which
  gitleaks)`) — or run `node dist/src/gitleaks-installer.js` for the automated path
  below, which exists specifically to remove that manual step.
- **The auto-installer (`gitleaks-installer.ts`) pins one specific gitleaks version
  (currently 8.30.1), hardcoded, with a real maintenance cost.** This is the same
  "a hardcoded hash rots" tradeoff as the point above, deliberately accepted for
  *this one, opt-in, explicitly human-confirmed path only* — the manual
  bring-your-own-binary default is untouched. Bumping the pinned version means
  fetching that release's real `gitleaks_<version>_checksums.txt` from
  [gitleaks' GitHub releases](https://github.com/gitleaks/gitleaks/releases) and
  replacing every hash in `PINNED_GITLEAKS_RELEASES` — never inventing one.
  **Two different hashes are in play and serve different purposes**: the pinned
  table hash verifies the *downloaded archive* (so a corrupted or tampered-with
  download is rejected before anything is extracted); after extraction, the
  installer computes its *own* hash of the extracted binary and writes that one
  into `gitleaks.expectedSha256` — that second hash is what every future scan's
  `verifyBinary()` checks (at-rest tamper detection on your disk, a different
  concern from one-time download integrity).
- **Tier 2 detections carry no real excerpt in the enforcement path.** Ollama gives a
  category and a confidence score, not a byte-accurate match location, so
  `Detection.matchedText` for a Tier 2 finding is a synthetic placeholder
  (`[semantic-detection:<category>]`), never real text. A short, separately-redacted
  excerpt exists only in the opt-in feedback log, specifically so the
  self-improvement loop has something to generalize from — it never touches
  enforcement, deduplication, or the allowlist.
- **Enabling Tier 2 in `block` mode requires Ollama to actually be reachable.** A
  request failure (timeout, connection refused, non-2xx) fails *closed* by design —
  meaning every prompt blocks until Ollama answers or you turn Tier 2 back off.
- **CI platform coverage is the closest practical approximation, not literal
  compliance** with "macOS Intel and Windows AMD+NVIDIA": GitHub-hosted runners
  cover macOS Intel (`macos-13`) and Windows/Linux (CPU only) — GPU runners aren't
  available on standard hosted infrastructure.
