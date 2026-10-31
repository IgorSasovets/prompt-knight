# PromptKnight — Requirements (EARS)

> Requirements use the **EARS** format (Easy Approach to Requirements Syntax): ubiquitous
> (`The system shall…`), event-driven (`When <trigger>, the system shall…`), state-driven
> (`While <state>, the system shall…`), unwanted-behaviour (`If <condition>, then the system
> shall…`), and optional-feature (`Where <feature>, the system shall…`). `design.md` is canonical;
> if anything here conflicts with it, `design.md` wins.

Each requirement links to the decision(s) and threat-model entries it realizes (see `design.md`
§4, §8).

---

## Interception & hook lifecycle (INT)

- **REQ-INT-01** — *When* a user submits a prompt in Claude Code, PromptKnight **shall** receive
  the full prompt text as JSON on stdin via the `UserPromptSubmit` hook before the prompt is sent
  to Claude. *(D1)*
- **REQ-INT-02** — PromptKnight **shall** complete all scanning for a prompt within the Claude Code
  hook timeout budget (30 s default). *(D1)*
- **REQ-INT-03** — *When* scanning completes and no detection is present, PromptKnight **shall**
  allow the prompt to proceed by exiting with code `0`. *(D17)*

## Tier 1 — regex engine (T1)

- **REQ-T1-01** — PromptKnight **shall** scan each prompt against a built-in regex library covering
  AWS access-key IDs, AWS secret keys, AWS account IDs, AWS ARNs, database connection strings,
  JWTs, NPM tokens, and RFC 1918 private IPv4 addresses. *(D2)*
- **REQ-T1-02** — *When* a Tier 1 pattern matches the prompt text, PromptKnight **shall** record a
  detection carrying the pattern category and match location.
- **REQ-T1-03** — *Where* a custom pattern file is configured, PromptKnight **shall** load and
  apply those patterns in addition to the built-in library.
- **REQ-T1-04** — *Where* an allowlist entry matches a candidate detection, PromptKnight **shall**
  suppress that detection.
- **REQ-T1-05** — *If* evaluating a pattern against the prompt exceeds the per-pattern time budget
  (`patternTimeoutMs`, default 50 ms), *then* PromptKnight **shall** abort that pattern, treat it as
  non-matching, and log a pattern-timeout event. *(D8 · TM-1)*
- **REQ-T1-06** — PromptKnight **shall** limit the prompt text submitted to regex evaluation to a
  configurable maximum size (`maxPromptBytes`, default 1 MB), truncating or declining beyond it.
  *(D8 · TM-1)*
- **REQ-T1-07** — *If* a pattern fails to compile or fails the ReDoS-safety check, *then*
  PromptKnight **shall** skip it, continue with the remaining patterns, and log a pattern-load
  error. *(D8 · TM-1)*

## Tier 1 supplement — gitleaks (GL)

- **REQ-GL-01** — *Where* the gitleaks integration is enabled and the binary is available,
  PromptKnight **shall** scan the prompt text with gitleaks as a supplementary Tier 1 check. *(D5)*
- **REQ-GL-02** — PromptKnight **shall** invoke gitleaks as an out-of-process subprocess using an
  argument array (never a shell string), passing prompt content via a temporary file or stdin, with
  no network access, and parse its JSON report. *(D5 · TM-6 · REQ-SEC-02/05)*
- **REQ-GL-03** — PromptKnight **shall** verify the configured gitleaks binary against the pinned
  version and expected SHA-256 checksum before invoking it. *(D5 · TM-7)*
- **REQ-GL-04** — *If* the gitleaks binary is absent, fails verification, or errors, *then*
  PromptKnight **shall** skip the gitleaks check, continue with the remaining detectors, and log the
  condition. *(D5)*
- **REQ-GL-05** — *When* gitleaks and a built-in pattern report the same secret, PromptKnight
  **shall** deduplicate the detections before enforcement.

## Tier 2 — Ollama LLM (T2)

- **REQ-T2-01** — *Where* Tier 2 is enabled, PromptKnight **shall**, after Tier 1 clears or flags a
  prompt, submit the prompt text to a locally running Ollama instance for semantic PII analysis.
  *(D2)*
- **REQ-T2-02** — PromptKnight **shall** send Tier 2 requests only to a localhost Ollama endpoint
  unless a non-local endpoint is explicitly enabled (`allowNonLocal:true`), in which case it
  **shall** emit a warning. *(D10 · TM-3)*
- **REQ-T2-03** — The Tier 2 result **shall** be able only to escalate a decision to warn/block; it
  **shall never** downgrade or override a Tier 1 detection. *(D9 · TM-2)*
- **REQ-T2-04** — *When* Tier 2 returns a result, PromptKnight **shall** validate it against the
  expected JSON schema and discard any non-conforming content. *(D9 · TM-2)*
- **REQ-T2-05** — *While* Tier 2 confidence is below the configured threshold
  (`confidenceThreshold`, default 0.7), PromptKnight **shall** treat the prompt as non-PII for
  enforcement purposes.
- **REQ-T2-06** — *If* the Ollama request times out or fails, *then* PromptKnight **shall** apply
  the mode-dependent failure posture (fail-closed in block mode; fail-open + warn in warn/audit
  mode). *(D6 · TM-8)*
- **REQ-T2-07** — PromptKnight **shall** pass prompt text to the model in a data field separated
  from the system instruction, so that prompt content cannot alter the detection instruction.
  *(D9 · TM-2)*

## Enforcement & modes (ENF)

- **REQ-ENF-01** — *While* in `block` mode, *if* any detection is present, *then* PromptKnight
  **shall** block the prompt by exiting with code `2` and a JSON block decision carrying a reason.
  *(D17)*
- **REQ-ENF-02** — *While* in `warn` mode, *if* any detection is present, *then* PromptKnight
  **shall** allow the prompt but emit a `systemMessage` describing the detection categories. *(D17)*
- **REQ-ENF-03** — *While* in `audit` mode, PromptKnight **shall** allow all prompts and record
  detections without interrupting the user. *(D17)*
- **REQ-ENF-04** — PromptKnight **shall** default to `block` mode with Tier 1 enabled, Tier 2
  disabled, and gitleaks disabled when no configuration is present. *(D14)*
- **REQ-ENF-05** — *If* the scanner encounters an internal error, *then* *while* in `block` mode
  PromptKnight **shall** fail closed (block), and *while* in `warn` or `audit` mode **shall** fail
  open and emit a warning. *(D6 · TM-8)*
- **REQ-ENF-06** — A block reason or `systemMessage` **shall not** include any raw detected value
  beyond the configured redaction preview. *(D7 · TM-10)*

## Configuration (CFG)

- **REQ-CFG-01** — PromptKnight **shall** load configuration in increasing precedence from the
  plugin default (`config/default.json`), the user config (`~/.prompt-knight/config.json`), and the
  project config (`.prompt-knight.json` in the project root). *(D14)*
- **REQ-CFG-02** — *If* a configured file path resolves outside the permitted directories (plugin
  dir, user config dir, project root), *then* PromptKnight **shall** refuse to load it and log a
  path-violation error. *(D11 · TM-5)*
- **REQ-CFG-03** — PromptKnight **shall** operate with secure defaults (`block` mode, Tier 1 only,
  localhost-only, redaction on, `autoExtendPatterns` off) when no configuration file is present.
  *(D14 · TM-4)*
- **REQ-CFG-04** — *If* a configuration file is malformed, *then* PromptKnight **shall** fall back
  to the last valid or default configuration, continue scanning, and log a configuration error.
  *(D6 · TM-8)*
- **REQ-CFG-05** — PromptKnight **shall** allow individual pattern categories and each detection
  tier to be toggled on or off via configuration.

## Logging & audit (LOG)

- **REQ-LOG-01** — *Where* logging is enabled, PromptKnight **shall** append each detection event as
  a JSON line to the audit log under `~/.prompt-knight/logs/`. *(D12 · TM-9)*
- **REQ-LOG-02** — PromptKnight **shall** record, per detection, a timestamp, the active mode, the
  pattern category, the match location, and — *where* preview is enabled — a redacted preview of at
  most `previewChars` characters (default 4). *(D7 · TM-9)*
- **REQ-LOG-03** — PromptKnight **shall** create log files and directories with owner-only
  permissions (files `0600`, directories `0700`). *(D12 · TM-4)*
- **REQ-LOG-04** — *While* value redaction is enabled (default), PromptKnight **shall never** write
  more than `previewChars` characters of any detected value to any log or message; setting
  `previewChars:0` **shall** disable previews entirely. *(D7 · TM-4)*
- **REQ-LOG-05** — *If* the log destination is not writable, *then* PromptKnight **shall** continue
  enforcement without logging and surface a one-time warning. *(TM-8)*

## Self-improvement loop (SI)

- **REQ-SI-01** — *Where* the feedback loop is enabled, PromptKnight **shall** log Tier 2 detections
  with enough redacted context to derive candidate regex patterns.
- **REQ-SI-02** — PromptKnight **shall** provide a CLI command that groups similar Tier 2 detections
  and proposes candidate regex patterns for human review.
- **REQ-SI-03** — PromptKnight **shall** require explicit human approval before any suggested
  pattern is written to the custom pattern library, and **shall not** auto-activate patterns unless
  `autoExtendPatterns` is explicitly enabled. *(D14)*
- **REQ-SI-04** — *When* a suggested pattern is approved, PromptKnight **shall** validate it
  (compile + ReDoS-safety check) before adding it to `patterns/custom.json`. *(D8 · TM-1)*
- **REQ-SI-05** — PromptKnight **shall** track per-pattern effectiveness (match counts and
  false-positive suppressions) over time.

## Distribution & packaging (DIST)

- **REQ-DIST-01** — PromptKnight **shall** be packaged as a Claude Code plugin with a
  `.claude-plugin/plugin.json` manifest and a `hooks/hooks.json` registering the `UserPromptSubmit`
  hook. *(D1)*
- **REQ-DIST-02** — PromptKnight **shall** be installable via a GitHub-hosted marketplace using
  `claude plugin marketplace add` and `claude plugin install`.
- **REQ-DIST-03** — PromptKnight **shall** ship compiled JavaScript so that no build step is
  required at install time. *(D3)*
- **REQ-DIST-04** — The project **shall** provide CI that runs pattern tests, lint, type-check, and
  cross-platform tests (macOS Intel and Windows AMD+NVIDIA at minimum) on each change. *(D16)*

## Secure development — cross-cutting (SEC)

- **REQ-SEC-01** — PromptKnight **shall** treat all prompt content, configuration, pattern files,
  and external-tool output as untrusted input and validate or sanitize it before use.
  *(WSTG input validation)*
- **REQ-SEC-02** — PromptKnight **shall** construct all subprocess invocations and HTTP requests
  without passing untrusted input through a shell, using argument arrays and structured request
  bodies. *(TM-6 · WSTG injection)*
- **REQ-SEC-03** — PromptKnight **shall** bound resource use on untrusted input (input-length cap
  and per-pattern time budget) so that no single prompt or pattern can exhaust the hook's time
  budget. *(D8 · TM-1 · satisfied via REQ-T1-05/06)*
- **REQ-SEC-04** — PromptKnight **shall** canonicalize and sandbox every filesystem path it reads or
  writes to the permitted directories, rejecting traversal. *(D11 · TM-5 · satisfied via
  REQ-CFG-02)*
- **REQ-SEC-05** — The core detection path and the gitleaks invocation **shall** make no outbound
  network connection other than to the configured localhost Ollama endpoint when Tier 2 is enabled.
  *(D5 · D10 · TM-3)*
- **REQ-SEC-06** — The design **shall** include and maintain a STRIDE-based threat model
  (`design.md` §4), and each mitigation **shall** trace to a requirement.
- **REQ-SEC-07** — PromptKnight **shall** pin and checksum-verify any external binary it invokes and
  **shall** declare zero runtime npm dependencies for the core detection path. *(D4 · D5 · TM-7)*
- **REQ-SEC-08** — Every configuration default **shall** be the secure option (block, localhost,
  redaction on, `autoExtendPatterns` off). *(D14)*
- **REQ-SEC-09** — PromptKnight **shall not** reveal raw secret values or internal stack traces in
  any user-facing message. *(TM-10)*
