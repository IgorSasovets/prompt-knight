# PromptKnight — Tasks (phased, MVP-first)

> Implement **phase by phase, MVP-first**. Each task lists the requirement IDs it satisfies (see
> `requirements.md`) and the decisions it depends on (see `design.md` §8). `design.md` is canonical.
> A phase's exit criterion is that every listed requirement is implemented and tested.

Phases map to the six grades from the source brief. **Phase 1 is the MVP** and is independently
useful on its own.

---

## Phase 1 — MVP: regex hard-block + configurable enforcement & audit logging
*(Grades 1–2. Effort per brief: ~5–8 days. Zero runtime deps.)*

- **T1.1 — Scaffold the TypeScript plugin project.**
  Set up `tsconfig`, `tsc` build to `dist/`, `node:test` wiring, `.claude-plugin/plugin.json`,
  `hooks/hooks.json` (registering `node ${CLAUDE_PLUGIN_ROOT}/dist/scan-prompt.js` on
  `UserPromptSubmit`), and the directory layout from `design.md` §7. Ship compiled JS.
  → REQ-DIST-01, REQ-DIST-03 · D3, D4

- **T1.2 — Hook entry point (`scan-prompt.ts`).**
  Read stdin JSON, extract prompt text, orchestrate tiers, emit the decision and exit code (`0`
  allow, `2` block) within the hook timeout budget.
  → REQ-INT-01, REQ-INT-02, REQ-INT-03

- **T1.3 — Tier 1 regex engine + built-in pattern library.**
  Implement `tier1-engine.ts`; load and compile the eight built-in pattern categories from
  `patterns/*.json`; record detections with category + location.
  → REQ-T1-01, REQ-T1-02 · D2

- **T1.4 — ReDoS safeguards (secure by design).**
  Enforce `maxPromptBytes` input bound; evaluate each pattern under `patternTimeoutMs`; validate
  pattern compilation and run a ReDoS-safety check, skipping unsafe/uncompilable patterns.
  → REQ-T1-05, REQ-T1-06, REQ-T1-07, REQ-SEC-03 · D8 · TM-1

- **T1.5 — Block-mode enforcement.**
  Return `exit 2` with a JSON block decision and reason; the reason carries only category +
  redacted preview, never the raw value.
  → REQ-ENF-01, REQ-ENF-06 · TM-10

- **T1.6 — Config loader with 3-tier override + path sandboxing.**
  Implement `config-loader.ts` with plugin→user→project precedence; canonicalize and sandbox all
  paths to permitted dirs (reject traversal); fall back safely on malformed config; allow
  per-category and per-tier toggles.
  → REQ-CFG-01, REQ-CFG-02, REQ-CFG-03, REQ-CFG-04, REQ-CFG-05, REQ-SEC-04 · D11, D14 · TM-5, TM-8

- **T1.7 — Enforcement modes + mode-dependent failure posture.**
  Implement `block` / `warn` / `audit`; secure defaults (block, Tier 1 only); on internal error,
  fail closed in block mode and fail open + warn in warn/audit. Confirm every shipped default is the
  secure option.
  → REQ-ENF-02, REQ-ENF-03, REQ-ENF-04, REQ-ENF-05, REQ-SEC-08 · D6, D14 · TM-8

- **T1.8 — Audit logging (JSONL) with redaction + secure permissions.**
  Implement `feedback-logger.ts`; append detections to `~/.prompt-knight/logs/detections.jsonl`;
  timestamp + mode + category + location + optional ≤`previewChars` preview; create files/dirs
  `0600`/`0700`; continue without logging (one-time warning) if the destination is unwritable.
  → REQ-LOG-01, REQ-LOG-02, REQ-LOG-03, REQ-LOG-04, REQ-LOG-05 · D7, D12 · TM-4, TM-9

- **T1.9 — Custom patterns + allowlist.**
  Load `patterns/custom.json` alongside built-ins (through the ReDoS-safe path from T1.4); apply
  the allowlist to suppress false positives.
  → REQ-T1-03, REQ-T1-04

- **T1.10 — Unit tests + cross-platform smoke.**
  `node:test` suites for each pattern category, enforcement modes, failure posture, and config
  precedence; smoke-test on macOS (Intel) and Windows (AMD+NVIDIA).
  → REQ-DIST-04 (partial)

- **T1.11 — Input-validation & injection-safe I/O scaffolding (cross-cutting).**
  Central input-validation helpers treating prompt/config/patterns as untrusted; ensure no
  user-facing message leaks raw values or stack traces. (Establishes the pattern that later
  subprocess/HTTP tasks build on.)
  → REQ-SEC-01, REQ-SEC-09 · TM-10

**Phase 1 exit:** a zero-dependency plugin that hard-blocks structured secrets by default, is
configurable across block/warn/audit, logs safely, and is ReDoS- and path-traversal-hardened.

---

## Phase 2 — gitleaks supplement
*(Grade 3. Effort per brief: ~1–2 days. Replaces detect-secrets-js per D5.)*

- **T2.1 — gitleaks discovery + supply-chain verification.**
  Detect the binary; verify pinned version and SHA-256 checksum before use.
  → REQ-GL-03, REQ-SEC-07 · D5 · TM-7

- **T2.2 — gitleaks out-of-process invocation (no shell, no network).**
  Implement `gitleaks-adapter.ts`; invoke via argument array, pass content by temp file/stdin, run
  with no network, parse the JSON report.
  → REQ-GL-01, REQ-GL-02, REQ-SEC-02, REQ-SEC-05 · D5 · TM-6, TM-3

- **T2.3 — Merge + deduplicate findings.**
  Combine gitleaks findings with built-in detections and map to the block/warn/audit decision tree.
  → REQ-GL-05

- **T2.4 — Graceful degradation.**
  If gitleaks is absent/unverified/errors, skip it, continue with other detectors, and log.
  → REQ-GL-04

**Phase 2 exit:** broader secret coverage with no added npm dependencies and no network calls.

---

## Phase 3 — Tier 2 Ollama semantic analysis
*(Grade 4. Effort per brief: ~3–5 days. Opt-in; requires local Ollama.)*

- **T3.1 — Ollama HTTP client, localhost-locked.**
  Implement `tier2-ollama.ts` with abort/timeout handling; refuse non-local endpoints unless
  `allowNonLocal:true`, warning when overridden.
  → REQ-T2-01, REQ-T2-02, REQ-SEC-05 · D10 · TM-3

- **T3.2 — Detection system prompt + injection-safe framing.**
  Design the structured-JSON system prompt; pass prompt text in a data field separated from the
  instruction so prompt content cannot alter the detection instruction.
  → REQ-T2-07 · D9 · TM-2

- **T3.3 — Schema validation, escalate-only enforcement, confidence gating.**
  Validate Ollama output against the expected schema and discard non-conforming content; allow the
  result to escalate only (never downgrade a Tier 1 block); gate on `confidenceThreshold`.
  → REQ-T2-03, REQ-T2-04, REQ-T2-05 · D9 · TM-2

- **T3.4 — Tier 2 failure posture.**
  On timeout/failure, apply the mode-dependent posture (closed in block, open+warn in warn/audit).
  → REQ-T2-06, REQ-ENF-05 · D6 · TM-8

**Phase 3 exit:** optional local-LLM tier that catches unstructured PII and cannot be injection-
talked out of a block.

---

## Phase 4 — Self-improvement loop
*(Grade 5. Effort per brief: ~5–7 days. Requires Tier 2 active.)*

- **T4.1 — Feedback logger with derivable context.**
  Log Tier 2 detections with enough redacted context to derive candidate patterns.
  → REQ-SI-01

- **T4.2 — Pattern suggestion engine.**
  Group similar Tier 2 detections and propose candidate regex patterns.
  → REQ-SI-02

- **T4.3 — Human-review CLI with safe activation.**
  Implement `review-patterns.ts`; require explicit approval; validate (compile + ReDoS-check) every
  approved pattern before writing it to `patterns/custom.json`; keep `autoExtendPatterns` off by
  default.
  → REQ-SI-03, REQ-SI-04 · D8, D14 · TM-1

- **T4.4 — Effectiveness tracking.**
  Track per-pattern match counts and false-positive suppressions over time.
  → REQ-SI-05

**Phase 4 exit:** Tier 2 catches measurably strengthen Tier 1, with a human gate on every new
pattern.

---

## Phase 5 — Marketplace publishing & docs
*(Grade 6. Effort per brief: ~2–3 days.)*

- **T5.1 — Marketplace manifest + docs.**
  Author `marketplace.json`, `README.md`, installation guide, and a configuration reference.
  → REQ-DIST-02

- **T5.2 — Sample configurations.**
  Ship sample configs for common scenarios (DevOps, DevSecOps).
  → REQ-CFG-05 (exercised)

- **T5.3 — CI: tests, lint, type-check, cross-platform.**
  Run pattern tests, lint, `tsc` type-check, and tests on macOS Intel + Windows AMD+NVIDIA on each
  change.
  → REQ-DIST-04, REQ-SEC-06 (threat-model trace kept current in CI review)

- **T5.4 — Demo.**
  Create a demo GIF/screencast showing a block in action.
  → REQ-DIST-02 (supporting)

**Phase 5 exit:** installable in two commands from a GitHub marketplace, documented, and CI-gated.

---

## Coverage check

Every requirement in `requirements.md` is referenced by at least one task above, and every task
references at least one requirement. The full matrix lives in `design.md` §9 (canonical). Verify
coverage again before packaging and whenever a requirement changes.
