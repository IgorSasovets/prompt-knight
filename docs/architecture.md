# Architecture

This is a condensed, implementation-level view. The canonical design record — full
STRIDE threat model, decision log, and requirement/task traceability — lives in
[`.specs/promptknight/design.md`](../.specs/promptknight/design.md) and is the source
of truth if anything here ever drifts from it.

## The pipeline

```
UserPromptSubmit hook (dist/src/scan-prompt.js)
  │
  ├─ Tier 1: regex engine (src/tier1-engine.ts)
  │    built-in patterns (patterns/builtin.json) + custom patterns (patterns/custom.json)
  │    ReDoS-checked at load time (src/redos-check.ts); custom patterns additionally
  │    run under a worker-thread timeout (src/pattern-worker.ts)
  │
  ├─ gitleaks supplement, if enabled (src/gitleaks-adapter.ts)
  │    out-of-process, pinned + checksum-verified binary, no network
  │
  ├─ Tier 2: Ollama semantic analysis, if enabled (src/tier2-ollama.ts)
  │    localhost-locked, escalate-only, schema-validated response
  │
  ├─ merge + dedupe (src/tier1-engine.ts: dedupeDetections)
  ├─ decide (src/enforcement.ts: pure function, mode × detections × unresolvedRisk)
  ├─ audit log (src/feedback-logger.ts) + pattern-effectiveness stats (src/pattern-stats.ts)
  └─ exit 0 (allow) / exit 0 + systemMessage (warn) / exit 2 (block)
```

Every prompt goes through Tier 1 first. gitleaks and Tier 2 — each independently
opt-in — run in addition to Tier 1, not instead of it; their findings merge with
Tier 1's before a single enforcement decision is made for the whole prompt.

## Module map

| Module | Responsibility |
|---|---|
| `src/scan-prompt.ts` | Hook entry point: reads stdin JSON, orchestrates every tier, emits the decision and exit code. The only module that does process I/O |
| `src/config-loader.ts` | Three-tier config load + deep merge, path sandboxing (`resolveSandboxedPath`, reused by every module that reads a user-configurable path) |
| `src/tier1-engine.ts` | Compiles + runs built-in and custom regex patterns, allowlist filtering, cross-source dedup |
| `src/redos-check.ts` | Static heuristic that rejects catastrophic-backtracking regex shapes before a pattern is ever compiled |
| `src/pattern-worker.ts` | `worker_threads` target that gives custom patterns a *real*, preemptible timeout |
| `src/gitleaks-adapter.ts` | Binary discovery + verification, out-of-process invocation, JSON report parsing |
| `src/tier2-ollama.ts` | Localhost-locked HTTP client, JSON-Schema-constrained request, hand-rolled response validation |
| `src/enforcement.ts` | Pure `decide(mode, detections, unresolvedRisk) -> allow|warn|block` — no I/O, directly unit-testable |
| `src/feedback-logger.ts` | JSONL audit log (`detections.jsonl`) and the opt-in feedback log (`feedback.jsonl`), both redaction-aware and permission-hardened (0600/0700) |
| `src/pattern-stats.ts` | Per-pattern match/suppression counters, persisted across invocations |
| `src/pattern-suggester.ts` | Shape-signature grouping + regex generalization for the self-improvement loop |
| `src/review-patterns.ts` | Human-review CLI (`node dist/src/review-patterns.js`) |
| `src/validation.ts` | Shared redaction/sanitization helpers used everywhere user-facing output is produced |

## Why each tier exists

- **Tier 1 (regex)** handles structured secrets — AWS keys, connection strings, JWTs,
  etc. — at effectively zero cost per scan, and is always on by default.
- **gitleaks** is a supplementary, actively-maintained secret-pattern library,
  chosen over trufflehog specifically because trufflehog's live-credential
  verification makes outbound network calls — the opposite of what a DLP tool should
  do (see `design.md` §8, decision D5).
- **Tier 2 (Ollama)** exists because regex structurally cannot generalize to
  natural-language-embedded PII ("my coworker John's SSN is..."). It's the slowest
  and least certain tier, which is why it's opt-in, escalate-only, and confidence-
  gated.
- **The self-improvement loop** exists to shift load from Tier 2 (slow, needs a
  local LLM) back to Tier 1 (fast, zero dependencies) over time, with a mandatory
  human-review gate so nothing novel ever gets auto-activated.

## Security properties worth knowing about explicitly

See [security.md](security.md) for the full list, including what's a heuristic
rather than a formal guarantee, and what relies on a dependency's own behavior
rather than an enforced sandbox.
