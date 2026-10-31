# The self-improvement loop

Tier 2 is slow (a local LLM call per prompt) and only runs at all when Tier 1 doesn't
already handle things. The self-improvement loop exists to shift load back to Tier 1
over time: every real PII catch Tier 2 makes is a candidate for a new, fast regex
pattern — reviewed and approved by a human before it ever takes effect.

This is entirely opt-in (`feedback.enabled: false` by default) and has no effect on
enforcement unless you turn it on.

## How it works end to end

1. **Enable it**: set `feedback.enabled: true` (and `tier2.enabled: true` — the loop
   only has anything to learn from if Tier 2 is actually running) in your config.
2. **Tier 2 catches accumulate**: each time Tier 2 escalates a detection, a redacted
   excerpt is appended to `~/.prompt-knight/logs/feedback.jsonl` — separate from the
   main `detections.jsonl` audit trail, truncated to `feedback.evidencePreviewChars`
   (default 64 characters; see [configuration.md](configuration.md) for why this
   differs from the shorter `logging.previewChars`).
3. **Run the review CLI periodically**:

   ```bash
   node dist/src/review-patterns.js
   ```

   It groups similar-shaped catches (by category and a normalized structural
   "skeleton" — letter runs collapsed to `A`, digit runs to `9`), and for any group
   with at least `feedback.minHitsForSuggestion` hits (default 3), proposes a
   candidate regex, pre-validated for ReDoS safety:

   ```
   Found 2 new pattern suggestion(s):

   email (5 hits)   [A-Za-z]+\d+@[A-Za-z]+\.[A-Za-z]+
       e.g. "user1@example.com"
   [a]pprove [s]kip [e]dit >
   ```

4. **Decide, per suggestion**:
   - **`a` (approve)**: re-validated (compile + ReDoS check again — an edited regex
     is untrusted input too), then written to `patterns/custom.json`. The
     backing `feedback.jsonl` entries are purged (their job is done) and the shape
     is recorded so the same suggestion never recurs.
   - **`s` (skip)**: nothing happens. The underlying entries stay in
     `feedback.jsonl` and keep accumulating — skip means "not right now," not "never
     ask again."
   - **`e` (edit)**: enter a replacement regex, which goes through the same
     validation before you're asked again.
5. **The new pattern takes effect immediately** on the next hook invocation — no
   restart needed, since `patterns/custom.json` is read fresh every time.

## What's a heuristic, not a formal generalizer

The regex PromptKnight proposes from a handful of examples is a rough structural
generalization, not a proven-correct pattern. That's the entire reason the review
step is mandatory rather than automatic (`feedback.autoExtendPatterns` has no "on"
behavior — approval always requires a human, regardless of that flag).

## Per-pattern effectiveness tracking

With `feedback.enabled: true`, every pattern — built-in, custom, a gitleaks rule, or
a Tier 2 category — gets its match and allowlist-suppression counts persisted to
`~/.prompt-knight/logs/pattern-stats.json`, keyed by `patternId`. There's no CLI to
view this yet; it's a plain JSON file you can read directly if you want to see which
patterns are actually earning their keep.
