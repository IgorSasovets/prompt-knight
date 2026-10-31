# PromptKnight documentation

- **[Installation](installation.md)** — marketplace install, `--plugin-dir` for
  local development, verifying it's working, uninstalling.
- **[Configuration reference](configuration.md)** — the full schema, precedence
  rules, and enforcement-mode semantics.
- **[Architecture](architecture.md)** — the detection pipeline, module map, and why
  each tier exists.
- **[The self-improvement loop](self-improvement.md)** — how Tier 2 catches turn
  into reviewed Tier 1 patterns, end to end.
- **[Security considerations](security.md)** — what's hardened, what's a heuristic
  rather than a formal guarantee, and what's an honest, stated gap rather than a
  hidden one.

For the full design history — architecture rationale, the STRIDE threat model, the
decision log, and requirement/task traceability — see
[`.specs/promptknight/`](../.specs/promptknight/), which remains the canonical
reference for *why* things are built the way they are.
