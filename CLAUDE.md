# Claude Code instructions

See [`AGENTS.md`](AGENTS.md) — it's the single source of truth for how to work in
this repo (commands, non-negotiable design constraints, testing conventions, pinned-
value handling). This file only adds what's specific to Claude Code itself.

## Plan mode

Everything in this repo so far — each phase and every feature after it — was built
by researching the real external contract first (a hook's actual stdin/stdout
behavior, a CLI tool's actual flags and output, an HTTP API's actual schema) and
writing that research and the resulting design decisions into a plan before
touching code. Keep doing that for anything non-trivial: a new detector, a new
external integration, a change that revisits an existing security/architecture
decision. A one-line fix or a doc tweak doesn't need it.

## Where the design history lives

`.specs/promptknight/design.md` is canonical. `AGENTS.md`'s "research before
implementing" rule and the inline comments across `src/` are where decisions get
recorded as they're made; `docs/` is where they get summarized for a human reader
afterward. Keep all three honest with each other rather than just updating
whichever one is fastest to edit.
