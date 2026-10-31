<p align="center">
  <img src=".claude-plugin/icon.png" alt="PromptKnight" width="128" height="128" />
</p>

<h1 align="center">PromptKnight</h1>

<p align="center">
  A client-side DLP plugin for <a href="https://code.claude.com">Claude Code</a> that
  scans every prompt via the <code>UserPromptSubmit</code> hook and catches secrets
  and PII <strong>before they leave the terminal</strong>.
</p>

A fast regex tier, an optional local-LLM tier for what regex can't catch, and a
feedback loop that turns real catches into new regex patterns over time.

Everything runs on your machine. No prompt content is sent anywhere as part of the
scan unless you explicitly enable and configure Tier 2 against a local Ollama
instance.

## Status

All five phases of the build plan are implemented:

| Phase | What it adds |
|---|---|
| 1 — MVP | Regex hard-block, configurable `block`/`warn`/`audit` modes, audit logging, ReDoS/path-traversal hardening |
| 2 — gitleaks | Broader secret coverage via a pinned, checksum-verified, offline gitleaks binary |
| 3 — Tier 2 | Optional semantic PII detection via a local Ollama instance, escalate-only |
| 4 — Self-improvement | Tier 2 catches feed a human-reviewed CLI that proposes new Tier 1 patterns |
| 5 — Packaging | README, marketplace manifest, CI, sample configs, demo script, docs |

## Documentation

- **[docs/installation.md](docs/installation.md)** — marketplace install,
  `--plugin-dir` for local dev, verifying it's working
- **[docs/configuration.md](docs/configuration.md)** — the full config schema,
  precedence rules, enforcement-mode semantics
- **[docs/architecture.md](docs/architecture.md)** — the detection pipeline and
  module map
- **[docs/self-improvement.md](docs/self-improvement.md)** — the Tier 2 →
  human-reviewed-pattern feedback loop, end to end
- **[docs/security.md](docs/security.md)** — what's hardened, what's a heuristic,
  and what's an honest, stated limitation rather than a hidden one

The full design history — architecture rationale, the STRIDE threat model, the
decision log, and requirement/task traceability — lives in
[`.specs/promptknight/`](.specs/promptknight/) and remains the canonical reference
for *why* things are built the way they are.

## Quick start

```bash
# Install from this repo as a marketplace (once pushed to GitHub)
claude plugin marketplace add <your-github-owner>/<this-repo>
claude plugin install prompt-knight@prompt-knight

# Or, for local development, load it without installing:
claude --plugin-dir /path/to/prompt-knight
```

With no configuration at all, PromptKnight defaults to the secure option everywhere:
`block` mode, Tier 1 regex only, everything else opt-in. See
[`config/samples/`](config/samples/) for ready-to-copy configs, and
[docs/installation.md](docs/installation.md) for the full install guide.

## How it works

Every submitted prompt passes through **Tier 1** (regex, ~1ms, zero network) first,
plus the optional **gitleaks** supplement. Only prompts that clear or merely flag at
that stage optionally go on to the slower **Tier 2** (local-LLM semantic analysis),
which can only ever *escalate* a decision — never talk the system out of a Tier 1
block, even via prompt injection embedded in the scanned text.

```
prompt → Tier 1 (regex + optional gitleaks) → match? → block/warn/audit
                     │
                no match
                     ▼
         Tier 2 (optional, Ollama) → PII found above confidence threshold? → escalate
```

See [docs/architecture.md](docs/architecture.md) for the full pipeline and module
map.

## Development

```bash
npm install
npm run lint        # eslint
npm run typecheck   # tsc --noEmit
npm test            # builds, then runs node:test against dist/test
```

`dist/` is committed, not gitignored — the plugin ships compiled JS so installing it
needs no build step.

**Working on this repo with a coding agent?** See [`AGENTS.md`](AGENTS.md) for the
rules it should follow (zero-dep policy, path sandboxing, testing conventions,
etc.) — `CLAUDE.md` just points here for Claude Code specifically.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

[MIT](LICENSE)
