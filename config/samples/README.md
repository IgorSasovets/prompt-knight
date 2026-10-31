# Sample configurations

Drop either file in as `~/.prompt-knight/config.json` (applies to every project) or
`.prompt-knight.json` in a project root (applies to that project only). See
[docs/configuration.md](../../docs/configuration.md) for the full schema and
precedence rules.

## `devops.json`

**Audit mode, Tier 1 only.** Nothing is ever blocked — every detection is just logged
to `~/.prompt-knight/logs/detections.jsonl`. For a team that wants visibility into what
would have been caught before turning on enforcement.

## `devsecops.json`

**Block mode, every tier enabled.** Tier 1 regex, the gitleaks supplement, Ollama
Tier 2 semantic analysis, and the self-improvement feedback loop are all on. Before
using this as-is:

- **gitleaks**: replace `pinnedVersion` and `expectedSha256` with your actually
  installed binary's values — `gitleaks version` and `shasum -a 256 $(which gitleaks)`
  (or `certutil -hashfile <path> SHA256` on Windows). Until you do, gitleaks fails
  verification and is skipped — safely, not silently broken (REQ-GL-04); Tier 1 still
  enforces normally. Or skip all of that: run `node dist/src/gitleaks-installer.js`,
  which downloads a pinned, checksum-verified gitleaks build (after asking you to
  confirm) and fills in these two values for you automatically — see
  [docs/security.md](../../docs/security.md) for exactly what it checks and why.
- **Tier 2**: requires a local [Ollama](https://github.com/ollama/ollama) install with
  the configured model pulled (`ollama pull llama3.2:3b`). If Ollama isn't reachable,
  Tier 2 fails closed in block mode (REQ-T2-06) — meaning **every** prompt blocks until
  either Ollama is reachable or `tier2.enabled` is set back to `false`. Don't turn this
  on in block mode until Ollama is actually running.
