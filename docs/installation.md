# Installation

PromptKnight ships compiled JavaScript in `dist/` — installing it never requires a
build step on your machine.

## From a marketplace (recommended)

Once this repository is pushed to GitHub, register it as a marketplace and install
the plugin from it:

```bash
claude plugin marketplace add <your-github-owner>/<this-repo>
claude plugin install prompt-knight@prompt-knight
```

The install id is `<plugin-name>@<marketplace-name>` — both happen to be
`prompt-knight` here, because this repository is both the plugin and its own
single-plugin marketplace (`.claude-plugin/marketplace.json`'s one entry has
`"source": "."`, meaning "the root of this repo").

Or, from inside an interactive Claude Code session, once the marketplace is added:

```
/plugin install prompt-knight --marketplace <your-github-owner>/<this-repo>
```

## For local development or trying it without installing

Load the plugin for a single session, straight from the working copy, with no
marketplace and nothing written to your settings:

```bash
claude --plugin-dir /path/to/prompt-knight
```

If you edit the TypeScript sources while developing, rebuild (`npm run build`) and run
`/reload-plugins` inside the session to pick up the change — `claude --plugin-dir`
loads whatever is currently in `dist/`, not the `.ts` sources directly.

## Choosing an install scope

When you install via `claude plugin install` (not `--plugin-dir`), you pick a scope:

- **User scope**: enabled for you, in every project on this machine.
- **Project scope**: enabled for everyone on a repository, via its committed
  `.claude/settings.json`. Each collaborator still needs to install it locally once.
- **Local scope**: enabled for you, in this one repository only.

See [Claude Code's own install docs](https://code.claude.com/docs/en/plugins/install)
for the full walkthrough of each scope.

## Verifying the install

```bash
claude plugin list
```

should show `prompt-knight@prompt-knight` with `Status: ✔ enabled`. To confirm the
hook actually fires, submit a prompt containing something like `AKIAABCDEFGHIJKLMNOP`
(a fake AWS-shaped key) — with the default `block` mode, PromptKnight should refuse
it before it ever reaches Claude. `demo/demo.sh` in this repository reproduces exactly
that, outside of a live session, if you want to see it without needing a real
install first.

## Uninstalling / disabling

```bash
claude plugin disable prompt-knight@prompt-knight   # keep it installed, turn it off
claude plugin uninstall prompt-knight@prompt-knight # remove it
```
