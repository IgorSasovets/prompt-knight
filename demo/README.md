# Demo

Here is `demo.sh` — a runnable script that produces
the real "block in action" output, so you can record it yourself.

```bash
./demo/demo.sh
```

It builds the plugin, then runs the actual compiled hook script
(`dist/src/scan-prompt.js`) against two sample prompts in an isolated temp `$HOME` (it
never touches your real `~/.prompt-knight/`): an ordinary request that's allowed, and
one with a fake-but-live-looking AWS key that gets blocked — showing that only the
category and a short redacted preview ever appear, never the raw key.

## Turning this into a GIF

Pick whichever terminal recorder you already use:

- **[asciinema](https://asciinema.org/)**: `asciinema rec demo.cast -c ./demo/demo.sh`,
  then convert with [agg](https://github.com/asciinema/agg) (`agg demo.cast demo.gif`)
  or embed the `.cast` file directly — many places (including GitHub) render it inline.
- **[vhs](https://github.com/charmbracelet/vhs)**: write a short `.tape` file that runs
  `demo.sh` and set `Output demo.gif`.
- **macOS**: QuickTime Player's screen recording, or `screencapture`, then convert the
  `.mov` to GIF with `ffmpeg` or [gifski](https://gif.ski/).
- **Any OS**: a plain screen recorder (OBS, etc.) works too — convert to GIF afterward
  if you want one inline in the README rather than a video link.
