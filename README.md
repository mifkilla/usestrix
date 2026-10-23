# usestrix

Interactive wrapper for [Strix](https://github.com/usestrix/strix), the
autonomous penetration testing agent.

Strix is powerful and its CLI is honest about what it does — but a few of its
defaults are easy to get wrong, and getting them wrong costs real money. This
wrapper picks sane presets, shows you what is happening while a scan runs,
and keeps an auditable record of every engagement.

*Not affiliated with the Strix project. MIT licensed.*

*Русская версия: [README.ru.md](README.ru.md)*

---

## Why this exists

Five things bite people, in roughly this order:

| What | Why it hurts |
|---|---|
| `--scan-mode` defaults to **deep** | Forget the flag and you get 1–4 hours of work and tens of dollars |
| `--max-turns` is counted **per agent** | A scan spawns several agents, so `100` can mean 500 turns in total |
| `--max-budget` is checked **after** a model reply | Small overshoot is normal; subagents wind down near 90% so the root agent can still write the report |
| Exit code **2** means *vulnerabilities found* | Not a failure. CI that treats non-zero as broken will report it wrong. Since Strix 1.7 `--fail-on` gates exit 2 by severity |
| A local directory target is mounted **writable** | Strix runs the application; expect new files in your working tree |

`usestrix` makes each of these visible instead of surprising.

## Features

- **Guided wizard** with five presets — quick triage, web app, API from a
  spec, source code, release audit. Each preset records *why* its numbers
  were chosen, so they do not silently rot.
- **Live progress panel** — Strix goes quiet after its banner in headless
  mode; this shows the current turn, the active agent, surfaces reviewed,
  SARIF entries and spend so far.
- **Web viewer, opened for you** — the link is printed at scan start and
  saved to `viewer-url.txt`. It works on *running* scans, not just finished
  ones.
- **Graceful stop** — `Ctrl+C`, or the menu item from a second terminal.
  `SIGTERM` first, so Strix saves what it has already found.
- **Severity exit gate** — asks whether to pass Strix 1.7's `--fail-on`
  (headless CI runs: exit 2 only for findings at or above the chosen severity).
- **Resume** — pick a previous run and continue it with a fresh budget.
- **Findings summary** — sorted by severity, with CVSS and confidence.
- **Audit trail** — every run writes `command.txt`, `scope.md`,
  `instruction.md`, `strix.log`, `status.txt`.
- **English and Russian** interface.

## Requirements

- Python 3.9+
- [Strix](https://github.com/usestrix/strix) installed and working
  (`pipx install strix-agent`)
- Docker running — Strix needs it for its sandbox
- `rich` for the pretty interface — optional, the wrapper degrades to plain
  text without it

## Install

```bash
git clone https://github.com/mifkilla/usestrix.git
cd usestrix
./install.sh
```

The installer copies a single file to `~/.local/bin/usestrix` and checks your
prerequisites. To remove it: `rm ~/.local/bin/usestrix`.

Manual install works just as well:

```bash
install -m 755 usestrix.py ~/.local/bin/usestrix
```

## Configure

The wrapper reads Strix's own configuration; it does not invent its own.
Model and key are looked up in this order:

1. environment variables
2. `~/.strix/env`
3. `~/.strix/cli-config.json`

Keep the model and the key **together** — Strix drops a stored model when the
shell supplies a key for a different connection (`config/loader.py`,
`_drop_stale_llm_connection`). The simplest working setup:

```bash
# ~/.strix/env   (chmod 600)
export STRIX_LLM=openrouter/deepseek/deepseek-v4.1-flash
export LLM_API_KEY=sk-or-...
```

Optional environment variables for the wrapper itself:

| Variable | Default | Meaning |
|---|---|---|
| `USESTRIX_HOME` | `~/strix-runs` | Where runs and engagement records live |
| `USESTRIX_VIEWER_PORT` | `3400` | First port tried for the web viewer |
| `USESTRIX_LANG` | from `$LANG` | `en` or `ru` |
| `STRIX_CONFIG_DIR` | `~/.strix` | Where to look for Strix config |

## Use

```bash
usestrix
```

The wrapper starts with a preflight check — Strix binary, Docker daemon,
sandbox image, model, key, free disk — and refuses to continue if something
essential is missing.

```
  OK  strix         strix 1.6.2
  OK  docker        daemon responds
  OK  sandbox image present
  OK  model         openrouter/deepseek/deepseek-v4.1-flash
  OK  api key       set, never passed on the command line
  OK  free disk     702 GB
```

Then a menu: new scan, resume, show findings, web viewer, stop a running
scan, help.

While a scan runs you get a live panel:

```
            scanning  3m 12s
  turn             19
  agent            Recon & Surface Mapping
  surfaces         4
  SARIF entries    9
  spend            $0.4212
  stop             Ctrl+C (graceful)
```

## What a run leaves behind

```
$USESTRIX_HOME/
  engagements/<stamp>_<name>/
    command.txt        exact command, reproducible
    scope.md           targets, mode, caps, which preset and why
    instruction.md     what the agent was told
    strix.log          full output
    status.txt         exit code and duration
    viewer-url.txt     viewer link for this run
  strix_runs/<run>/    Strix's own output
    vulnerabilities.json
    penetration_test_report.md
    findings.sarif     level: error = critical/high, warning = medium
    coverage.json      what was reviewed, and what was not
```

## Reading findings well

A finding carries more than a severity. Two fields are worth more than the
rest and are usually ignored:

- **`counterevidence`** — what Strix tested *against* its own finding. Empty
  counterevidence is a weak finding.
- **`coverage.json`** — what was *not* reviewed. A coverage gap presented as
  "clean" is a false report.

Filtering by confidence beats filtering by severity:

```bash
jq '[.[] | select(.confidence == "high" and .cvss >= 7.0)]' \
  "$USESTRIX_HOME"/strix_runs/*/vulnerabilities.json
```

## Safety notes

- The viewer link **contains a token**. Anyone with it can steer a live scan
  and read history. Do not share it, and do not bind the viewer to `0.0.0.0`.
- Scan a **copy** of your code — a git worktree or a fresh clone. The wrapper
  asks, but it cannot check for you.
- Only test what you are authorized to test. The wrapper writes your scope to
  `scope.md` so the boundary is on record, but the boundary itself is yours to
  set.

## Contributing

Issues and pull requests welcome. Keep it a single file with no required
dependencies beyond the standard library — that is the point.

## Licence

MIT. See [LICENSE](LICENSE).
