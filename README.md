# claude-redact

**Find credentials that leaked into Claude Code's local state — then get them out.**

Claude Code stores every session as plaintext JSONL under `~/.claude/projects/`.
When an agent reads a config file, the tool result is persisted verbatim, so a
credential printed once stays on disk indefinitely and gets re-read on `/resume`.
Transcript trees reaching hundreds of megabytes across dozens of project
directories are normal.

`claude-redact` tells you what is in there.

> **It does not un-send anything.** By the time a value reaches a transcript it
> has already gone to the API as part of that request. This is about *local*
> hygiene: stopping the value being re-read by future sessions, and getting it
> out of anything that backs up or syncs your home directory. If a credential is
> genuinely exposed, rotate it — this tool is not a substitute for that.

## Status

`0.2.0` — scanning and redaction. A prevention hook is still planned; see
[Roadmap](#roadmap).

## Install

Python 3.9+, no dependencies.

```bash
git clone https://github.com/deviationist/claude-redact.git ~/.zsh/claude-redact
ln -s ~/.zsh/claude-redact/claude-redact ~/.local/bin/claude-redact
```

## Usage

### Audit a project's configs against your transcripts

With no arguments it does the obvious thing: finds every config file in the
current directory that plausibly holds secrets, extracts their values, and
reports which ones appear in your Claude Code state.

```bash
cd ~/code/myproject
claude-redact
```

Only candidates that look like credentials are listed; `-v` adds the ones
classified benign. To audit a tree you are not standing in:

```bash
claude-redact --from-dir ~/code/myproject --all
```

The values are read **inside the process**. They are never printed, never passed
as arguments, and never reach your shell history — only key names and counts
come back.

Picks up `.env`, `.env.*`, compose files, `*.tfvars`, `credentials.json`,
`secrets.yaml`, `.netrc`, `.pgpass`, `.npmrc`, `msmtprc`, Spring
`application.properties`, `appsettings.json` and similar. See what it would read
without scanning:

```bash
claude-redact --from-dir ~/code/myproject --list-sources
```

Note it deliberately ignores `.gitignore`: a gitignored file is *more* likely to
hold live credentials, which is usually why it is ignored.

### Narrow to one file

```bash
claude-redact --from-file ~/code/myproject/.env --all
```

### Search for a value you already know leaked

```bash
printf '%s' "$SECRET" | claude-redact --value - --all
```

Use `-` and pipe it in. Passing a secret as a literal argument puts it in your
shell history and in `ps` output.

### Discovery — find credentials with no reference file

```bash
claude-redact --discover --all
```

Searches for credential *shapes* rather than known values: AWS/GitHub/GitLab/
OpenAI/Anthropic/Stripe/Slack/SendGrid/Google/npm/DigitalOcean key formats, JWTs,
PEM private-key blocks, `scheme://user:pass@host` connection strings,
`Authorization:` headers, and `SOMETHING_PASSWORD=` assignments.

This is the mode that catches leaks whose source was never a config file — Bash
output like `docker compose config`, `docker inspect`, or something pasted into
a prompt once. Deliberately shape-based rather than entropy-based: transcripts
are full of git SHAs, UUIDs, base64 and minified code, and an entropy threshold
buries real findings in noise.

## Removing what you find

```bash
claude-redact --redact --dry-run    # show exactly what would change
claude-redact --redact              # plan, confirm, rewrite, verify
```

Each confirmed value is replaced with `[REDACTED:KEY_NAME]`, so the transcript
stays readable and you can see later what was removed.

**This is destructive and there is no undo.** That is deliberate: an undo store
would have to hold every secret you ever redacted, in one predictable path —
strictly worse than the leak being cleaned, which is one string buried in a
large tree. The dry run and the confirmation prompt are the safety net instead.
Your config file is untouched, so it remains the source of truth.

Guarantees, each covered by tests:

- **Only `redact` verdicts** are touched. `--include-review` widens it;
  `--value` bypasses the classifier, since you have already said what it is.
- **Rewritten in place**, never write-and-rename. Claude Code holds the active
  transcript open for append, and a rename leaves that descriptor writing into
  an unlinked inode — silently losing the rest of the session.
- **JSONL lines without a hit stay byte-identical.** Lines with one are edited
  raw where possible, and only parsed and re-serialised when the value contains
  characters JSON escapes and a raw search cannot find it.
- **Undecodable bytes round-trip** unchanged.
- **A live session is refused** unless `--force`. Its context still holds the
  value and can write it back, so redacting it is best-effort at best — exit
  the session first.
- **Non-interactive runs refuse** without `--yes`.
- **A verify pass re-scans everything afterwards** — the whole of each config
  dir, not just the files that were rewritten — and reports anything still
  present. Coverage becomes a result you can read rather than a design
  assumption.

A journal at `$XDG_STATE_HOME/claude-redact/journal.jsonl` (mode `0600`) records
file, key names and counts. **No values, and no hashes** — a SHA-256 of a weak
password is brute-forceable, which would reintroduce the risk in miniature.

## Scope

| Flag | Scans |
|---|---|
| *(default)*, `--all` | Everything under `~/.claude`: `projects/`, `file-history/`, `history.jsonl`, `paste-cache/`, `shell-snapshots/`, `backups/`, `debug/`, `todos/` |
| `--session UUID` | One specific session and everything belonging to it |
| `--here` | Only the current directory's newest session |
| `--config-dir DIR` | A Claude Code config dir to scan (repeatable) |
| `--all-profiles` | Every config dir declared by `claude-profile`, if installed |
| `--path P` | Any extra file or directory (repeatable) — combine with any of the above |

### Multiple profiles

Tools that run several Claude Code profiles side by side give each one its own
config dir. Scanning only one reports clean while another profile's transcripts
go completely unexamined, so the scan covers **all** of them.

Config dirs are resolved in this order, most specific first:

1. `--config-dir DIR` (repeatable), or `CLAUDE_REDACT_PROFILE_DIRS`
   (`os.pathsep`-separated)
2. [`claude-profile`](https://github.com/deviationist/claude-profile), when
   installed — every profile it lists, so a profile added there is picked up
   here with no second edit
3. `$CLAUDE_CONFIG_DIR`
4. `~/.claude`, plus a `-personal` sibling beside it when one exists

```bash
claude-redact                      # every profile, if claude-profile is installed
claude-redact --active-profile     # only the one it reports as active
claude-redact --all-profiles       # require it; fail if unavailable
claude-redact --config-dir ~/.claude --config-dir ~/.claude-work
```

`claude-profile` is an optional integration, never a dependency: any failure
falls through to the next source. It is located via `$CLAUDE_PROFILE_SCRIPT`,
then a `claude-profile` on `PATH`, then a sibling clone — the same order its
other companion tools use, so no two can disagree about which install they mean.
Note it is usually a **shell function**, so a Python process finds it via the
sibling clone; set `CLAUDE_PROFILE_SCRIPT` if your checkouts are not siblings.

**The full sweep is the default, and narrowing has a counter-intuitive cost.**
The "too common" signal is measured against the corpus you scan, so a narrow
scope has too little evidence to dismiss ordinary tokens and reports *more*
false positives, not fewer. On a real host, one project scanned alone produced
three findings; the same configs swept against the whole tree came back clean,
because values like `REGISTRY` turned out to appear 453 times across 24 files.

Values also travel: a credential defined in one project is routinely leaked by a
session run somewhere else entirely.

A session is more than its `.jsonl`. Three locations are searched together:

```
projects/<slug>/<uuid>.jsonl                  the transcript
projects/<slug>/<uuid>/subagents/*.jsonl      subagent transcripts
projects/<slug>/<uuid>/tool-results/*         raw tool output written to disk
file-history/<uuid>/*                         pre-edit copies of files that were edited
```

`tool-results/` matters most: large tool output is stored there rather than
inline, so a sizeable `cat .env` can land in a file the transcript only points
at. Scanning the `.jsonl` alone would report the session clean.

`--all` also reaches two places that are easy to forget and that a
session-scoped run will not touch:

- `projects/<slug>/memory/*.md` — persistent memory files, which are loaded into
  context at the start of every session in that project. A credential written
  into one is re-read indefinitely.
- `file-history/<uuid>/` — pre-edit snapshots of files an agent modified. Editing
  a `.env` leaves a complete copy of its previous contents here.

`--all` is the honest choice when you do not know which session leaked.

## How values are judged

Every candidate gets a verdict of `redact`, `review`, or `skip`, from four
signals:

- **Key name** — `PASSWORD`, `SECRET`, `TOKEN`, `API_KEY` score up; `PORT`, `TZ`,
  `PUID`, `LOG_LEVEL` score down.
- **Occurrence count** — the strongest signal, and measured from your actual
  files rather than guessed from the value's shape. A real credential appears
  once or twice. A generic word appears everywhere.
- **Shannon entropy and charset mix** — catches high-entropy values whose key
  name gave nothing away.
- **Stoplist and structural shapes** — `true`, `admin`, `localhost`, port
  numbers, durations, paths, timezones, image refs, semver.

The occurrence count matters more than it sounds. Auditing a real `.env`
against a 554 MB transcript tree, `POSTGRES_USER=admin` scored **83,687 hits
across 1,162 files** — a naive `sed` would have rewritten every one of them to
remove the word "admin". Real credentials in the same run sat at 1–7 hits in a
single file.

Tune with `--min-length N` (default 8). `--show-prefix N` reveals the first N
characters of each value; it defaults to 0 because anything printed lands in the
transcript you are currently in.

## Tuning which keys count as credentials

The built-in credential key names (`pass`, `password`, `pwd`, `secret`, `token`,
`api_key`, `private_key`, `credential`, `auth`, `salt`, `dsn`, …) can be
extended for your own conventions — never replaced, since narrowing detection is
the one direction that loses credentials.

Per run:

```bash
claude-redact --key-pattern 'vault|kms|licence' --benign-pattern 'mount|replica'
```

Or persistently, in `~/.config/claude-redact/config.ini` (or `.claude-redact.ini`
in the directory you run from):

```ini
[keys]
# regex alternatives added to the built-in credential key names
secret = vault|kms|licence|handle
# added to the built-in benign key names
benign = mount|replica|shard

[values]
# never treated as credentials, comma or newline separated
stoplist = mycorp, internal.example
```

`--no-config` ignores both files. `--stop-value` adds a single value for one run.

## Ignoring files

`*.example`, `*.sample`, `*.template`, `*.dist` and `*.default` are skipped by
default — they hold placeholders. `--include-examples` brings them back, for the
rarer case of a real secret committed into one.

Add `--exclude GLOB` (repeatable), or drop a `.claude-redactignore` at the root
of the scanned tree:

```
# one glob per line
docker-compose.override.yml
fixtures/*.env
```

## Performance

A full `--all` sweep is I/O and regex bound — expect roughly a minute per
gigabyte. Default scope (one transcript) is instant. Progress is shown on a TTY.

Two things make it survivable: known-value scanning does one regex pass per file
instead of one per value, and discovery runs its patterns individually rather
than as one alternation — measured 3.2× faster, because a multi-branch
alternation defeats CPython's literal-prefix scan optimisation.

## Prevention

This tool is remediation. It pairs with prevention, which is a different problem
solved by different projects:

- [`cc-redact`](https://github.com/ShindouMihou/cc-redact) — `PreToolUse` hook,
  `Read` only. Redacts values while preserving keys, fails closed.
- [`claude-redact-env`](https://github.com/trevorstenson/claude-redact-env) —
  `PreToolUse` hook covering `Read` and some `Bash` file reads.
- [`claude-code-redact`](https://github.com/paroque28/claude-code-redact) — a
  local proxy on `ANTHROPIC_BASE_URL`, the only one covering arbitrary Bash
  output.

None of them modifies transcripts, so none of them helps with what is already on
disk. Be aware of the trade-off in the proxy approach specifically: it sanitises
what leaves your machine, but Claude Code still reads the real value locally and
still writes it into the transcript.

Prevention also cannot be complete. A `PreToolUse` hook rewrites tool *input*,
so `@file` references (which Claude Code inlines without calling `Read`), pasted
content, `Grep`/`Edit` output, MCP results and Bash stdout all bypass it — and
they bypass it silently. Scanning is how you find out.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — nothing worth attention |
| `1` | One or more findings (`redact` or `review`) |
| `2` | Error |

Presence alone is not a finding: `PUID=1000` appears in every transcript on
every host, so an exit code keyed on presence would fire forever.

Suitable for a cron audit: `claude-redact --discover --all || notify`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

69 tests, stdlib only. Several are regression guards for bugs found in
development and are labelled as such.

## Roadmap

1. **Scanning** — done.
2. **Redaction** — done.
3. **Prevention** — possibly a `--hook` mode reusing the same parsers.

## License

MIT
