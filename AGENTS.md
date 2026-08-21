# claude-redact — agent notes

Scanner for credentials that have leaked into Claude Code's local state
(`~/.claude/`). **Read-only in 0.1.0** — it never modifies anything. Redaction is
milestone two and does not exist yet; do not describe it as if it does.

## Layout

| Path | Purpose |
|---|---|
| `claude-redact` | Executable shim. Wires argv to `main()`, nothing else. |
| `claude_redact.py` | All logic. Kept importable so the tests can reach it — this is why the shim exists. |
| `tests/test_claude_redact.py` | 139 stdlib `unittest` tests. `python3 -m unittest discover -s tests` |

No dependencies, and it should stay that way. PyYAML is used **if importable**
and otherwise falls through to the line scanner — never add it as a requirement.
Targets Python 3.9+; `tomllib` is guarded behind `try/import`.

## Module map (`claude_redact.py`)

- **Classification** — `entropy`, `looks_structural`, `Candidate.classify`,
  `Candidate.leaf_key`. Verdicts are `redact` / `review` / `skip`.
- **Tuning** — `configure()` extends the key regexes and stoplist;
  `load_user_config()` reads `~/.config/claude-redact/config.ini` and
  `./.claude-redact.ini`.
- **Extraction** — `extract_candidates` is the entry point. It unions
  `_structural_pairs` (real parsers), `_line_pairs` (dotenv/msmtprc/generic) and
  `_quoted_strings`; substitutes list-form `KEY=VALUE` env entries via
  `ENV_ASSIGN_RE`; then adds `_derive_embedded` results for URL and Basic-auth
  credentials.
- **Config discovery** — `find_config_files` walks a tree for `CONFIG_GLOBS`,
  honouring `--exclude`, `EXAMPLE_GLOBS` and `.claude-redactignore`.
- **Scope** — `resolve_targets`, `session_targets`, `encode_cwd`, `config_dirs`,
  `load_profile_dirs`.
- **Scanning** — `scan` / `count_in_file` for known values, `discover` for
  credential shapes.
- **CLI** — `build_parser`, `main`, `report`, `report_discovery`.

## The classification model

`Candidate.classify` is a **three-way gate**, in this order:

```
value shape says not-a-secret  -> skip     (stoplist, structural, absent)
key name says credential       -> redact   (entropy NOT consulted)
key name says not-a-credential -> skip     (entropy NOT consulted)
key name says nothing          -> occurrence count, then entropy
```

**The key name decides; entropy is only a tie-breaker when the key is silent.**
This was measured, not assumed: on real hosts a genuine password sits at entropy
3.5 while a Rust linker flag sits at 3.6, a container image reference at 3.5 and
a docker volume spec at 4.0. Entropy does not discriminate in the middle of its
range. Every false positive found during development came from entropy
overriding a key name that was already correct, and every real credential found
was caught by key name — not one by entropy alone below 4.2.

Three rules make the gate safe, and all three are load-bearing:

- **Secret key names match the leaf only** (`leaf_key`). A compose service named
  `ollama-auth` otherwise makes `image`, `cap_add`, `volumes` and
  `container_name` all look like credentials because the path contains "auth".
- **Benign key names match the leaf, and `BENIGN_SUBTREE_RE` matches any
  segment.** `depends_on.postgres.condition` is configuration however deep it
  sits. `environment` and `labels` are deliberately **not** subtree keys — they
  hold arbitrary user keys, so masking their children would hide real secrets.
- **Skipping a benign-named key outright is only safe because composites are
  decomposed upstream.** `DATABASE_URL` is a benign name, but the password
  inside it was already extracted as `DATABASE_URL.password` and is judged on
  its own. If you ever remove `_derive_embedded`, this gate becomes unsafe.

## Invariants — do not break these

**Extraction is deliberately over-inclusive.** A false positive costs the user a
glance; a miss leaves a live credential in a file they now believe is clean.
Never tighten a parser to "reduce noise" — fix the classifier instead. Note this
is also why `extract_candidates` takes no length floor, and why keys that are
benign by name are still extracted: `--key-pattern` can only widen detection over
values that were extracted, and a credential passed on a `command:` line is only
recovered because `command` was extracted despite being benign.

**Never print a candidate value.** `--show-prefix` defaults to 0 because output
lands in the very transcript being audited. `test_secret_value_never_printed` and
the JSON equivalents lock this down.

**No silent caps.** If output is truncated, say so. `report_discovery` once
capped its listing at 20 with no notice; a real host produced 33 findings, so 13
were hidden while the summary implied full coverage.

**Presence is not a finding.** Exit `1` means one or more `redact`/`review`
verdicts. `PUID=1000` appears in every transcript on every host, so an exit code
keyed on presence would fire forever. Text output, JSON output and exit code must
agree — `--verbose` widens all three together.

**Discovery is shape-based, never entropy-based.** Transcripts are full of git
SHAs, UUIDs, base64 and minified code; an entropy threshold buries real findings.

**A reference to a secret is not a secret.** `${DB_PASSWORD:?set it in .env}` and
`api_key: process.env.OPENAI_KEY` name where a credential lives. Reporting them
invites the user to "remove" a line that must stay. See `INTERPOLATION_RE` and
`CODE_REF_RE`.

**`DISCOVERY_PATTERNS` order is significant.** Patterns run independently, so
overlapping ones both fire; `discover` dedupes by value keeping the earliest
entry. Most-specific first — `anthropic_key` must precede `openai_key`.

## Defaults, and why

- **No source argument** → audit the current directory's config files. Requiring
  `--from-dir .` was friction for the overwhelmingly common intent.
- **No scope argument** → sweep all of `~/.claude`, not the current session.
  Narrowing is counter-intuitively *worse*: the "too common" signal is relative
  to the corpus scanned, so a single-transcript scan has too little evidence to
  dismiss ordinary tokens. Measured: one project scanned alone reported three
  findings; the same configs against the whole tree came back clean, because
  `REGISTRY` turned out to appear 453 times across 24 files. `--here` opts back
  into the narrow scope.
- Values travel between projects. A credential defined in one project is
  routinely leaked by a session run somewhere else entirely.

## Performance notes (measured, not guessed)

- Known-value scanning compiles **one** alternation of all values and does a
  single pass per file. Do not revert to per-value `str.count`.
- Discovery compiles its patterns **individually** and runs them in sequence.
  This is 3.2× faster than one combined alternation (0.096 vs 0.305 s/MB),
  because a multi-branch alternation defeats CPython's literal-prefix scan.
  The two facts look contradictory; both are measured. Re-measure before changing.
- **Word boundaries are checked in Python, not with `(?<!...)`.** A leading
  lookbehind also defeats the literal-prefix scan — ~5s per pattern over 554 MB,
  negligible alone but 70s across the fourteen patterns in `BOUNDARY_KINDS`.
  Total went 124s → 57s by moving the check to match time.
- `password_assignment` must not carry a leading `[A-Za-z0-9_.\-]*`. It only
  spanned the key name, which is never captured, and cost 13× in backtracking.
- `.jsonl` is only JSON-parsed when a searched value contains characters JSON
  escapes (`_NEEDS_PARSE_RE`). Otherwise the raw text is searched directly.
  Discovery never parses JSON at all — credential shapes contain no escapable
  characters.

## Multiple config dirs

`resolve_targets` iterates every dir from `config_dirs()`, because a machine
running several Claude Code profiles has one config dir per profile and scanning
only the active one reports clean while another profile goes unexamined.
`session_targets` therefore takes its root explicitly — resolving `file-history/`
against the module-level `CLAUDE_HOME` would silently look in the wrong profile.

`load_profile_dirs()` reads `claude-profile`'s config when present. It is an
**optional integration, never a dependency**: it returns `[]` for an absent or
malformed config and warns rather than failing, so the tool works for people who
have never heard of that project.

## Where a session's data actually lives

`session_targets` covers all four; a `.jsonl`-only scan reports false clean:

```
projects/<slug>/<uuid>.jsonl                the transcript
projects/<slug>/<uuid>/subagents/*.jsonl    subagent transcripts
projects/<slug>/<uuid>/tool-results/*       raw tool output written to disk
file-history/<uuid>/*                       pre-edit copies of edited files
```

`--all` additionally reaches `projects/<slug>/memory/*.md`, which is loaded into
context at the start of every session in that project — a credential written
there is re-read indefinitely. All of these were found on a live host, not
inferred from documentation.

## Gotchas

- Claude Code encodes a project dir by replacing **both** `/` and `.` with `-`
  (`encode_cwd`). `/Users/bob/.zsh` → `-Users-bob--zsh`.
- `.netrc` ends in `rc`, so its parser must be dispatched **before** the
  `endswith("rc")` INI branch.
- Discovery must not fire on `input_tokens` / `cache_read_input_tokens`, which
  appear in every transcript's usage block. Hence `(?![A-Za-z])` after the
  keyword and the numeric-value exclusion.
- The placeholder filter tests the **credential portion**, not the whole match.
  Testing the whole span discarded real findings whose context contained a word
  like "example" — e.g. `postgres://user:realpw@db.example.internal/app`.
- **Pad before colourising.** ANSI escapes count toward `str` width, so padding
  a coloured string collapses the column on a terminal while looking correct
  when piped. This class of bug is invisible in captured output — check a real
  terminal.
- Compose `environment` may be a YAML list, giving `PUID=1000` as one opaque
  value with the key name lost. `ENV_ASSIGN_RE` splits those back into pairs.

## Scope of the project

Remediation, not prevention. Prevention is a `PreToolUse` hook problem and is
covered by other projects (see README). It cannot be complete — `@file` refs,
pasted content, `Grep`/`Edit` output, MCP results and Bash stdout all bypass
hooks, and they bypass it silently — which is the argument for scanning existing
state rather than trusting a control that has no failure signal.
