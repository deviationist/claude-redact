# claude-redact — agent notes

Scanner for credentials that have leaked into Claude Code's local state
(`~/.claude/`). **Read-only in 0.1.0** — it never modifies anything.

## Layout

| Path | Purpose |
|---|---|
| `claude-redact` | Executable shim. Wires argv to `main()`, nothing else. |
| `claude_redact.py` | All logic. Kept importable so the tests can reach it — this is why the shim exists. |
| `tests/test_claude_redact.py` | 69 stdlib `unittest` tests. `python3 -m unittest discover -s tests` |

No dependencies, and it should stay that way. PyYAML is used **if importable**
and otherwise falls through to the line scanner — never add it as a requirement.

## Module map (`claude_redact.py`)

- **Classification** — `entropy`, `looks_structural`, `Candidate.classify`.
  Verdicts are `redact` / `review` / `skip`.
- **Extraction** — `extract_candidates` is the entry point; it unions
  `_structural_pairs` (real parsers), `_line_pairs` (dotenv/msmtprc/YAML/generic)
  and `_quoted_strings`, then `_derive_embedded` for URL and Basic-auth
  credentials.
- **Config discovery** — `find_config_files` walks a tree for `CONFIG_GLOBS`.
- **Scanning** — `scan` / `count_in_file` for known values, `discover` for
  credential shapes.
- **CLI** — `build_parser`, `main`.

## Invariants — do not break these

**Extraction is deliberately over-inclusive.** Nothing is written without
confirmation, so a false positive costs a keystroke while a miss leaves a live
credential in a file the user believes is clean. Never tighten a parser to
"reduce noise".

**Never print a candidate value.** `--show-prefix` defaults to 0 for a reason:
output lands in the transcript being audited. `TestCLI.test_secret_value_never_printed`
locks this down.

**Occurrence count is the primary signal**, ahead of entropy. It is measured
from the user's real files rather than guessed from the value's shape, so it
catches low-entropy secrets and — more importantly — stops common words being
treated as credentials.

**Discovery is shape-based, never entropy-based.** Transcripts are full of git
SHAs, UUIDs, base64 and minified code. An entropy threshold buries real findings.

**`DISCOVERY_PATTERNS` order is significant.** Patterns run independently, so
overlapping ones both fire; `discover` dedupes by value keeping the earliest
entry. Most-specific first — `anthropic_key` must precede `openai_key`.

## Performance notes (measured, not guessed)

- Known-value scanning compiles **one** alternation of all values and does a
  single pass per file. Do not revert to per-value `str.count`.
- Discovery compiles its patterns **individually** and runs them in sequence.
  This is 3.2× faster than one combined alternation (0.096 vs 0.305 s/MB),
  because a multi-branch alternation defeats CPython's literal-prefix scan.
  The two facts look contradictory; both are measured. Re-measure before changing.
- `password_assignment` must not carry a leading `[A-Za-z0-9_.\-]*`. It only
  spanned the key name, which is never captured, and cost 13× in backtracking.
- `.jsonl` is only JSON-parsed when a searched value contains characters JSON
  escapes (`_NEEDS_PARSE_RE`). Otherwise the raw text is searched directly.

## Gotchas

- Claude Code encodes a project dir by replacing **both** `/` and `.` with `-`
  (`encode_cwd`). `/Users/bob/.zsh` → `-Users-bob--zsh`.
- `.netrc` ends in `rc`, so its parser must be dispatched **before** the
  `endswith("rc")` INI branch. This was a real bug caught by the tests.
- Discovery must not fire on `input_tokens` / `cache_read_input_tokens`, which
  appear in every transcript's usage block. Hence `(?![A-Za-z])` after the
  keyword and the numeric-value exclusion.
- The placeholder filter tests the **credential portion**, not the whole match.
  Testing the whole span discarded real findings whose context contained a word
  like "example" — e.g. `postgres://user:realpw@db.example.internal/app`.

## Scope of the project

Remediation, not prevention. Prevention is a `PreToolUse` hook problem and is
covered by other projects (see README). It cannot be complete — `@file` refs,
pasted content, `Grep`/`Edit` output, MCP results and Bash stdout all bypass
hooks — which is the argument for scanning existing state.
