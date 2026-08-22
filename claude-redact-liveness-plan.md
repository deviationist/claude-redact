# claude-redact: replace the mtime-only live-session heuristic

**Repo:** `git@github.com:deviationist/claude-redact.git` (checked out at `~/.zsh/claude-redact`, branch `main`)
**Do the work on:** the MacBook Air. xavi and quim are consumers only — they just `git pull`.
**Written:** 2026-08-22, from a false positive observed on quim.

---

## 1. Why

`claude-redact --redact` refuses to rewrite a transcript that looks like a live
Claude Code session, because rewriting a file Claude Code holds open for append
can lose data, and a live session's context still holds the secret and can write
it back after the pass. That refusal is correct in principle. The detection is
too blunt.

Observed on quim on 2026-08-22:

```
error: 2732975d-5b05-4f16-83e6-78f5f4bedcfe.jsonl looks like a live session.
       Exit that session and re-run, or pass --force to accept a best-effort result.
```

That session was **not** running. Its transcript's last record was its own
teardown write:

```json
{"type":"queue-operation","operation":"enqueue","timestamp":"2026-08-22T18:54:02.100Z",
 "sessionId":"2732975d-...","content":"<task-notification>...<status>killed</status>
 <summary>Background command \"Wait for build to complete\" was stopped</summary>..."}
```

mtime `18:54:02`; the redact ran within the next minute. The file was dead, it
just had a fresh mtime. Waiting 137 s and re-running passed with no `--force`.

So: **every session that exits produces a two-minute window in which the tool
refuses to clean it** — which is exactly the window you are in, because
finding a leak in a session is usually why you just quit that session.

## 2. Current implementation

`claude_redact.py:834`:

```python
def is_active(path: Path, window: float = 120.0) -> bool:
    """Heuristic: a transcript touched moments ago is probably a live session.

    Rewriting a file Claude Code holds open for append is the one operation
    here that can lose data, so this errs towards claiming 'active'.
    """
    env_session = os.environ.get("CLAUDE_SESSION_ID")
    if env_session and path.stem == env_session:
        return True
    try:
        return (time.time() - path.stat().st_mtime) < window
    except OSError:
        return False
```

Two call sites:

| Line | Context | Effect |
|---|---|---|
| `claude_redact.py:2005` | inside `_do_redact`, over the files in the plan | hard `die()` unless `--force` |
| `claude_redact.py:2182` | inside `main`, read-only runs only | soft `warn()` |

`--force` is defined at `claude_redact.py:1906`.

Note there is no process check anywhere. There is also no platform-specific
code in the file at all today (only stdlib imports; `subprocess` is imported
locally at line 667 for the claude-profile shim).

## 3. Goal

Keep every true positive. Drop the false positive where the mtime is fresh but
nothing is actually holding the file.

**Non-goals**
- Do not weaken the refusal. When the tool cannot tell, it must still refuse.
- Do not add a dependency. Stdlib only; the repo has none and should keep none.
- Do not touch the `CLAUDE_SESSION_ID` self-check — that one is exact, keep it first.

## 4. Phase 0 — verify the signal before writing any code

**This phase decides whether the feature is buildable. Do not skip it, and do
not start Phase 1 until it has an answer.**

The proposed signal is "some process has this .jsonl open". That is only useful
if Claude Code holds the transcript fd open across the session rather than
opening, appending and closing per write. **This is unverified.** Determine it
empirically:

1. Start a Claude Code session in some scratch directory on the MBA. Note its
   session id and transcript path under `~/.claude/projects/<slug>/<uuid>.jsonl`.
2. With that session **idle at a prompt** (not mid-turn), from a second terminal:
   ```sh
   lsof -t -- ~/.claude/projects/<slug>/<uuid>.jsonl
   ```
3. Repeat mid-turn, while the session is actively writing.
4. Quit the session, then run it once more.

Record all four results in the commit message or PR body.

**Decision gate**

- **Held while idle** → the signal is good. Proceed to Phase 1 as written.
- **Held only mid-turn** → too weak on its own to *clear* a file, but it is a
  reliable positive. Proceed to Phase 1, but the precedence in Phase 2 changes:
  an open fd forces "active"; absence of one does **not** clear it. Combine with
  the smaller window from the fallback below. Say so in the docstring.
- **Never held (open/append/close per write)** → abandon the fd approach.
  Fall back to the cheap win instead, which is worth shipping on its own:
  - Shrink the window to something like 20–30 s. It was picked as a round
    number, not measured; the risk it covers is a session writing *during* the
    rewrite, which is a seconds-scale race, not a two-minute one.
  - Make the error message actionable: print the file's age and how long
    remains, e.g. `last written 41s ago; it will stop looking live in 79s`.
    Right now the user cannot tell whether to wait 3 seconds or 2 minutes.
  - Ship that, and stop.

**Already ruled out — do not spend time here:**
- `~/.claude/session-env/<uuid>/` — the directory persists after exit and is
  empty. Not a liveness marker.
- `~/.claude/daemon/roster.json` — has `supervisorPid` + a `workers` map, but
  it was empty while a session was live. It is Remote Control's roster, not a
  session registry. Undocumented internal; do not build on it.
- `/tmp/claude-<uid>/<slug>/<uuid>/` runtime dirs — also persist after exit.

## 5. Phase 1 — a cross-platform holder check

Add one helper near `is_active`. It must be **three-state**: held, not held, or
*unknown*. Collapsing "unknown" into "not held" is the one change that would
make this tool less safe than it is today.

```python
def _holders(paths: Sequence[Path]) -> set[Path] | None:
    """Which of `paths` some process currently holds open.

    Returns None when that cannot be determined — no /proc, no lsof, the probe
    failed or timed out. None means "unknown", never "nothing", because the
    caller falls back to the conservative mtime window on None.
    """
```

Requirements:

- **Linux:** walk `/proc/[0-9]*/fd/*` and `readlink` each entry. No external
  binary, and same-user processes are visible without root — which is all that
  matters, since Claude Code runs as the invoking user. `PermissionError` and
  `FileNotFoundError` on individual entries are normal (racing processes,
  other users' pids); skip them silently. Only return `None` if `/proc` itself
  is absent or unreadable.
- **macOS:** `/proc` does not exist. Use `lsof`, which ships with the OS at
  `/usr/sbin/lsof`. Call it **once for the whole set**, not once per file:
  `lsof -t -- path1 path2 …` and map the exit status. `lsof` exits non-zero
  when nothing holds any of the paths, which is a normal result, not an error —
  distinguish that from a failure to run at all.
- **Both:** wrap in `try/except` returning `None`, and pass a `timeout=` to
  `subprocess.run`. A hung `lsof` must not hang a redaction.
- Resolve symlinks on both sides before comparing (`Path.resolve()`), or a
  symlinked `~/.claude` will silently never match.

Note the sandbox caveat found while investigating this: inside a restricted
environment `ps`/`/proc` may show no userspace processes at all, so the scan
returns empty rather than failing. That is a real "unknown" the code cannot
detect — which is another reason the fallback must stay conservative, and a
reason not to advertise the check as authoritative in the docs.

## 6. Phase 2 — rewire `is_active`

Keep the signature and the name; both call sites keep working unchanged. New
precedence, top to bottom:

| # | Condition | Result |
|---|---|---|
| 1 | `path.stem == $CLAUDE_SESSION_ID` | **active** (exact, unchanged) |
| 2 | holder check says *held* | **active** |
| 3 | holder check says *unknown* (`None`) | fall through to the mtime window |
| 4 | holder check says *not held* | **not active**, regardless of mtime |
| 5 | `stat()` raises | not active (unchanged) |

Row 4 is the whole point of the change, and under the "held only mid-turn"
outcome from Phase 0 it must be dropped — in that case unknown *and* not-held
both fall through to the window.

Batch the probe. `_do_redact` (`claude_redact.py:1965`) and `main`
(`claude_redact.py:2063`) both evaluate `is_active` over a list, so add an
optional pre-computed holder set parameter, or compute it once per run and
cache it. Spawning `lsof` once per candidate transcript on a host with hundreds
of them would be slower than the redaction itself.

Also improve the message at `claude_redact.py:2005` while you are in there:
say *why* the file reads as live — "held open by pid 4123" vs "written 41s
ago" are different problems with different fixes, and the current text covers
both with one sentence.

## 7. Phase 3 — tests

`tests/test_claude_redact.py`, 210 stdlib `unittest` tests, run with:

```sh
python3 -m unittest discover -s tests
```

The existing fixture `self.transcript(..., age=0)` fakes liveness purely by
mtime, so **these four tests will change meaning** under row 4 and must be
revisited (line numbers as of `5cd4ad9`):

| Line | Test |
|---|---|
| 1726 | `test_live_session_is_refused_without_force` |
| 1736 | `test_unrelated_live_session_does_not_warn_during_redact` |
| 1747 | `test_live_target_still_warns_during_redact` |
| 1755 | `test_force_redacts_a_live_session` |

The clean way to keep them honest, and it is cross-platform: **have the test
process hold the fd itself.**

```python
with open(t, "rb"):          # this pid now holds the transcript open
    code, _, err = self.run_cli([...])
```

That exercises the real code path on both Linux and macOS with no mocking. Add:

- fresh mtime + no holder → **not** refused (the regression this whole plan is about)
- fresh mtime + holder → refused
- old mtime + holder → refused
- `_holders` returns `None` → falls back to the window, refused (patch the
  helper directly for this one)
- `--force` still overrides every case above
- `$CLAUDE_SESSION_ID` match is still refused with no holder and an old mtime

Keep `TempTree.setUp`'s pinning of `CLAUDE_PROFILE_SCRIPT` — tests must never
reach a real `~/.claude`, and this suite scans real transcripts if you let it.

## 8. Phase 4 — docs

`AGENTS.md` is the contributor-facing description of the code and the repo has
a history of it drifting (`3293289 Bring AGENTS.md back in line with the code`).
Update all of:

- `AGENTS.md:260` — "**Refuse a live session** unless forced" — describe the
  new two-signal detection and, explicitly, that unknown still refuses.
- `README.md:158` — same, in user-facing terms.
- The `--force` help text at `claude_redact.py:1906`.
- The `is_active` docstring — including whichever Phase 0 outcome you got,
  since that is the reason the precedence is shaped the way it is.

## 9. Phase 5 — ship

```sh
cd ~/.zsh/claude-redact
python3 -m unittest discover -s tests     # all green before committing
git add -A && git commit
git push origin main                      # ask first — this is a public repo
```

Rollout to the rest of the fleet, from the MBA:

```sh
zsh-push            # ssh into each host and run zsh-pull there
```

or on each host individually: `zsh-pull`. Nothing else is needed — quim already
symlinks `~/.local/bin/claude-redact` → `~/.zsh/claude-redact/claude-redact`,
so a fast-forward of the repo *is* the deploy.

Verify on quim afterwards:

```sh
claude-redact --from-dir ~/code/autotag-bridge --redact --dry-run
```

Expected: it names the three transcripts holding `MQTT_PASSWORD` and does not
error, with no live session running.

## 10. Guardrails

- **Fail safe.** Every new failure mode — no `/proc`, no `lsof`, timeout,
  permission denied, unparseable output — must end at the existing mtime
  window, not at "clean". A false "not active" corrupts a live transcript; a
  false "active" costs one `--force`. The asymmetry is the entire design.
- **Do not remove `--force`.** It stays the escape hatch when the new check is
  wrong in the other direction.
- **Do not let the probe slow the common path.** One batched call per run.
- **Sequence matters:** Phase 0 first. If the fd is not held while idle, most
  of Phases 1–3 is wasted work and the fallback in Phase 0 is the deliverable.
