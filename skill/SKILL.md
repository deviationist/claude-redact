---
name: redact-transcript
description: >-
  Remove a credential that has leaked into Claude Code's local transcripts using
  claude-redact. Use immediately after reading or printing a secret into the
  conversation - from a .env, docker compose config, msmtprc, docker inspect,
  SSH output, or any command that echoed a password, token or key. Also use when
  the user says something was secret, asks to redact or scrub it, asks whether a
  credential is in the logs, or wants an audit of what secrets are sitting in
  ~/.claude. Trigger phrases include 'redact', 'scrub that', 'that was a
  secret', 'did that leak', 'is that in the logs', 'claude-redact'.
---

# redact-transcript

A credential just landed in a transcript. `claude-redact` removes it. This file
exists because the improvised alternative — writing a throwaway Python script,
then pressing the user to rotate — is worse on both counts.

## Do not

- **Do not write a one-off script.** The tool exists, is tested, and handles
  JSON-escaped values, in-place rewriting and verification. A `sed` one-liner
  gets all three wrong.
- **Do not open with rotation.** Most leaked values are internal and sit behind
  other controls. Risk-tiering is the user's call, not yours. See
  [When rotation genuinely applies](#when-rotation-genuinely-applies).
- **Do not repeat the value** while explaining what happened. That writes it to
  the transcript a second time.
- **Do not put the value in a command line.** It lands in shell history and in
  `ps`. Use `--from-file`, `--from-dir`, or `--value -` reading stdin.

## Say this once

Redaction does **not** un-send anything: a value in a transcript already went to
the API with that request. What it fixes is local persistence — future sessions
re-reading it, and backups or syncs carrying it. Say that once, plainly, and
move on.

## Decide which branch you are in

**The leak is in a past or other session** → run it yourself. There is no race,
and with `--from-file` the value never enters your context or the command line.

```bash
claude-redact --from-dir <project> --redact --dry-run   # look first
claude-redact --from-dir <project> --redact             # then apply
```

**The leak is in the session you are in right now** → hand the user one line and
stop. Do not run it. Three reasons, and state the second:

1. Claude Code holds the transcript open for append.
2. Your context still holds the value, so compaction or another quote can write
   it back after the pass runs — the result is best-effort.
3. Every tool call you make appends to the file you are trying to clean.

```bash
# run after exiting this session
claude-redact --from-dir <project> --redact
```

The genuine remedy for the value still being in your context is ending the
session. Say so if it matters; do not belabour it.

## Choosing the input

| Situation | Command |
|---|---|
| Value is in a config file on this machine | `--from-file <file>` or `--from-dir <dir>` |
| Config lives on another host | see [Across hosts](#across-hosts) |
| User knows the value | `--value -` then paste, Ctrl-D |
| Nobody knows what leaked | `--discover --all` |
| Auditing a machine | `claude-redact --discover --all` |

`--from-dir` is preferred: the tool reads the values itself, so nothing
sensitive passes through your context, the shell history, or `ps`.

## Across hosts

**Redaction happens where the transcript is, which is often not where the
config is.** Reading a remote file over SSH puts the value in the *local*
transcript, so `--from-dir` pointed at a local project finds nothing — there is
no local file holding that value to extract it from.

Two ways round it, in order of preference:

```bash
# 1. let the remote host extract its own values, and redact locally by value
ssh <host> "grep -h '^SOME_KEY=' <path>/.env | cut -d= -f2-" \
  | claude-redact --value - --redact

# 2. or, if claude-redact is installed there, redact on the host that has both
ssh <host> "cd <project> && claude-redact --redact --dry-run"
```

Never interpolate the value into a command you then run. It belongs on stdin.

## Stopping the next one

The leak you just cleaned did not have to happen. When about to read something
that may hold credentials — a `.env`, `docker compose config`, `docker inspect`,
`msmtprc`, an app log — pipe it through the filter instead:

```bash
ssh <host> 'cat /srv/app/.env' | claude-redact --filter
docker compose config            | claude-redact --filter
```

Key names survive, values do not:

```
MYSQL_ROOT_PASSWORD=[REDACTED:MYSQL_ROOT_PASSWORD]
TZ=Europe/Oslo
```

That is almost always enough. **You rarely need a credential's value — you need
to know it exists and what it is called**, which is all it takes to write a
command that dereferences it on the remote side:

```bash
ssh <host> 'docker exec -i db mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "SHOW DATABASES"'
```

Suggest the filter once, after cleaning up. Do not lecture about it.

## Reading the result

`redact` verdicts are acted on; `review` needs `--include-review`. A `skip` with
a stated reason is the classifier working, not a miss. The verify pass re-scans
the whole config dir afterwards — if it reports leftovers, say so plainly rather
than declaring success.

If the tool is not installed: https://github.com/deviationist/claude-redact

## When rotation genuinely applies

Raise rotation only in these cases, and then say it once:

- The value reached a **git repo others pull from** — local redaction does
  nothing about history already on other machines.
- It is a **third-party credential** whose blast radius is not local: a cloud
  provider key, a GitHub PAT, a payment or mail provider token.
- The user asks.

Otherwise, clean it up and let the user decide.
