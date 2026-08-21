#!/usr/bin/env python3
"""
claude-redact - remove a leaked credential from Claude Code's local state.

Claude Code stores every session as plaintext JSONL under ~/.claude/projects/.
When an agent reads a config file, the tool result is persisted verbatim, so a
credential printed once stays on disk indefinitely and is re-read on /resume.

This removes it. It does NOT un-send anything: by the time a value is in the
transcript it has already gone to the API. The purpose is local hygiene -
stopping the value being re-read, backed up, or synced.

The rewrite is destructive and there is no undo. See README.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

__version__ = "0.1.0"

CLAUDE_HOME = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
STATE_DIR = Path(
    os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")
) / "claude-redact"
JOURNAL = STATE_DIR / "journal.jsonl"

# Directories under CLAUDE_HOME swept by --all, in rough order of likelihood.
SWEEP_DIRS = (
    "projects",
    "file-history",
    "history.jsonl",
    "paste-cache",
    "shell-snapshots",
    "backups",
    "debug",
    "todos",
)

# Never descend into these - large, binary, or vendored.
SKIP_DIR_NAMES = {".git", "node_modules", "__pycache__", "plugins", "cache"}

MAX_SCAN_BYTES = 64 * 1024 * 1024  # per-file ceiling for the verify sweep

# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

# Key names that strongly imply the value is a credential. The alternation is
# kept separate from the surrounding anchors so user patterns can extend it -
# see configure() and load_user_config().
_SECRET_KEY_BASE = (
    r"pass(?:wd|word)?|pwd|secret|token|api_?key|apikey|access_?key|"
    r"private_?key|privkey|credential|auth|bearer|session_?key|"
    r"encryption_?key|signing_?key|salt|seed|nonce|otp|totp|"
    r"client_?secret|refresh_?token|sas|dsn|conn(?:ection)?_?str"
)

# Key names that almost never hold a credential. Checked after the secret
# pattern, so API_KEY_TIMEOUT still classifies as secret-ish; that is the safe
# direction.
_BENIGN_KEY_BASE = (
    r"port|host|hostname|addr|address|url|uri|path|dir|file|name|user(?:name)?|"
    r"tz|timezone|lang|locale|log_?level|debug|env|environment|version|"
    r"puid|pgid|uid|gid|umask|timeout|retries|interval|enabled?|disabled?|"
    r"driver|dialect|scheme|protocol|type|mode|format|charset|collation|"
    # compose/k8s structural keys - the leaf names a knob, never a secret
    r"image|command|entrypoint|container_name|volumes|networks|ports|"
    r"depends_on|restart|labels|cap_add|cap_drop|devices|healthcheck|"
    r"working_dir|profiles|replicas|platform|pull_policy|shm_size|"
    # build/toolchain knobs: rustflags, ldflags, compiler args, linker targets
    r"rustflags|cflags|cxxflags|ldflags|cppflags|flags|args|argv|opts|options|"
    r"linker|rpath|target|features|toolchain|edition|runner|incremental|"
    # cloud resource identifiers - names of things, not keys to them
    r"bucket|region|endpoint|account_?id|zone|project_?id|namespace|cluster"
)

# Structural containers whose *entire subtree* is configuration, never secrets.
# Applied to any segment of the key path, unlike the leaf-only checks above.
# `environment` and `labels` are deliberately NOT here: they hold arbitrary
# user keys, so a secret ancestor rule would mask real credentials beneath them.
_BENIGN_SUBTREE_BASE = (
    r"depends_on|healthcheck|deploy|logging|ulimits|sysctls|extra_hosts|"
    r"blkio_config|resources|dns|tmpfs|configs|placement|update_config"
)
BENIGN_SUBTREE_RE = re.compile(
    r"(?:^|[._\-/])(?:" + _BENIGN_SUBTREE_BASE + r")(?:$|[._\-/])", re.IGNORECASE
)


def _key_regex(base: str, extra: Sequence[str] = ()) -> "re.Pattern[str]":
    alternation = "|".join([base, *[e for e in extra if e]])
    return re.compile(
        r"(?:^|[._\-/])(?:" + alternation + r")(?:$|[._\-/])", re.IGNORECASE
    )


SECRET_KEY_RE = _key_regex(_SECRET_KEY_BASE)
BENIGN_KEY_RE = _key_regex(_BENIGN_KEY_BASE)

# Values that are common words or enum-ish, never worth redacting on their own.
STOPLIST = {
    "true", "false", "yes", "no", "on", "off", "none", "null", "nil", "auto",
    "root", "admin", "administrator", "user", "guest", "test", "example",
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "default", "public", "private",
    "debug", "info", "warn", "warning", "error", "trace", "fatal", "silent",
    "development", "production", "staging", "local", "utf8", "utf-8", "utf8mb4",
    "always", "never", "unless-stopped", "bridge", "host", "latest", "stable",
    "postgres", "mysql", "mariadb", "redis", "sqlite", "mongodb",
}

# Value shapes that are structurally never a secret.
NUMERIC_RE = re.compile(r"^[\d.:+\-]+$")
DURATION_RE = re.compile(r"^\d+(?:ms|s|m|h|d|w|[kmgt]i?b?)$", re.IGNORECASE)
PATH_RE = re.compile(r"^(?:\.{0,2}/|~/|[a-z]:\\)")
TZ_RE = re.compile(r"^[A-Z][a-z]+/[A-Z]")
IMAGE_REF_RE = re.compile(r"^[a-z0-9._\-]+(?:/[a-z0-9._\-]+)+:[a-z0-9._\-]+$")
# Docker volume/bind specs: "named_vol:/in/container", "/on/host:/in/container".
VOLUME_SPEC_RE = re.compile(r"^[\w./\-${}]+:/[\w./\-]+(?::(?:ro|rw|z|Z|r?slave|r?shared))?$")
# Linux capability lists (cap_add), e.g. NET_ADMIN or SYS_ADMIN,NET_RAW.
CAP_LIST_RE = re.compile(r"^[A-Z][A-Z_]{2,}(?:,[A-Z][A-Z_]{2,})*$")
SEMVER_RE = re.compile(r"^v?\d+\.\d+(?:\.\d+)?(?:[.\-+][\w.\-]+)?$")


CONFIG_FILENAME = "config.ini"
LOCAL_CONFIG = ".claude-redact.ini"


def config_paths() -> list[Path]:
    """User config, then a per-project override in the working directory."""
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return [xdg / "claude-redact" / CONFIG_FILENAME, Path.cwd() / LOCAL_CONFIG]


def load_user_config() -> dict[str, list[str]]:
    """Read extra key patterns and stoplist values from config files.

        [keys]
        # regex alternatives, added to the built-in credential key names
        secret = pwd|vault|kms|licence
        # added to the built-in benign key names
        benign = mount|replica

        [values]
        # never treated as credentials, one per line or comma separated
        stoplist = mycorp, internal.example
    """
    import configparser

    out: dict[str, list[str]] = {"secret": [], "benign": [], "stoplist": []}
    for path in config_paths():
        if not path.is_file():
            continue
        cp = configparser.ConfigParser(interpolation=None)
        try:
            cp.read_string(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            warn(f"ignoring malformed config {path}: {exc}")
            continue
        if cp.has_option("keys", "secret"):
            out["secret"].append(cp.get("keys", "secret").strip())
        if cp.has_option("keys", "benign"):
            out["benign"].append(cp.get("keys", "benign").strip())
        if cp.has_option("values", "stoplist"):
            raw = cp.get("values", "stoplist")
            out["stoplist"].extend(
                v.strip().lower()
                for v in re.split(r"[,\n]", raw)
                if v.strip()
            )
    return out


def configure(
    secret_patterns: Sequence[str] = (),
    benign_patterns: Sequence[str] = (),
    stoplist_values: Sequence[str] = (),
) -> None:
    """Extend the built-in key patterns and stoplist. Never replaces them:
    narrowing detection is the one direction that loses credentials."""
    global SECRET_KEY_RE, BENIGN_KEY_RE, STOPLIST
    for pat in list(secret_patterns) + list(benign_patterns):
        try:
            re.compile(pat)
        except re.error as exc:
            die(f"invalid key pattern {pat!r}: {exc}")
    SECRET_KEY_RE = _key_regex(_SECRET_KEY_BASE, secret_patterns)
    BENIGN_KEY_RE = _key_regex(_BENIGN_KEY_BASE, benign_patterns)
    if stoplist_values:
        STOPLIST = STOPLIST | {v.lower() for v in stoplist_values}


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def charset_classes(value: str) -> int:
    return sum(
        bool(re.search(p, value))
        for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]")
    )


def looks_structural(value: str) -> bool:
    """True when the value's shape rules out a credential."""
    v = value.strip()
    return bool(
        NUMERIC_RE.match(v)
        or DURATION_RE.match(v)
        or PATH_RE.match(v)
        or TZ_RE.match(v)
        or IMAGE_REF_RE.match(v)
        or SEMVER_RE.match(v)
        or VOLUME_SPEC_RE.match(v)
        or CAP_LIST_RE.match(v)
    )


@dataclass
class Candidate:
    """A value that might be a credential, plus everything needed to judge it."""

    key: str
    value: str
    source: str = ""          # masked context line from the origin file
    hits: int = 0             # occurrences across the resolved targets
    files: int = 0            # distinct files containing it
    verdict: str = "skip"     # redact | review | skip
    reason: str = ""
    selected: bool = False

    @property
    def label(self) -> str:
        """Placeholder tag. Sanitised: it gets written into the transcript."""
        key = re.sub(r"[^A-Za-z0-9_.\-]", "_", self.key)[:48]
        return key or "VALUE"

    @property
    def placeholder(self) -> str:
        return f"[REDACTED:{self.label}]"

    @property
    def leaf_key(self) -> str:
        """Final segment of a dotted key path.

        Matching the whole path is wrong: a compose service named `ollama-auth`
        makes every key beneath it - image, cap_add, volumes, container_name -
        look like a credential because the path contains "auth". Only the leaf
        names the value.
        """
        if not self.key:
            return ""
        # Strip list indices first: rustflags[1] must yield "rustflags", not "1]".
        stripped = re.sub(r"\[\d+\]$", "", self.key)
        leaf = stripped.rsplit(".", 1)[-1]
        return leaf or stripped

    def classify(self, min_length: int) -> None:
        """Key name first; entropy only where the key name says nothing.

        Entropy does not discriminate in the middle of its range - measured on
        real data, a genuine password sits at 3.5 while a Rust linker flag sits
        at 3.6, an image reference at 3.5 and a volume spec at 4.0. So it never
        overrides an explicit key name in either direction. It is a tie-breaker
        for keys that carry no meaning, nothing more.

        Skipping a benign-named key outright is safe because composite values are
        decomposed upstream: DATABASE_URL is benign, but the password inside it
        was already extracted as DATABASE_URL.password and judged on its own.
        """
        v = self.value
        low = v.strip().lower()
        ent = entropy(v)

        # --- value is not a secret by form, whatever it is called -------------
        if self.hits == 0:
            self.verdict, self.reason = "skip", "not present"
            return
        if low in STOPLIST:
            self.verdict, self.reason = "skip", "stoplist"
            return
        if looks_structural(v):
            self.verdict, self.reason = "skip", "structural"
            return

        leaf = self.leaf_key
        credential_key = bool(SECRET_KEY_RE.search(leaf))
        benign_key = not credential_key and (
            bool(BENIGN_KEY_RE.search(leaf)) or bool(BENIGN_SUBTREE_RE.search(self.key))
        )

        # A credential key name lowers the length floor - short passwords are
        # real - but a very short value still causes the worst collateral damage.
        floor = 4 if credential_key else min_length
        if len(v) < floor:
            self.verdict, self.reason = "skip", f"under {floor} chars"
            return

        # --- 1. the key name says "credential" -------------------------------
        if credential_key:
            if self.hits > 100 and self.files > 10:
                self.verdict, self.reason = (
                    "review",
                    f"credential key but {self.hits} hits in {self.files} files",
                )
            else:
                self.verdict, self.reason = "redact", "credential key name"
            return

        # --- 2. the key name says "not a credential" -------------------------
        if benign_key:
            self.verdict, self.reason = "skip", "benign key name"
            return

        # --- 3. the key name says nothing: fall back to value signals --------
        # Occurrence count first. It is measured from the user's real files
        # rather than guessed from the value, so it catches low-entropy secrets
        # and, more usefully, stops common words being treated as credentials.
        if self.hits > 25:
            self.verdict, self.reason = "skip", f"{self.hits} hits, too common"
            return
        if ent >= 4.2 and len(v) >= 24 and charset_classes(v) >= 2:
            self.verdict, self.reason = "redact", f"entropy {ent:.1f}"
            return
        self.verdict, self.reason = "review", f"entropy {ent:.1f}, {self.hits} hits"

    def masked(self, prefix: int = 0) -> str:
        n = len(self.value)
        if prefix <= 0:
            return "*" * min(n, 12)
        shown = self.value[:prefix]
        return shown + "*" * min(max(n - prefix, 0), 12)


# ---------------------------------------------------------------------------
# candidate extraction
# ---------------------------------------------------------------------------
#
# Extraction is deliberately over-inclusive. Nothing is written until the user
# confirms, so a false positive costs one keystroke while a miss leaves a live
# credential in a file the user now believes is clean. Structural parsers run
# when the stdlib provides one (better key names for the classifier); the
# generic scanner always runs as well, catching formats we cannot parse (YAML
# without PyYAML) and values a correct parser hands back in the wrong shape.

DOTENV_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$"
)
# Generic `key: value` / `key = value` / `key value` (msmtprc, .netrc, conf).
GENERIC_ASSIGN_RE = re.compile(
    r"^\s*[-#]?\s*([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*(.+?)\s*$"
)
SPACE_ASSIGN_RE = re.compile(
    r"^\s*(password|passwordeval|user|login|account|machine|secret|token)\s+(\S.*?)\s*$",
    re.IGNORECASE,
)
# `environment: [- PUID=1000]` in compose gives the whole "PUID=1000" string as
# one value, losing the key name and making it look like a random token. Uppercase
# is required so ordinary values containing '=' (base64 padding) are left alone.
ENV_ASSIGN_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$", re.DOTALL)
QUOTED_RE = re.compile(r"""(['"])((?:(?!\1)[^\\]|\\.){6,})\1""")
URL_CRED_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://([^/\s:@]+):([^/\s@]+)@")
BASIC_AUTH_RE = re.compile(r"\bBasic\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE)


def _unquote(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        inner = raw[1:-1]
        if raw[0] == '"':
            inner = re.sub(r"\\(.)", r"\1", inner)
        return inner
    # Strip an unquoted trailing comment, but only when preceded by whitespace
    # so that values legitimately containing '#' survive.
    return re.sub(r"\s+#.*$", "", raw).strip()


def _walk_structured(obj, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (dotted.key, value) for every string leaf of a parsed document."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_structured(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk_structured(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix or "value", obj
    elif isinstance(obj, (int, float)) and prefix:
        yield prefix, str(obj)


def _derive_embedded(key: str, value: str) -> Iterator[tuple[str, str]]:
    """Pull credentials out of composite values.

    A parser hands back `mysql://svc:pw@host/db` as one value, but redacting the
    whole URL destroys context worth keeping - only the password should go.
    """
    for user, secret in URL_CRED_RE.findall(value):
        if secret and secret not in ("", "*"):
            yield f"{key}.password", secret
    for blob in BASIC_AUTH_RE.findall(value):
        yield f"{key}.basic", blob
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode(
                "utf-8", "strict"
            )
        except Exception:
            continue
        if ":" in decoded:
            yield f"{key}.basic.password", decoded.split(":", 1)[1]


def _structural_pairs(path: Path, text: str) -> list[tuple[str, str]]:
    """Parse with a real parser when one is available. Never raises."""
    suffix = path.suffix.lower()
    name = path.name.lower()
    pairs: list[tuple[str, str]] = []

    def try_json() -> bool:
        try:
            return bool(pairs.extend(_walk_structured(json.loads(text))) or True)
        except Exception:
            return False

    def try_toml() -> bool:
        try:
            import tomllib
        except ImportError:
            return False
        try:
            return bool(pairs.extend(_walk_structured(tomllib.loads(text))) or True)
        except Exception:
            return False

    def try_yaml() -> bool:
        try:
            import yaml  # optional; absent by default on macOS
        except ImportError:
            return False
        try:
            docs = list(yaml.safe_load_all(text))
        except Exception:
            return False
        for doc in docs:
            pairs.extend(_walk_structured(doc))
        return True

    def try_ini() -> bool:
        import configparser

        cp = configparser.ConfigParser(
            strict=False, interpolation=None, allow_no_value=True
        )
        try:
            cp.read_string(text)
        except Exception:
            return False
        for section in cp.sections():
            for k, v in cp.items(section):
                if v:
                    pairs.append((f"{section}.{k}", v))
        return bool(pairs)

    def try_netrc() -> bool:
        machine = ""
        for line in text.splitlines():
            toks = line.split()
            for i, tok in enumerate(toks[:-1]):
                low = tok.lower()
                if low == "machine":
                    machine = toks[i + 1]
                elif low in ("password", "login", "account"):
                    pairs.append((f"{machine or 'netrc'}.{low}", toks[i + 1]))
        return bool(pairs)

    if suffix == ".json" or name in ("composer.json", "package.json"):
        try_json()
    elif suffix == ".toml":
        try_toml()
    elif suffix in (".yaml", ".yml"):
        try_yaml()
    elif "netrc" in name:
        # Must precede the endswith("rc") branch below - ".netrc" matches both,
        # and the INI parser silently yields nothing for netrc's syntax.
        try_netrc()
    elif suffix in (".ini", ".cfg", ".conf", ".properties") or name.endswith("rc"):
        try_ini()
    elif not suffix or suffix in (".env", ".envrc") or name.startswith(".env"):
        pass  # dotenv is handled by the line scanner below
    else:
        # Unknown extension - try the cheap structured parsers opportunistically.
        try_json() or try_toml() or try_yaml()

    return pairs


def _line_pairs(text: str) -> list[tuple[str, str]]:
    """Line-oriented scan: dotenv, msmtprc, .netrc, YAML, and anything else."""
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        m = DOTENV_RE.match(line)
        if m:
            pairs.append((m.group(1), _unquote(m.group(2))))
            continue
        m = SPACE_ASSIGN_RE.match(line)
        if m:
            pairs.append((m.group(1), _unquote(m.group(2))))
            continue
        m = GENERIC_ASSIGN_RE.match(line)
        if m:
            pairs.append((m.group(1), _unquote(m.group(2))))
    return pairs


def _quoted_strings(text: str) -> list[tuple[str, str]]:
    out = []
    for _, body in QUOTED_RE.findall(text):
        body = re.sub(r"\\(.)", r"\1", body)
        out.append(("quoted", body))
    return out


def extract_candidates(path: Path, min_length: int) -> list[Candidate]:
    """Every plausible secret in a config file, over-inclusive by design."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        die(f"cannot read {path}: {exc}")

    pairs = _structural_pairs(path, text)
    pairs += _line_pairs(text)
    pairs += _quoted_strings(text)

    # Split list-form env assignments into real key/value pairs. Substituted
    # rather than added: redacting the whole "PUID=1000" string would be wrong.
    split_pairs: list[tuple[str, str]] = []
    for key, value in pairs:
        m = ENV_ASSIGN_RE.match(value.strip())
        split_pairs.append((m.group(1), m.group(2)) if m else (key, value))
    pairs = split_pairs

    for key, value in list(pairs):
        pairs.extend(_derive_embedded(key, value))

    # Map value -> best key name. A strong key name wins so the classifier and
    # the [REDACTED:KEY] placeholder both get the most informative label.
    best: dict[str, str] = {}
    for key, value in pairs:
        value = value.strip()
        if not value or len(value) < 3:
            continue
        if any(unicodedata.category(c)[0] == "C" for c in value):
            continue
        prev = best.get(value)
        if prev is None:
            best[value] = key
        elif SECRET_KEY_RE.search(key) and not SECRET_KEY_RE.search(prev):
            best[value] = key
        elif prev == "quoted" and key != "quoted":
            best[value] = key

    # Context line for the confirm table, with the value masked out.
    lines = text.splitlines()
    contexts: dict[str, str] = {}
    for value in best:
        for line in lines:
            if value in line:
                masked = line.replace(value, "*" * min(len(value), 12)).strip()
                contexts[value] = masked[:60]
                break

    cands = [
        Candidate(key=k, value=v, source=contexts.get(v, ""))
        for v, k in best.items()
    ]
    cands.sort(key=lambda c: (-len(c.value), c.key))
    return cands


# ---------------------------------------------------------------------------
# terminal helpers
# ---------------------------------------------------------------------------

_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def die(msg: str, code: int = 2) -> "None":
    print(f"{_c('1;31', 'error:')} {msg}", file=sys.stderr)
    raise SystemExit(code)


def warn(msg: str) -> None:
    print(f"{_c('1;33', 'warning:')} {msg}", file=sys.stderr)


def info(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# target resolution
# ---------------------------------------------------------------------------


def encode_cwd(path: Path) -> str:
    """Claude Code's project-dir encoding: '/' and '.' both become '-'."""
    return re.sub(r"[/.]", "-", str(path))


def _newest(paths: Sequence[Path]) -> Path | None:
    existing = [p for p in paths if p.is_file()]
    if not existing:
        return None
    return max(existing, key=lambda p: p.stat().st_mtime)


def session_of(transcript: Path) -> str:
    return transcript.stem


def session_targets(transcript: Path) -> list[Path]:
    """Every file belonging to one session.

    Beyond the .jsonl itself there are two sibling locations, both confirmed on
    a live host and both easy to miss:

      projects/<slug>/<uuid>/subagents/agent-*.jsonl   subagent transcripts
      projects/<slug>/<uuid>/tool-results/*            raw tool output on disk

    The second is where a large `cat .env` result ends up, so omitting it would
    leave the credential behind while reporting the session clean.
    """
    uuid = session_of(transcript)
    out = [transcript]
    out.extend(iter_files(transcript.parent / uuid))
    out.extend(iter_files(CLAUDE_HOME / "file-history" / uuid))
    return out


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


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                if p.stat().st_size > MAX_SCAN_BYTES:
                    warn(f"skipping oversized file: {p}")
                    continue
            except OSError:
                continue
            yield p


def resolve_targets(args: argparse.Namespace) -> list[Path]:
    """Which files this run looks at. --all sweeps everything under CLAUDE_HOME."""
    targets: list[Path] = []

    if args.all:
        for name in SWEEP_DIRS:
            targets.extend(iter_files(CLAUDE_HOME / name))
    elif args.session:
        matches = list((CLAUDE_HOME / "projects").glob(f"*/{args.session}.jsonl"))
        if not matches:
            die(f"no transcript found for session {args.session}")
        for m in matches:
            targets.extend(session_targets(m))
    else:
        proj = CLAUDE_HOME / "projects" / encode_cwd(Path.cwd().resolve())
        newest = _newest(list(proj.glob("*.jsonl"))) if proj.is_dir() else None
        if args.here and newest is not None:
            targets.extend(session_targets(newest))
        else:
            if args.here:
                warn("no transcripts for this directory - sweeping everything")
            # Default: the whole tree. Two reasons, both measured on real data.
            #
            # A credential defined in one project is routinely leaked by a
            # session run somewhere else: values from a project .env turned up
            # in 24 and 54 unrelated transcripts on a live host.
            #
            # More subtly, the "too common" signal is relative to the corpus
            # scanned, so a narrow scope has too little evidence to dismiss
            # ordinary tokens - scoping down produced MORE false positives than
            # a full sweep, which is the opposite of what a user expects.
            for name in SWEEP_DIRS:
                targets.extend(iter_files(CLAUDE_HOME / name))

    for extra in args.path or []:
        p = Path(extra).expanduser()
        if not p.exists():
            die(f"--path does not exist: {p}")
        targets.extend(iter_files(p))

    # de-duplicate, preserve order
    seen: set[Path] = set()
    out = []
    for p in targets:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------
#
# Transcripts are JSONL, so a value containing a quote or backslash is stored
# escaped. Counting raw bytes would miss those, which is the silent-failure
# direction. Each line is parsed and its decoded strings searched instead;
# non-JSON lines fall back to a raw search.


def _strings_in(obj) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _strings_in(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings_in(v)


# A value survives JSON encoding unchanged unless it contains characters the
# encoder escapes. For those - the vast majority - the raw file text can be
# searched directly, skipping the parse entirely. Values that WOULD be escaped
# force the slow, correct path for that file, because a missed hit is the one
# failure direction that matters.
_NEEDS_PARSE_RE = re.compile(r'["\\\x00-\x1f]')


def _values_regex(values: Sequence[str]) -> "re.Pattern[str] | None":
    """One alternation instead of N passes. Longest-first so the most specific
    value wins where one is a substring of another."""
    if not values:
        return None
    ordered = sorted(set(values), key=len, reverse=True)
    return re.compile("|".join(re.escape(v) for v in ordered))


def count_in_file(
    path: Path,
    values: Sequence[str],
    pattern: "re.Pattern[str] | None" = None,
) -> dict[str, int]:
    """Occurrences of each value in one file. JSON-aware for .jsonl."""
    counts = {v: 0 for v in values}
    pattern = pattern or _values_regex(values)
    if pattern is None:
        return counts
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return counts

    needs_parse = path.suffix == ".jsonl" and any(
        _NEEDS_PARSE_RE.search(v) for v in values
    )

    if not needs_parse:
        # Fast path: one regex pass over the raw bytes of the file.
        for m in pattern.finditer(raw):
            counts[m.group(0)] += 1
        return counts

    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            for m in pattern.finditer(line):
                counts[m.group(0)] += 1
            continue
        for s in _strings_in(doc):
            for m in pattern.finditer(s):
                counts[m.group(0)] += 1
    return counts


@dataclass
class ScanResult:
    counts: dict[str, int] = field(default_factory=dict)
    locations: dict[str, list[Path]] = field(default_factory=dict)
    files_scanned: int = 0
    bytes_scanned: int = 0


def scan(targets: Sequence[Path], values: Sequence[str]) -> ScanResult:
    res = ScanResult(counts={v: 0 for v in values}, locations={v: [] for v in values})
    pattern = _values_regex(values)
    for path in targets:
        res.files_scanned += 1
        try:
            res.bytes_scanned += path.stat().st_size
        except OSError:
            pass
        for value, n in count_in_file(path, values, pattern).items():
            if n:
                res.counts[value] += n
                res.locations[value].append(path)
    return res


# ---------------------------------------------------------------------------
# config-file discovery
# ---------------------------------------------------------------------------
#
# Auditing one .env at a time misses the point: a project's secrets are spread
# across compose files, tfvars, and framework configs. This walks a tree and
# collects everything worth extracting from.
#
# Note it deliberately does NOT honour .gitignore - a gitignored file is more
# likely to hold live credentials, not less. That is usually why it is ignored.

CONFIG_GLOBS = (
    ".env", ".env.*", "*.env",
    "docker-compose.yml", "docker-compose.yaml", "docker-compose.*.yml",
    "docker-compose.*.yaml", "compose.yml", "compose.yaml", "compose.*.yml",
    "*.tfvars", "*.tfvars.json",
    "credentials.json", "credentials.yml", "credentials.yaml",
    "secrets.json", "secrets.yml", "secrets.yaml", "secrets.toml",
    ".netrc", "_netrc", ".pgpass", ".my.cnf", "msmtprc", ".msmtprc",
    "passwd", "pwfile", "password_file", "htpasswd", ".htpasswd",
    ".npmrc", ".pypirc", ".dockercfg", ".boto",
    "application.properties", "application.yml", "application.yaml",
    "settings.py", "local_settings.py", "wp-config.php",
    "config.json", "config.yml", "config.yaml", "config.toml",
    "appsettings.json", "appsettings.*.json",
)

# Whole-file secrets: nothing to extract key/value pairs from, but their
# presence is worth reporting so the user knows they exist.
OPAQUE_GLOBS = ("*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519", "id_ecdsa")

# Template files carry placeholder values by definition. Excluded by default;
# --include-examples brings them back for the rarer case of a real secret having
# been committed into one.
EXAMPLE_GLOBS = (
    "*.example", "*.example.*", "*.sample", "*.sample.*",
    "*.template", "*.tmpl", "*.dist", "*.default",
)

IGNORE_FILENAME = ".claude-redactignore"

CONFIG_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "dist", "build", "target", ".next", ".cache", ".terraform", "site-packages",
}


def load_ignore_globs(root: Path) -> list[str]:
    """Globs from a .claude-redactignore file at the root of a scanned tree."""
    f = root / IGNORE_FILENAME
    if not f.is_file():
        return []
    out = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def find_config_files(
    root: Path,
    max_depth: int = 6,
    exclude: Sequence[str] = (),
    include_examples: bool = False,
) -> tuple[list[Path], list[Path]]:
    """Return (parseable configs, opaque key files) beneath root."""
    import fnmatch

    skip_globs = list(exclude) + load_ignore_globs(root)
    if not include_examples:
        skip_globs += list(EXAMPLE_GLOBS)

    configs: list[Path] = []
    opaque: list[Path] = []
    root = root.resolve()
    root_depth = len(root.parts)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        if len(here.parts) - root_depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in CONFIG_SKIP_DIRS]
        for name in filenames:
            path = here / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > 4 * 1024 * 1024:
                    continue
            except OSError:
                continue
            rel = str(path.relative_to(root))
            if any(
                fnmatch.fnmatch(name, g) or fnmatch.fnmatch(rel, g)
                for g in skip_globs
            ):
                continue
            if any(fnmatch.fnmatch(name, g) for g in CONFIG_GLOBS):
                configs.append(path)
            elif any(fnmatch.fnmatch(name, g) for g in OPAQUE_GLOBS):
                opaque.append(path)

    configs.sort()
    opaque.sort()
    return configs, opaque


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
#
# Known-value scanning only finds what you point it at, which misses every leak
# whose source was not a config file - Bash stdout, `docker inspect`, something
# pasted once. Discovery looks for credential *shapes* instead.
#
# Deliberately shape-based, not entropy-based: transcripts are full of git SHAs,
# UUIDs, base64 blobs and minified code, so an entropy threshold produces noise
# that buries the real findings. These patterns are near-zero false positive.

# These patterns must not match inside a longer word: "sk-" otherwise matches
# "ta{sk-8...}" in a git branch name and "ma{sk-i}mage" in Tailwind classes,
# which produced hundreds of false positives on a real transcript tree.
#
# The check is applied in Python after matching rather than as a (?<!...)
# lookbehind in the pattern. A leading lookbehind defeats CPython's literal
# prefix scan, costing ~5s per pattern over 554 MB - negligible alone, but 70s
# across the fourteen patterns that need it. Checking one character at match
# time is free, because matches are rare.
BOUNDARY_KINDS = frozenset({
    "aws_access_key", "github_pat", "github_fine_grained", "gitlab_pat",
    "anthropic_key", "openai_key", "stripe_key", "slack_token", "sendgrid_key",
    "google_api_key", "google_oauth", "npm_token", "digitalocean_pat", "jwt",
})

_WORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)

DISCOVERY_PATTERNS: list[tuple[str, str]] = [
    ("aws_access_key",      r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("github_pat",          r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("github_fine_grained", r"github_pat_[A-Za-z0-9_]{22,}"),
    ("gitlab_pat",          r"glpat-[A-Za-z0-9_\-]{20,}"),
    ("anthropic_key",       r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai_key",          r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    ("stripe_key",          r"[sr]k_(?:live|test)_[A-Za-z0-9]{24,}"),
    ("slack_token",         r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("slack_webhook",       r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ("sendgrid_key",        r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}"),
    ("google_api_key",      r"AIza[0-9A-Za-z_\-]{35}"),
    ("google_oauth",        r"ya29\.[0-9A-Za-z_\-]{20,}"),
    ("npm_token",           r"npm_[A-Za-z0-9]{36}"),
    ("digitalocean_pat",    r"dop_v1_[a-f0-9]{64}"),
    # Upper bounds keep a greedy class from swallowing minified code: a real
    # JWT or bearer token is not 676 characters long.
    ("jwt",                 r"eyJ[A-Za-z0-9_\-]{10,1024}\.eyJ[A-Za-z0-9_\-]{10,1024}\.[A-Za-z0-9_\-]{10,512}"),
    ("private_key_block",   r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ("url_credentials",
     r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@\"']+:"
     r"(?P<url_pw>[^/\s@\"']{4,128})@[^\s\"']+"),
    ("basic_auth_header",   r"[Aa]uthorization[\"']?\s*[:=]\s*[\"']?Basic\s+[A-Za-z0-9+/=]{12,512}"),
    ("bearer_header",       r"[Aa]uthorization[\"']?\s*[:=]\s*[\"']?Bearer\s+[A-Za-z0-9._\-]{20,512}"),
    ("password_assignment",
     # No leading [A-Za-z0-9_.-]* here: it only spanned the key name, which is
     # never captured, and cost 13x in backtracking on every scanned position.
     r"(?i:password|passwd|secret|api[_\-]?key|token)(?![A-Za-z])"
     r"[A-Za-z0-9_.\-]*\s*[:=]\s*[\"']?"
     r"(?P<pw_value>(?![0-9]+(?:[\s\"',;}]|$))[^\s\"',;}{]{8,256})"),
]

# Measured: 20 separate passes beat one big alternation by 3.2x (0.096 vs
# 0.305 s/MB). A multi-branch alternation defeats CPython's literal-prefix
# scan optimisation, so each branch pays full cost at every position; compiled
# individually, most patterns skip ahead on their fixed prefix instead.
_DISCOVERY_COMPILED: list[tuple[str, "re.Pattern[str]"]] = [
    (name, re.compile(pat)) for name, pat in DISCOVERY_PATTERNS
]

# Values that match a pattern but are obviously placeholders, not live secrets.
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:redacted|example|changeme|your[_\-]?|placeholder|xxxx+|\*\*\*|"
    r"<[^>]+>|\{\{[^}]+\}\}|\$\{[^}]+\}|dummy|sample|test[_\-]?key|foo|bar)"
)


# Provider patterns (ghp_, AKIA, AIza...) are unambiguous - a match is a match.
# These four infer from context instead, so they fire on ordinary source code:
# `const token = ...`, `secret = opts?.token ?? x`. They get the noise filters.
LOW_PRECISION_KINDS = frozenset({
    "password_assignment", "bearer_header", "basic_auth_header", "url_credentials",
})

# Values shaped like code rather than credentials.
CODE_SHAPE_RE = re.compile(r"(?:=>|\?\.|\$\{|[(){}\[\]]|::|`)")
CODE_KEYWORDS = frozenset({
    "string", "number", "boolean", "object", "null", "undefined", "void", "any",
    "unknown", "never", "function", "return", "import", "export", "const", "let",
})

# A reference to a secret is not the secret: `api_key: process.env.OPENAI_KEY`
# names where the value lives, and there is nothing there to redact.
CODE_REF_RE = re.compile(
    r"^(?:process\.env|import\.meta\.env|os\.environ|Deno\.env|ENV|env|"
    r"self|this|opts|options|config|settings|secrets|vault)[.\[]",
    re.IGNORECASE,
)

# A credential does not appear in dozens of unrelated files. This is the same
# occurrence-count signal the known-value classifier uses, and it is measured
# from the user's real tree rather than guessed from the value's shape.
NOISE_MIN_HITS = 25
NOISE_MIN_FILES = 3


@dataclass
class Finding:
    kind: str
    sample: str                       # never printed raw; masked at display time
    files: dict[str, int] = field(default_factory=dict)

    @property
    def hits(self) -> int:
        return sum(self.files.values())

    def masked(self, prefix: int = 0) -> str:
        v = self.sample
        head = v[:prefix] if prefix > 0 else ""
        return f"{head}{'*' * min(max(len(v) - prefix, 0), 16)} ({len(v)} chars)"


def discover(targets: Sequence[Path]) -> tuple[list[Finding], ScanResult]:
    """Scan for credential shapes with no reference file."""
    res = ScanResult()
    found: dict[tuple[str, str], Finding] = {}

    def consider(kind: str, text: str, path: Path, secret: str | None = None) -> None:
        """`secret` is the credential portion; `text` may carry context around it.

        The placeholder test must look only at the credential. Matching the whole
        span discards real findings whose *context* happens to contain a word like
        "example" - e.g. postgres://user:realpw@db.example.internal/app.
        """
        if not text or PLACEHOLDER_RE.search(secret if secret is not None else text):
            return
        key = (kind, text)
        f = found.get(key)
        if f is None:
            f = found[key] = Finding(kind=kind, sample=text)
        f.files[str(path)] = f.files.get(str(path), 0) + 1

    show_progress = sys.stderr.isatty() and len(targets) > 200
    for idx, path in enumerate(targets):
        if show_progress and idx % 250 == 0:
            print(
                f"\r  scanning {idx}/{len(targets)} files"
                f" ({human_bytes(res.bytes_scanned)})...",
                end="",
                file=sys.stderr,
                flush=True,
            )
        res.files_scanned += 1
        try:
            res.bytes_scanned += path.stat().st_size
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for kind, rx in _DISCOVERY_COMPILED:
            needs_boundary = kind in BOUNDARY_KINDS
            for m in rx.finditer(raw):
                if (
                    needs_boundary
                    and m.start() > 0
                    and raw[m.start() - 1] in _WORD_CHARS
                ):
                    continue
                secret = None
                if kind == "password_assignment":
                    text = m.group("pw_value")
                elif kind == "url_credentials":
                    text = m.group(0)
                    secret = m.group("url_pw")
                else:
                    text = m.group(0)
                consider(kind, (text or "").strip(), path, secret)

    if show_progress:
        print("\r" + " " * 60 + "\r", end="", file=sys.stderr, flush=True)

    # Patterns run independently, so overlapping ones both fire on the same
    # value (sk-ant-... matches anthropic_key AND openai_key). Keep whichever
    # appears first in DISCOVERY_PATTERNS - that table is ordered most-specific
    # first for exactly this reason.
    def is_noise(f: "Finding") -> bool:
        if f.kind not in LOW_PRECISION_KINDS:
            return False
        if f.hits > NOISE_MIN_HITS and len(f.files) > NOISE_MIN_FILES:
            return True
        v = f.sample
        return bool(
            v.lower() in CODE_KEYWORDS
            or v.lower() in STOPLIST
            or CODE_REF_RE.match(v)
            or CODE_SHAPE_RE.search(v)
            or looks_structural(v)
        )

    for key in [k for k, f in found.items() if is_noise(f)]:
        del found[key]

    rank = {name: i for i, (name, _) in enumerate(DISCOVERY_PATTERNS)}
    by_value: dict[str, Finding] = {}
    for f in found.values():
        prev = by_value.get(f.sample)
        if prev is None or rank[f.kind] < rank[prev.kind]:
            if prev is not None:
                for path_str, n in prev.files.items():
                    f.files[path_str] = f.files.get(path_str, 0) + 0
            by_value[f.sample] = f

    findings = sorted(by_value.values(), key=lambda f: (f.kind, -f.hits))
    return findings, res


def _jsonl_strings(raw: str) -> Iterator[str]:
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            yield line
            continue
        yield from _strings_in(doc)


def report_discovery(findings: Sequence[Finding], res: ScanResult, prefix: int) -> None:
    info(f"scanned {res.files_scanned} file(s), {human_bytes(res.bytes_scanned)}")
    if not findings:
        print(_c("1;32", "clean") + " — no credential-shaped values found")
        return

    print()
    print(f"  {'KIND':<22} {'HITS':>5} {'FILES':>6}  VALUE")
    print(f"  {'-' * 22} {'-' * 5} {'-' * 6}  {'-' * 30}")
    for f in findings:
        print(
            f"  {_c('1;31', f.kind[:22]):<22} {f.hits:>5} {len(f.files):>6}  "
            f"{f.masked(prefix)}"
        )

    print()
    for f in findings[:20]:
        print(f"  {f.kind}:")
        for path, n in sorted(f.files.items(), key=lambda kv: -kv[1])[:5]:
            p = Path(path)
            try:
                shown = Path("~") / p.relative_to(Path.home())
            except ValueError:
                shown = p
            print(f"    {shown}  ({n})")
        if len(f.files) > 5:
            print(f"    ... and {len(f.files) - 5} more file(s)")

    print()
    print(_c("1;31", f"{len(findings)} distinct credential-shaped value(s) found"))


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n / 1:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def report(
    cands: Sequence[Candidate],
    res: ScanResult,
    targets: Sequence[Path],
    show_prefix: int,
    verbose: bool = False,
) -> None:
    present = [c for c in cands if c.hits > 0]
    info(
        f"scanned {res.files_scanned} file(s), "
        f"{human_bytes(res.bytes_scanned)} — {len(cands)} candidate value(s)"
    )

    if not present:
        print(_c("1;32", "clean") + " — no candidate value appears in the scanned files")
        return

    interesting = [c for c in present if c.verdict != "skip"]
    shown = present if verbose else interesting

    if not shown:
        print(
            _c("1;32", "clean")
            + f" — {len(present)} value(s) present but all classified benign"
            + " (--verbose to list them)"
        )
        return

    print()
    print(
        f"  {'KEY':<28} {'LEN':>4} {'ENT':>5} {'HITS':>5} {'FILES':>6}  "
        f"{'VERDICT':<8} REASON"
    )
    print(f"  {'-' * 28} {'-' * 4} {'-' * 5} {'-' * 5} {'-' * 6}  {'-' * 8} {'-' * 20}")
    for c in sorted(shown, key=lambda c: (c.verdict != "redact", c.verdict != "review", -c.hits)):
        colour = {"redact": "1;31", "review": "1;33"}.get(c.verdict, "2")
        print(
            f"  {c.key[:28]:<28} {len(c.value):>4} {entropy(c.value):>5.1f} "
            f"{c.hits:>5} {len(res.locations[c.value]):>6}  "
            f"{_c(colour, c.verdict):<8} {c.reason}"
        )
        if show_prefix:
            print(f"    {'':<28} value: {c.masked(show_prefix)}")

    print()
    for c in interesting:
        locs = res.locations[c.value]
        print(f"  {_c('1', c.key)} in:")
        for p in locs[:8]:
            try:
                shown = p.relative_to(Path.home())
                shown = Path("~") / shown
            except ValueError:
                shown = p
            print(f"    {shown}")
        if len(locs) > 8:
            print(f"    ... and {len(locs) - 8} more")

    print()
    benign = len(present) - len(interesting)
    suffix = f" ({benign} present but classified benign)" if benign else ""
    print(_c("1;31", f"{len(interesting)} value(s) worth attention") + suffix)


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------


def read_values_stdin() -> list[str]:
    if sys.stdin.isatty():
        info("reading values from stdin, one per line; ctrl-d when done")
    return [ln.rstrip("\n") for ln in sys.stdin if ln.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="claude-redact",
        description=(
            "Find (and later remove) credentials that leaked into Claude Code's "
            "local state. This release scans only; it never modifies anything."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  clean - nothing found\n"
            "  1  one or more candidate values present\n"
            "  2  error\n"
        ),
    )
    src = p.add_argument_group("what to look for")
    src.add_argument(
        "--from-file",
        action="append",
        metavar="FILE",
        help="extract candidate secrets from a config file (.env, JSON, YAML, "
        "TOML, INI, netrc, msmtprc, or anything line-oriented). Repeatable.",
    )
    src.add_argument(
        "--from-dir",
        action="append",
        metavar="DIR",
        help="walk a project tree and extract from every config file found "
        "(.env*, compose files, tfvars, netrc, framework configs). Repeatable. "
        "Use --from-file to narrow the run to a single file.",
    )
    src.add_argument(
        "--exclude",
        action="append",
        metavar="GLOB",
        help="skip config files matching GLOB (repeatable). A "
        f"{IGNORE_FILENAME} file at the root of a scanned tree adds more.",
    )
    src.add_argument(
        "--include-examples",
        action="store_true",
        help="also read *.example / *.sample / *.template files, which are "
        "skipped by default as they hold placeholders rather than secrets",
    )
    src.add_argument(
        "--list-sources",
        action="store_true",
        help="with --from-dir: list the config files that would be read, then exit",
    )
    src.add_argument(
        "--discover",
        action="store_true",
        help="no reference file: search for credential shapes (provider key "
        "prefixes, JWTs, PEM blocks, connection strings, PASSWORD= assignments). "
        "Finds leaks whose source was never a config file - Bash output, pastes.",
    )
    src.add_argument(
        "--value",
        action="append",
        metavar="VALUE",
        help="a literal value to look for; use '-' to read from stdin "
        "(preferred - keeps it out of shell history and ps)",
    )

    scope = p.add_argument_group("where to look")
    scope.add_argument("--session", metavar="UUID", help="a specific session id")
    scope.add_argument(
        "--all",
        action="store_true",
        help=f"sweep everything under {CLAUDE_HOME} (this is the default)",
    )
    scope.add_argument(
        "--here",
        action="store_true",
        help="only this directory's newest session. Faster, but note that the "
        "'too common' signal needs a broad corpus to work - a narrow scope "
        "reports more false positives, not fewer",
    )
    scope.add_argument(
        "--path",
        action="append",
        metavar="PATH",
        help="additional file or directory to include (repeatable)",
    )

    tune = p.add_argument_group("tuning")
    tune.add_argument(
        "--key-pattern",
        action="append",
        metavar="REGEX",
        help="extra key names to treat as credentials, e.g. 'vault|kms|licence'. "
        "Added to the built-ins (pass/password/token/secret/api_key/...), never "
        "replacing them. Repeatable.",
    )
    tune.add_argument(
        "--benign-pattern",
        action="append",
        metavar="REGEX",
        help="extra key names to treat as never-credentials. Repeatable.",
    )
    tune.add_argument(
        "--stop-value",
        action="append",
        metavar="VALUE",
        help="a value never to treat as a credential. Repeatable.",
    )
    tune.add_argument(
        "--no-config",
        action="store_true",
        help=f"ignore ~/.config/claude-redact/{CONFIG_FILENAME} and ./{LOCAL_CONFIG}",
    )

    out = p.add_argument_group("output")
    out.add_argument(
        "--min-length",
        type=int,
        default=8,
        metavar="N",
        help="ignore values shorter than N characters (default: 8)",
    )
    out.add_argument(
        "--show-prefix",
        type=int,
        default=0,
        metavar="N",
        help="reveal the first N characters of each value (default: 0). "
        "Anything shown here is written into the transcript you are reading.",
    )
    out.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="also list candidates classified benign (hidden by default)",
    )
    out.add_argument("--json", action="store_true", help="machine-readable output")
    out.add_argument("--version", action="version", version=f"claude-redact {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    cfg = {"secret": [], "benign": [], "stoplist": []}
    if not args.no_config:
        cfg = load_user_config()
    configure(
        secret_patterns=cfg["secret"] + (args.key_pattern or []),
        benign_patterns=cfg["benign"] + (args.benign_pattern or []),
        stoplist_values=cfg["stoplist"] + (args.stop_value or []),
    )

    if not any((args.from_file, args.from_dir, args.value, args.discover)):
        # The overwhelmingly common intent is "audit this project's configs".
        # Requiring --from-dir . to express that is friction for no benefit.
        args.from_dir = ["."]
    if args.discover and (args.from_file or args.from_dir or args.value):
        die("--discover takes no reference values; drop --from-file/--from-dir/--value")
    if args.value and (args.from_file or args.from_dir):
        die("--value cannot be combined with --from-file/--from-dir")

    if args.discover:
        targets = resolve_targets(args)
        if not targets:
            die("no files to scan")
        findings, res = discover(targets)
        if args.json:
            print(json.dumps({
                "mode": "discover",
                "files_scanned": res.files_scanned,
                "bytes_scanned": res.bytes_scanned,
                "findings": [
                    {"kind": f.kind, "length": len(f.sample), "hits": f.hits,
                     "files": sorted(f.files)} for f in findings
                ],
            }, indent=2))
        else:
            report_discovery(findings, res, args.show_prefix)
        return 1 if findings else 0

    # 1. candidate values
    if args.from_file or args.from_dir:
        sources: list[Path] = []
        opaque: list[Path] = []

        for entry in args.from_dir or []:
            root = Path(entry).expanduser()
            if not root.is_dir():
                die(f"not a directory: {root}")
            found, keys = find_config_files(
                root,
                exclude=args.exclude or (),
                include_examples=args.include_examples,
            )
            sources.extend(found)
            opaque.extend(keys)

        for entry in args.from_file or []:
            src = Path(entry).expanduser()
            if not src.is_file():
                die(f"not a file: {src}")
            sources.append(src)

        sources = list(dict.fromkeys(sources))
        if not sources:
            die("no config files found; use --from-file to name one explicitly")

        if args.from_dir:
            info(f"reading {len(sources)} config file(s):")
            for sp in sources:
                info(f"  {sp}")
            if opaque:
                info(
                    f"  ({len(opaque)} key/certificate file(s) found but not parsed - "
                    "whole-file secrets, nothing to extract)"
                )
        if args.list_sources:
            return 0

        cands = []
        seen_values: set[str] = set()
        for src in sources:
            for c in extract_candidates(src, args.min_length):
                if c.value not in seen_values:
                    seen_values.add(c.value)
                    cands.append(c)
        if not cands:
            die("no candidate values extracted from the given file(s)")
    else:
        raw: list[str] = []
        for v in args.value:
            raw.extend(read_values_stdin() if v == "-" else [v])
        raw = [v for v in dict.fromkeys(raw) if v]
        if not raw:
            die("no values supplied")
        cands = [Candidate(key="value", value=v) for v in raw]

    # 2. targets
    targets = resolve_targets(args)
    if not targets:
        die("no files to scan")
    active = [t for t in targets if t.suffix == ".jsonl" and is_active(t)]
    if active:
        warn(
            f"{active[0].name} was modified in the last two minutes and is "
            "probably a live session"
        )

    # 3. scan, then classify using the measured hit counts
    res = scan(targets, [c.value for c in cands])
    for c in cands:
        c.hits = res.counts.get(c.value, 0)
        c.files = len(res.locations.get(c.value, []))
        c.classify(args.min_length)

    # 4. report
    if args.json:
        print(
            json.dumps(
                {
                    "files_scanned": res.files_scanned,
                    "bytes_scanned": res.bytes_scanned,
                    "findings": [
                        {
                            "key": c.key,
                            "length": len(c.value),
                            "entropy": round(entropy(c.value), 2),
                            "hits": c.hits,
                            "files": [str(p) for p in res.locations[c.value]],
                            "verdict": c.verdict,
                            "reason": c.reason,
                        }
                        for c in cands
                        if c.hits > 0
                    ],
                },
                indent=2,
            )
        )
    else:
        report(cands, res, targets, args.show_prefix, args.verbose)

    return 1 if any(c.hits > 0 for c in cands) else 0

