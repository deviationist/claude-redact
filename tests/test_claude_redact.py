#!/usr/bin/env python3
"""Test suite for claude-redact.

Stdlib unittest only - the tool has no dependencies and neither should its tests.

    python3 -m unittest discover -s tests -v
    ./tests/test_claude_redact.py

Every secret in here is fabricated. Several tests are regression guards for bugs
found during development; those are marked with the bug they lock down.
"""

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import claude_redact as cr  # noqa: E402


class TempTree(unittest.TestCase):
    """Base class giving each test an isolated directory tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, relpath: str, content: str) -> Path:
        p = self.root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


class TestEntropy(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(cr.entropy(""), 0.0)

    def test_uniform_string_is_zero(self):
        self.assertEqual(cr.entropy("aaaaaaaa"), 0.0)

    def test_random_beats_repetitive(self):
        self.assertGreater(cr.entropy("Kx7vQm2ZpLr9WtBn"), cr.entropy("aaaabbbbcccc"))

    def test_charset_classes(self):
        self.assertEqual(cr.charset_classes("abc"), 1)
        self.assertEqual(cr.charset_classes("abcABC"), 2)
        self.assertEqual(cr.charset_classes("abcABC123"), 3)
        self.assertEqual(cr.charset_classes("abcABC123!"), 4)


class TestStructuralShapes(unittest.TestCase):
    def test_recognises_non_secrets(self):
        for value in (
            "1000", "8080", "192.168.1.1", "30s", "512mb", "/var/lib/data",
            "./relative/path", "~/home/path", "Europe/Oslo", "America/New_York",
            "lscr.io/linuxserver/plex:latest", "v1.2.3", "2.14.0-beta.1",
        ):
            with self.subTest(value=value):
                self.assertTrue(cr.looks_structural(value), f"{value!r} should be structural")

    def test_does_not_swallow_real_secrets(self):
        for value in (
            "Kx7vQm2ZpLr9WtBn4Hs6", "hunter2pass", "Tr0ub4dor3xKq",
            "zR4tYuIoPaSdFgHjKlZxCvBnM1234567890",
        ):
            with self.subTest(value=value):
                self.assertFalse(cr.looks_structural(value), f"{value!r} must not be structural")


class TestClassification(unittest.TestCase):
    def classify(self, key, value, hits=1, min_length=8):
        c = cr.Candidate(key=key, value=value, hits=hits)
        c.classify(min_length)
        return c

    def test_credential_key_name_wins(self):
        for key in ("MYSQL_PASSWORD", "api_key", "AUTHELIA_JWT_SECRET",
                    "db.password", "CLIENT_SECRET", "ACCESS_TOKEN"):
            with self.subTest(key=key):
                self.assertEqual(self.classify(key, "Kx7vQm2ZpLr9WtBn").verdict, "redact")

    def test_service_name_does_not_credentialise_its_keys(self):
        """Regression: a compose service named `ollama-auth` made every key
        beneath it (image, cap_add, volumes, container_name) score as a
        credential, because "auth" appeared in the dotted path."""
        for key, value in (
            ("services.ollama-auth.image", "ollama/ollama:latest"),
            ("services.ollama-auth.container_name", "ollama-auth"),
            ("services.ollama-auth.cap_add", "NET_ADMIN"),
            ("services.ollama-auth.volumes[0]", "ollama_data:/root/.ollama"),
        ):
            with self.subTest(key=key):
                self.assertEqual(self.classify(key, value, hits=50).verdict, "skip")

    def test_leaf_key_still_detects_real_credentials(self):
        for key in ("services.api.environment.R2_SECRET_KEY",
                    "services.db.environment.POSTGRES_PASSWORD"):
            with self.subTest(key=key):
                self.assertEqual(self.classify(key, "Kx7vQm2ZpLr9WtBn").verdict, "redact")

    def test_compose_structural_keys_are_benign(self):
        for key, value in (("services.mosquitto.image", "eclipse-mosquitto:2"),
                           ("services.mqttx-web.image", "emqx/mqttx-web:latest"),
                           ("services.app.restart", "unless-stopped")):
            with self.subTest(key=key):
                self.assertEqual(self.classify(key, value, hits=20).verdict, "skip")

    def test_structural_subtrees_are_benign(self):
        """`depends_on.postgres.condition = service_healthy` is configuration."""
        c = cr.Candidate(key="services.api.depends_on.postgres.condition",
                         value="service_healthy", hits=18)
        c.classify(8)
        self.assertEqual(c.verdict, "skip")

    def test_environment_subtree_still_yields_secrets(self):
        """environment holds arbitrary keys, so it must NOT mask its children."""
        c = cr.Candidate(key="services.api.environment.R2_SECRET_KEY",
                         value="Kx7vQm2ZpLr9WtBn", hits=3)
        c.classify(8)
        self.assertEqual(c.verdict, "redact")

    def test_cloud_resource_names_are_benign(self):
        for key in ("R2_BUCKET", "BACKUP_R2_BUCKET", "AWS_REGION", "GCP_PROJECT_ID"):
            with self.subTest(key=key):
                c = cr.Candidate(key=key, value="my-app-storage", hits=13)
                c.classify(8)
                self.assertEqual(c.verdict, "skip")

    def test_verdict_column_padding_survives_colour(self):
        """ANSI escapes must not be counted toward the column width."""
        import io, contextlib
        cands = [cr.Candidate(key="K", value="Kx7vQm2ZpLr9WtBn", hits=1)]
        cands[0].classify(8)
        res = cr.ScanResult(counts={"Kx7vQm2ZpLr9WtBn": 1},
                            locations={"Kx7vQm2ZpLr9WtBn": [Path("/x")]},
                            files_scanned=1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cr.report(cands, res, [], 0)
        rows = [l for l in out.getvalue().splitlines() if " redact" in l or " review" in l]
        self.assertTrue(rows)
        for row in rows:
            plain = re.sub(r"\033\[[0-9;]*m", "", row)
            self.assertRegex(plain, r"(redact|review)\s{3,}\S",
                             "verdict column lost its padding")

    def test_docker_volume_specs_are_structural(self):
        for v in ("ollama_data:/root/.ollama", "/srv/data:/data:ro",
                  "./config:/etc/app", "${PWD}/x:/x"):
            with self.subTest(v=v):
                self.assertTrue(cr.looks_structural(v), f"{v!r} should be structural")

    def test_capability_lists_are_structural(self):
        self.assertTrue(cr.looks_structural("NET_ADMIN"))
        self.assertTrue(cr.looks_structural("SYS_ADMIN,NET_RAW"))

    def test_implausible_spread_downgrades_to_review(self):
        c = cr.Candidate(key="AUTH_MODE", value="localhost", hits=447, files=23)
        c.classify(8)
        self.assertEqual(c.verdict, "skip")
        c = cr.Candidate(key="API_SECRET", value="Kx7vQm2ZpLr9", hits=447, files=23)
        c.classify(8)
        self.assertEqual(c.verdict, "review")

    def test_entropy_never_overrides_a_benign_key_name(self):
        """High entropy in an explicitly non-secret key is not a finding."""
        c = self.classify("services.app.volumes[0]", "aZ4tYuIoPaSdFgHjKlZxCvBnM12345", hits=3)
        self.assertEqual(c.verdict, "skip")
        self.assertEqual(c.reason, "benign key name")

    def test_low_entropy_never_overrides_a_credential_key_name(self):
        """A short simple password is still a password."""
        c = self.classify("MYSQL_PASSWORD", "hunter22", hits=2)
        self.assertEqual(c.verdict, "redact")
        self.assertEqual(c.reason, "credential key name")

    def test_entropy_only_applies_when_key_name_is_silent(self):
        c = self.classify("blob", "aZ4tYuIoPaSdFgHjKlZxCvBnM12345", hits=2)
        self.assertEqual(c.verdict, "redact")
        self.assertTrue(c.reason.startswith("entropy"))

    def test_stoplist_values_skipped(self):
        for value in ("admin", "true", "localhost", "postgres", "production"):
            with self.subTest(value=value):
                self.assertEqual(self.classify("SOME_KEY", value).verdict, "skip")

    def test_absent_value_skipped(self):
        c = self.classify("MYSQL_PASSWORD", "Kx7vQm2ZpLr9WtBn", hits=0)
        self.assertEqual(c.verdict, "skip")
        self.assertEqual(c.reason, "not present")

    def test_high_hit_count_blocks_collateral_damage(self):
        """The guard that stopped 'admin' (83,687 hits) rewriting 1,162 files."""
        c = self.classify("CUSTOM_FIELD", "buildkite", hits=5000)
        self.assertEqual(c.verdict, "skip")
        self.assertIn("too common", c.reason)

    def test_high_hits_do_not_override_explicit_credential_key(self):
        c = self.classify("MYSQL_PASSWORD", "Kx7vQm2ZpLr9WtBn", hits=5000)
        self.assertEqual(c.verdict, "redact")

    def test_short_values_skipped(self):
        self.assertEqual(self.classify("GENERIC", "abc123").verdict, "skip")

    def test_credential_key_lowers_length_floor_but_still_reviews(self):
        c = self.classify("PASSWORD", "sh0rt")
        self.assertNotEqual(c.verdict, "skip")

    def test_min_length_is_respected(self):
        self.assertEqual(self.classify("GENERIC", "abcdefgh", min_length=20).verdict, "skip")

    def test_high_entropy_without_key_name_is_caught(self):
        c = self.classify("unknown", "aZ4tYuIoPaSdFgHjKlZxCvBnM12345", hits=2)
        self.assertEqual(c.verdict, "redact")

    def test_benign_key_name_downweighted(self):
        self.assertEqual(self.classify("LOG_LEVEL", "verbose-debug").verdict, "skip")


class TestPlaceholderLabel(unittest.TestCase):
    def test_placeholder_carries_key_name(self):
        c = cr.Candidate(key="MYSQL_PASSWORD", value="x")
        self.assertEqual(c.placeholder, "[REDACTED:MYSQL_PASSWORD]")

    def test_label_is_sanitised(self):
        c = cr.Candidate(key="weird key/with spaces!", value="x")
        self.assertNotIn(" ", c.placeholder)
        self.assertNotIn("!", c.placeholder)

    def test_masked_hides_value_by_default(self):
        c = cr.Candidate(key="K", value="SuperSecretValue123")
        self.assertNotIn("SuperSecret", c.masked())
        self.assertEqual(set(c.masked()), {"*"})

    def test_masked_prefix_reveals_only_requested_chars(self):
        c = cr.Candidate(key="K", value="SuperSecretValue123")
        m = c.masked(prefix=4)
        self.assertTrue(m.startswith("Supe"))
        self.assertNotIn("Secret", m)


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------


class TestDotenvExtraction(TempTree):
    def values(self, path):
        return {c.value for c in cr.extract_candidates(path, 8)}

    def keys_for(self, path, value):
        return {c.key for c in cr.extract_candidates(path, 8) if c.value == value}

    def test_basic_pairs_and_quotes(self):
        p = self.write(".env", "\n".join([
            "PLAIN=Kx7vQm2ZpLr9WtBn",
            'DOUBLE="Zx9KpQm2VnLr7Wtc"',
            "SINGLE='Ax9KpQm2VnLr7Wtd'",
            "export EXPORTED=Bx9KpQm2VnLr7Wte",
        ]))
        vals = self.values(p)
        for expected in ("Kx7vQm2ZpLr9WtBn", "Zx9KpQm2VnLr7Wtc",
                         "Ax9KpQm2VnLr7Wtd", "Bx9KpQm2VnLr7Wte"):
            self.assertIn(expected, vals)

    def test_comments_ignored(self):
        p = self.write(".env", "# COMMENT=NotARealSecretValue\nREAL=Kx7vQm2ZpLr9WtBn")
        self.assertNotIn("NotARealSecretValue", self.values(p))

    def test_inline_comment_stripped_when_unquoted(self):
        p = self.write(".env", "KEY=Kx7vQm2ZpLr9WtBn # trailing note")
        self.assertIn("Kx7vQm2ZpLr9WtBn", self.values(p))

    def test_hash_inside_quoted_value_preserved(self):
        p = self.write(".env", 'PASSWORD="pa#ss#word#123"')
        self.assertIn("pa#ss#word#123", self.values(p))

    def test_secret_key_name_preferred_over_generic(self):
        p = self.write(".env", 'MYSQL_PASSWORD="Kx7vQm2ZpLr9WtBn"')
        self.assertIn("MYSQL_PASSWORD", self.keys_for(p, "Kx7vQm2ZpLr9WtBn"))


class TestStructuredExtraction(TempTree):
    def values(self, path):
        return {c.value for c in cr.extract_candidates(path, 8)}

    def test_json_nested_keys(self):
        p = self.write("config.json", json.dumps(
            {"database": {"password": "Kx7vQm2ZpLr9WtBn", "port": 5432}}))
        cands = cr.extract_candidates(p, 8)
        match = [c for c in cands if c.value == "Kx7vQm2ZpLr9WtBn"]
        self.assertTrue(match)
        self.assertIn("password", match[0].key)

    def test_toml(self):
        p = self.write("config.toml", '[db]\npassword = "Kx7vQm2ZpLr9WtBn"\n')
        self.assertIn("Kx7vQm2ZpLr9WtBn", self.values(p))

    def test_ini(self):
        p = self.write("app.ini", "[db]\npassword = Kx7vQm2ZpLr9WtBn\n")
        self.assertIn("Kx7vQm2ZpLr9WtBn", self.values(p))

    def test_netrc(self):
        p = self.write(".netrc", "machine example.com login bob password Kx7vQm2ZpLr9WtBn\n")
        self.assertIn("Kx7vQm2ZpLr9WtBn", self.values(p))

    def test_msmtprc_space_separated(self):
        p = self.write("msmtprc", "account default\nhost smtp.example.com\npassword Kx7vQm2ZpLr9WtBn\n")
        self.assertIn("Kx7vQm2ZpLr9WtBn", self.values(p))

    def test_compose_list_form_environment_splits_into_pairs(self):
        """Regression: `environment: [- PUID=1000]` yielded the whole string as
        one opaque value, losing the key name and scoring as a mystery token."""
        p = self.write("docker-compose.yml", "\n".join([
            "services:", "  app:", "    environment:",
            "      - PUID=1000", "      - TZ=Europe/Oslo",
            "      - APP_SECRET=Kx7vQm2ZpLr9WtBn",
        ]))
        cands = {c.key: c for c in cr.extract_candidates(p, 8)}
        self.assertIn("APP_SECRET", cands)
        self.assertEqual(cands["APP_SECRET"].value, "Kx7vQm2ZpLr9WtBn")
        self.assertNotIn("PUID=1000", {c.value for c in cands.values()})

    def test_build_flags_are_benign(self):
        for key, value in (
            ("target.x86_64-unknown-linux-gnu.rustflags[1]", "-Clink-arg=-fuse-ld=lld"),
            ("build.rustflags", "target-feature=+crt-static"),
        ):
            with self.subTest(key=key):
                c = cr.Candidate(key=key, value=value, hits=6)
                c.classify(8)
                self.assertEqual(c.verdict, "skip")

    def test_yaml_without_pyyaml_via_line_scanner(self):
        """PyYAML is absent on stock macOS; compose files must still work."""
        p = self.write("docker-compose.yml", "\n".join([
            "services:", "  db:", "    image: mysql:8",
            "    environment:", "      MYSQL_ROOT_PASSWORD: Kx7vQm2ZpLr9WtBn",
        ]))
        self.assertIn("Kx7vQm2ZpLr9WtBn", self.values(p))


class TestEmbeddedCredentials(TempTree):
    def test_url_password_extracted_separately(self):
        pairs = dict(cr._derive_embedded("DATABASE_URL",
                                         "mysql://svc:hunter2pass@db.internal/app"))
        self.assertEqual(pairs.get("DATABASE_URL.password"), "hunter2pass")

    def test_basic_auth_decoded(self):
        import base64
        blob = base64.b64encode(b"user:Kx7vQm2ZpLr9WtBn").decode()
        pairs = dict(cr._derive_embedded("HDR", f"Authorization: Basic {blob}"))
        self.assertEqual(pairs.get("HDR.basic.password"), "Kx7vQm2ZpLr9WtBn")

    def test_url_password_surfaces_from_a_real_file(self):
        p = self.root / ".env"
        p.write_text("DATABASE_URL=mysql://svc:hunter2pass@db.internal/app\n")
        self.assertIn("hunter2pass", {c.value for c in cr.extract_candidates(p, 8)})


# ---------------------------------------------------------------------------
# discovery patterns
# ---------------------------------------------------------------------------


class TestDiscoveryPatterns(TempTree):
    def kinds_in(self, text):
        p = self.write("blob.txt", text)
        findings, _ = cr.discover([p])
        return {f.kind for f in findings}

    def test_provider_key_shapes_detected(self):
        cases = {
            "aws_access_key": "AKIAIOSFODNN7ABCDEFG",
            "github_pat": "ghp_016Ap2mQxZ4vB8nK3rT7yU1wE5sD9fG2hJ4k",
            "gitlab_pat": "glpat-A1b2C3d4E5f6G7h8I9j0",
            "anthropic_key": "sk-ant-api03-QwErTyUiOpAsDfGhJkLzXcVbNm1234567890",
            "openai_key": "sk-proj-abc123XYZ789defGHI456jklMNO012pqrSTU",
            "slack_token": "xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrSt",
            "google_api_key": "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7",
            "npm_token": "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uh",
            "private_key_block": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
        }
        for kind, sample in cases.items():
            with self.subTest(kind=kind):
                self.assertIn(kind, self.kinds_in(sample))

    def test_anthropic_key_not_mislabelled_as_openai(self):
        """Regression: sk- matched first, so sk-ant- was reported as openai_key."""
        kinds = self.kinds_in("sk-ant-api03-QwErTyUiOpAsDfGhJkLzXcVbNm1234567890")
        self.assertIn("anthropic_key", kinds)
        self.assertNotIn("openai_key", kinds)

    def test_url_credentials_survive_example_hostname(self):
        """Regression: 'example' in the HOSTNAME suppressed the whole finding."""
        kinds = self.kinds_in("DATABASE_URL=postgres://appuser:Tr0ub4dor3xKq@db.example.internal:5432/app")
        self.assertIn("url_credentials", kinds)

    def test_password_assignment_detected(self):
        self.assertIn("password_assignment", self.kinds_in("MYSQL_ROOT_PASSWORD=Zx9KpQm2VnLr7WtBs4Hd"))

    def test_token_usage_counters_do_not_fire(self):
        """Regression: 'input_tokens' matched, so every transcript looked dirty."""
        noise = '{"usage":{"input_tokens":15234,"cache_read_input_tokens":1553728,"output_tokens":812}}'
        self.assertNotIn("password_assignment", self.kinds_in(noise))

    def test_no_match_inside_longer_words(self):
        """Regression: 'sk-' matched mid-word, giving 275 false hits on one tree.

        Real cases from a live transcript sweep: a git branch named "task-..."
        and Tailwind's "mask-image" utility classes.
        """
        for noise in (
            '{"gitBranch":"task-8f2a1c9d4b7e0a3f6c2d8b5"}',
            '"mask-image-linear-pos":[{"mask-linear":[wx]}]',
            'const unmask-identifier-value-here = 1',
            '"branch":"refs/heads/task-2026-08-migrate-database"',
        ):
            with self.subTest(noise=noise):
                self.assertEqual(self.kinds_in(noise), set(), f"{noise!r} must not match")

    def test_real_key_still_matches_after_boundary_fix(self):
        for sample in (
            "sk-proj-abc123XYZ789defGHI456jklMNO012pqrSTU",
            'API_KEY="sk-proj-abc123XYZ789defGHI456jklMNO012pqrSTU"',
            "export OPENAI=sk-proj-abc123XYZ789defGHI456jklMNO012pqrSTU",
        ):
            with self.subTest(sample=sample):
                self.assertIn("openai_key", self.kinds_in(sample))

    def test_greedy_classes_are_bounded(self):
        """Regression: bearer_header swallowed 676 chars of minified code."""
        blob = "Authorization: Bearer " + ("a" * 4000)
        findings, _ = cr.discover([self.write("big.txt", blob)])
        for f in findings:
            self.assertLessEqual(len(f.sample), 600, f"{f.kind} match unbounded")

    def test_source_code_is_not_a_credential(self):
        """Regression: `const token = ...` gave 417 hits across 96 files."""
        for code in (
            "const token = generateAccessToken(user)",
            "secret = opts?.token ?? fallbackValue",
            "export const uniq = (): string => nanoid()",
            "def get_secret(self) -> Optional[str]:",
            "api_key: process.env.OPENAI_API_KEY",
        ):
            with self.subTest(code=code):
                self.assertNotIn("password_assignment", self.kinds_in(code))

    def test_real_password_assignment_survives_noise_filter(self):
        self.assertIn("password_assignment",
                      self.kinds_in("MYSQL_ROOT_PASSWORD=Zx9KpQm2VnLr7WtBs4Hd"))

    def test_provider_keys_exempt_from_noise_filter(self):
        """A GitHub PAT is unambiguous - never drop it for being frequent."""
        secret = "ghp_016Ap2mQxZ4vB8nK3rT7yU1wE5sD9fG2hJ4k"
        paths = [self.write(f"f{i}.txt", "\n".join([secret] * 30)) for i in range(6)]
        findings, _ = cr.discover(paths)
        self.assertIn("github_pat", {f.kind for f in findings})

    def test_placeholders_suppressed(self):
        for line in ("API_KEY=your-api-key-here", "SECRET=<REDACTED>",
                     "PASSWORD=changeme", "TOKEN=${VAULT_TOKEN}",
                     "SECRET={{ vault_secret }}", "PASSWORD=xxxxxxxxxx"):
            with self.subTest(line=line):
                self.assertEqual(self.kinds_in(line), set(), f"{line!r} should be suppressed")

    def test_findings_never_expose_the_value(self):
        secret = "ghp_016Ap2mQxZ4vB8nK3rT7yU1wE5sD9fG2hJ4k"
        p = self.write("blob.txt", secret)
        findings, _ = cr.discover([p])
        self.assertTrue(findings)
        self.assertNotIn(secret, findings[0].masked())


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------


class TestScanning(TempTree):
    def test_counts_in_plain_text(self):
        p = self.write("a.txt", "secret1 and secret1 and secret2")
        counts = cr.count_in_file(p, ["secret1", "secret2"])
        self.assertEqual(counts["secret1"], 2)
        self.assertEqual(counts["secret2"], 1)

    def test_value_escaped_in_jsonl_is_still_found(self):
        """A value containing a quote is escaped on disk; raw search would miss it."""
        secret = 'pa"ss\\word'
        line = json.dumps({"type": "user", "message": {"content": f"cat .env -> {secret}"}})
        p = self.write("t.jsonl", line + "\n")
        self.assertEqual(cr.count_in_file(p, [secret])[secret], 1)

    def test_plain_value_found_in_jsonl_fast_path(self):
        secret = "Kx7vQm2ZpLr9WtBn"
        p = self.write("t.jsonl", json.dumps({"content": f"x {secret} y"}) + "\n")
        self.assertEqual(cr.count_in_file(p, [secret])[secret], 1)

    def test_malformed_jsonl_line_still_searched(self):
        p = self.write("t.jsonl", "this is not json but has Kx7vQm2ZpLr9WtBn in it\n")
        self.assertEqual(cr.count_in_file(p, ["Kx7vQm2ZpLr9WtBn"])["Kx7vQm2ZpLr9WtBn"], 1)

    def test_values_regex_prefers_longest(self):
        rx = cr._values_regex(["abc", "abcdef"])
        self.assertEqual(rx.search("xxabcdefxx").group(0), "abcdef")

    def test_scan_aggregates_across_files(self):
        a = self.write("a.txt", "Kx7vQm2ZpLr9WtBn")
        b = self.write("b.txt", "Kx7vQm2ZpLr9WtBn Kx7vQm2ZpLr9WtBn")
        res = cr.scan([a, b], ["Kx7vQm2ZpLr9WtBn"])
        self.assertEqual(res.counts["Kx7vQm2ZpLr9WtBn"], 3)
        self.assertEqual(len(res.locations["Kx7vQm2ZpLr9WtBn"]), 2)

    def test_absent_value_reports_zero(self):
        p = self.write("a.txt", "nothing here")
        self.assertEqual(cr.scan([p], ["Kx7vQm2ZpLr9WtBn"]).counts["Kx7vQm2ZpLr9WtBn"], 0)


class TestEncodeCwd(unittest.TestCase):
    def test_matches_claude_code_encoding(self):
        self.assertEqual(cr.encode_cwd(Path("/Users/bob/.zsh")), "-Users-bob--zsh")
        self.assertEqual(cr.encode_cwd(Path("/Users/bob/code")), "-Users-bob-code")


# ---------------------------------------------------------------------------
# config file discovery
# ---------------------------------------------------------------------------


class TestConfigFileDiscovery(TempTree):
    def setUp(self):
        super().setUp()
        for rel in (".env", ".env.local", "docker-compose.yml", "sub/.env",
                    "terraform.tfvars", ".env.example", "config.sample.json",
                    "node_modules/pkg/.env", ".git/config", "README.md"):
            self.write(rel, "KEY=Kx7vQm2ZpLr9WtBn\n")
        self.write("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n")

    def names(self, **kw):
        configs, _ = cr.find_config_files(self.root, **kw)
        return {p.name for p in configs}

    def test_finds_expected_configs(self):
        names = self.names()
        for expected in (".env", ".env.local", "docker-compose.yml", "terraform.tfvars"):
            self.assertIn(expected, names)

    def test_recurses_into_subdirectories(self):
        configs, _ = cr.find_config_files(self.root)
        self.assertTrue(any(p.parent.name == "sub" for p in configs))

    def test_skips_vendor_directories(self):
        configs, _ = cr.find_config_files(self.root)
        self.assertFalse(any("node_modules" in p.parts for p in configs))
        self.assertFalse(any(".git" in p.parts for p in configs))

    def test_example_files_skipped_by_default(self):
        names = self.names()
        self.assertNotIn(".env.example", names)
        self.assertNotIn("config.sample.json", names)

    def test_example_files_included_on_request(self):
        self.assertIn(".env.example", self.names(include_examples=True))

    def test_explicit_exclude_glob(self):
        self.assertNotIn(".env.local", self.names(exclude=[".env.local"]))

    def test_ignore_file_is_honoured(self):
        self.write(cr.IGNORE_FILENAME, "# comment\ndocker-compose.yml\n")
        self.assertNotIn("docker-compose.yml", self.names())

    def test_opaque_key_files_reported_separately(self):
        _, opaque = cr.find_config_files(self.root)
        self.assertIn("id_rsa", {p.name for p in opaque})

    def test_unreadable_names_are_not_configs(self):
        self.assertNotIn("README.md", self.names())


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------


class TestCLI(TempTree):
    def setUp(self):
        super().setUp()
        self.claude_home = self.root / "claude"
        (self.claude_home / "projects" / "-tmp-proj").mkdir(parents=True)
        self._orig_home = cr.CLAUDE_HOME
        cr.CLAUDE_HOME = self.claude_home
        self.addCleanup(lambda: setattr(cr, "CLAUDE_HOME", self._orig_home))

    def transcript(self, content: str) -> Path:
        p = self.claude_home / "projects" / "-tmp-proj" / "aaaa-bbbb.jsonl"
        p.write_text(json.dumps({"type": "user", "message": content}) + "\n")
        return p

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cr.main(argv)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_session_scope_includes_subagents_and_tool_results(self):
        """Regression: default scope missed projects/<slug>/<uuid>/tool-results/,
        which is where large raw tool output (e.g. a cat of .env) is stored."""
        proj = self.claude_home / "projects" / "-tmp-proj"
        t = proj / "aaaa-bbbb.jsonl"
        t.write_text(json.dumps({"type": "user", "message": "hi"}) + "\n")
        (proj / "aaaa-bbbb" / "subagents").mkdir(parents=True)
        (proj / "aaaa-bbbb" / "subagents" / "agent-1.jsonl").write_text(
            json.dumps({"message": "sub saw Kx7vQm2ZpLr9WtBn"}) + "\n")
        (proj / "aaaa-bbbb" / "tool-results").mkdir(parents=True)
        (proj / "aaaa-bbbb" / "tool-results" / "r1.txt").write_text("Zx9KpQm2VnLr7Wtc\n")

        found = cr.session_targets(t)
        names = {p.name for p in found}
        self.assertIn("agent-1.jsonl", names)
        self.assertIn("r1.txt", names)

        res = cr.scan(found, ["Kx7vQm2ZpLr9WtBn", "Zx9KpQm2VnLr7Wtc"])
        self.assertEqual(res.counts["Kx7vQm2ZpLr9WtBn"], 1)
        self.assertEqual(res.counts["Zx9KpQm2VnLr7Wtc"], 1)

    def test_exit_zero_when_clean(self):
        self.transcript("nothing sensitive here")
        env = self.write("proj/.env", "MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\n")
        code, out, _ = self.run_cli(["--from-file", str(env), "--all"])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_exit_one_when_value_present(self):
        self.transcript("the password is Kx7vQm2ZpLr9WtBn ok")
        env = self.write("proj/.env", "MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\n")
        code, out, _ = self.run_cli(["--from-file", str(env), "--all"])
        self.assertEqual(code, 1)
        self.assertIn("MYSQL_PASSWORD", out)

    def test_secret_value_never_printed(self):
        """The tool must not leak the thing it is helping you remove."""
        secret = "Kx7vQm2ZpLr9WtBn"
        self.transcript(f"leaked {secret} here")
        env = self.write("proj/.env", f"MYSQL_PASSWORD={secret}\n")
        code, out, err = self.run_cli(["--from-file", str(env), "--all"])
        self.assertEqual(code, 1)
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, err)

    def test_discover_mode_reports_without_reference_file(self):
        self.transcript("token is ghp_016Ap2mQxZ4vB8nK3rT7yU1wE5sD9fG2hJ4k here")
        code, out, _ = self.run_cli(["--discover", "--all"])
        self.assertEqual(code, 1)
        self.assertIn("github_pat", out)

    def test_discover_rejects_reference_values(self):
        env = self.write("proj/.env", "K=Kx7vQm2ZpLr9WtBn\n")
        code, _, err = self.run_cli(["--discover", "--from-file", str(env), "--all"])
        self.assertEqual(code, 2)
        self.assertIn("takes no reference values", err)

    def test_value_and_from_file_are_exclusive(self):
        env = self.write("proj/.env", "K=Kx7vQm2ZpLr9WtBn\n")
        code, _, err = self.run_cli(["--value", "x", "--from-file", str(env), "--all"])
        self.assertEqual(code, 2)
        self.assertIn("cannot be combined", err)

    def test_missing_file_is_an_error(self):
        code, _, err = self.run_cli(["--from-file", str(self.root / "nope.env"), "--all"])
        self.assertEqual(code, 2)
        self.assertIn("not a file", err)

    def test_no_source_defaults_to_current_directory(self):
        """`claude-redact --all` from a project should just audit that project."""
        import os
        proj = self.root / "proj"
        proj.mkdir(exist_ok=True)
        (proj / ".env").write_text("MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\n")
        self.transcript("leaked Kx7vQm2ZpLr9WtBn here")
        cwd = os.getcwd()
        os.chdir(proj)
        try:
            code, out, _ = self.run_cli(["--all"])
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 1)
        self.assertIn("MYSQL_PASSWORD", out)

    def test_default_scope_is_the_whole_tree(self):
        """A credential defined in one project is routinely leaked from another,
        and the 'too common' signal needs a broad corpus to work at all."""
        import os
        other = self.claude_home / "projects" / "-somewhere-else"
        other.mkdir(parents=True, exist_ok=True)
        (other / "cccc-dddd.jsonl").write_text(
            json.dumps({"message": "leaked Kx7vQm2ZpLr9WtBn"}) + "\n")
        proj = self.root / "proj3"
        proj.mkdir(exist_ok=True)
        (proj / ".env").write_text("MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\n")
        cwd = os.getcwd()
        os.chdir(proj)
        try:
            code, out, _ = self.run_cli([])
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 1, "should find the value in an unrelated project")
        self.assertIn("MYSQL_PASSWORD", out)

    def test_here_narrows_to_current_directory(self):
        import os
        self.transcript("nothing here")
        proj = self.root / "proj4"
        proj.mkdir(exist_ok=True)
        (proj / ".env").write_text("MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\n")
        cwd = os.getcwd()
        os.chdir(proj)
        try:
            _, _, err = self.run_cli(["--here"])
        finally:
            os.chdir(cwd)
        self.assertIn("no transcripts for this directory", err)

    def test_verbose_with_no_findings_reports_clean_not_red(self):
        """Regression: --verbose showed benign rows, so the summary took the
        'worth attention' branch and printed '0 value(s) worth attention'."""
        proj = self.root / "proj5"
        proj.mkdir(exist_ok=True)
        (proj / ".env").write_text("PUID=1000\nTZ=Europe/Oslo\n")
        self.transcript("PUID=1000 and TZ=Europe/Oslo appear here")
        code, out, _ = self.run_cli(["--from-dir", str(proj), "--all", "--verbose"])
        self.assertIn("clean", out)
        self.assertNotIn("worth attention", out)
        self.assertEqual(code, 0, "benign-only presence must not exit non-zero")

    def test_exit_code_tracks_findings_not_presence(self):
        proj = self.root / "proj6"
        proj.mkdir(exist_ok=True)
        (proj / ".env").write_text("TZ=Europe/Oslo\n")
        self.transcript("TZ=Europe/Oslo is here")
        self.assertEqual(self.run_cli(["--from-dir", str(proj), "--all"])[0], 0)

    def test_benign_rows_hidden_unless_verbose(self):
        proj = self.root / "proj2"
        proj.mkdir(exist_ok=True)
        (proj / ".env").write_text(
            "MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\nTZ=Europe/Oslo\n")
        self.transcript("leaked Kx7vQm2ZpLr9WtBn in Europe/Oslo")
        quiet = self.run_cli(["--from-dir", str(proj), "--all"])[1]
        loud = self.run_cli(["--from-dir", str(proj), "--all", "--verbose"])[1]
        self.assertNotIn("TZ", quiet)
        self.assertIn("TZ", loud)
        self.assertIn("MYSQL_PASSWORD", quiet)

    def test_list_sources_exits_without_scanning(self):
        self.write("proj/.env", "K=Kx7vQm2ZpLr9WtBn\n")
        code, _, err = self.run_cli(["--from-dir", str(self.root / "proj"), "--list-sources", "--all"])
        self.assertEqual(code, 0)
        self.assertIn(".env", err)

    def test_json_output_is_valid(self):
        self.transcript("leaked Kx7vQm2ZpLr9WtBn here")
        env = self.write("proj/.env", "MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\n")
        code, out, _ = self.run_cli(["--from-file", str(env), "--all", "--json"])
        payload = json.loads(out)
        self.assertEqual(code, 1)
        self.assertTrue(payload["findings"])
        self.assertNotIn("Kx7vQm2ZpLr9WtBn", out)

    def test_from_dir_collects_multiple_configs(self):
        self.write("proj/.env", "MYSQL_PASSWORD=Kx7vQm2ZpLr9WtBn\n")
        self.write("proj/docker-compose.yml", "    POSTGRES_PASSWORD: Zx9KpQm2VnLr7Wtc\n")
        self.transcript("saw Kx7vQm2ZpLr9WtBn and Zx9KpQm2VnLr7Wtc")
        code, out, _ = self.run_cli(["--from-dir", str(self.root / "proj"), "--all"])
        self.assertEqual(code, 1)
        self.assertIn("MYSQL_PASSWORD", out)
        self.assertIn("POSTGRES_PASSWORD", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
