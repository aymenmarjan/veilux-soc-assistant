"""Synthetic regression and actual outbound HTTP inspection; never uses the network."""

import asyncio
import json
import time
import unittest
from unittest.mock import patch
import httpx
import server
from secret_detection import (
    MECHANISMS,
    SecretFinding,
    detect_secrets,
    redact_findings,
    resolve_overlaps,
)

FIXTURES = {
    "known_tokens": ("key ghp_" + "A" * 36, "ghp_" + "A" * 36),
    "private_keys": (
        "-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----",
    ),
    "authorization": (
        '2026-09-06 request_header="Authorization: Bearer opaque-session-value" next=ok',
        "opaque-session-value",
    ),
    "cookies": (
        '2026-09-06 request_header="Cookie: sessionid=synthetic-session" next=ok',
        "sessionid=synthetic-session",
    ),
    "urls": (
        "https://api.example.test/callback?access_token=opaque-access-value&state=complete",
        "opaque-access-value",
    ),
    "assignments": ("password=Summer2026! next=ok", "Summer2026!"),
    "commands": ("curl -u bob:Orange2026! https://api.example.test", "Orange2026!"),
    "context": ("authentication failed alice:synthetic-pass", "synthetic-pass"),
}


def only(name):
    return {key: key == name for key in MECHANISMS}


class DetectorRegressionTests(unittest.TestCase):
    def test_examples_and_boundaries(self):
        samples = list(FIXTURES.values()) + [
            ("password=abc", "abc"),
            (
                "2026-09-06 Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000",
                "550e8400-e29b-41d4-a716-446655440000",
            ),
            (
                'curl --user "alice:password with spaces" https://api.example.test',
                "password with spaces",
            ),
            (
                "Server=db.example.test;Password=DbPass2026!;Database=events;",
                "DbPass2026!",
            ),
            (
                '{"password":"with \\"escaped\\" quotes", "next":1}',
                'with \\"escaped\\" quotes',
            ),
            (
                'broken {"password": "multi\nline secret" trailing=ok',
                "multi\nline secret",
            ),
            (
                'Cookie: sid="quoted cookie"; next=secret',
                'sid="quoted cookie"; next=secret',
            ),
            ("https://alice:pass%20word@api.example.test/path?state=ok", "pass%20word"),
        ]
        for text, secret in samples:
            with self.subTest(text=text):
                redacted, mapping, _ = redact_findings(text, detect_secrets(text))
                self.assertNotIn(secret, redacted)
                self.assertIn(secret, mapping.values())
                # Exact reconstruction proves quotes, unrelated fields, and offsets survive.
                for marker, value in mapping.items():
                    redacted = redacted.replace(marker, value)
                self.assertEqual(text, redacted)

    def test_header_quoted_boundaries_and_edits_next_to_markers(self):
        for text, secret in [
            (
                'Cookie: sid="space other=inside"; sid2=second status=200',
                'sid="space other=inside"; sid2=second',
            ),
            (
                'Authorization: Digest username="alice", response="digest-secret" status=200',
                'username="alice", response="digest-secret"',
            ),
            ("password=⟦SECRET#1⟧edited-value status=200", "⟦SECRET#1⟧edited-value"),
        ]:
            out, mapping, _ = redact_findings(text, detect_secrets(text))
            self.assertIn(secret, mapping.values())
            self.assertIn(" status=200", out)
            self.assertNotIn(secret, out)

    def test_each_checkbox_independent(self):
        for mechanism, (text, secret) in FIXTURES.items():
            with self.subTest(mechanism=mechanism):
                self.assertIn(
                    secret, [f.value for f in detect_secrets(text, only(mechanism))]
                )
                self.assertEqual(
                    [], detect_secrets(text, {key: False for key in MECHANISMS})
                )
                self.assertNotIn(
                    secret, [f.value for f in detect_secrets(text, {mechanism: False})]
                )

    def test_other_enabled_evidence_still_applies(self):
        token = "ghp_" + "B" * 36
        self.assertTrue(detect_secrets("password=" + token, {"known_tokens": False}))
        self.assertTrue(detect_secrets("password=" + token, {"assignments": False}))

    def test_identifiers_context_and_case(self):
        text = (
            "authentication uid:event-id guid:550e8400-e29b-41d4-a716-446655440000 hash:"
            + "a" * 64
            + " port:8080 time:2026-09-06T10:20:30 /path/to/file mapping alice:word"
        )
        # Identifier shapes are uncertain/reviewable, never silently exempted.
        identifiers = detect_secrets(text.split(" mapping")[0])
        self.assertEqual(2, len(identifiers))
        self.assertTrue(all(f.confidence == "ambiguous" for f in identifiers))
        text = "Secret Secret secret SECRET"
        redacted, mapping, effective = redact_findings(text, [], ["Secret"], ["Secret"])
        self.assertEqual(2, len(effective))
        self.assertIn("secret SECRET", redacted)
        self.assertEqual(1, len(mapping))

    def test_overlap_union_preserves_tails(self):
        text = "abcdefgh"
        findings = [
            SecretFinding(0, 5, "abcde", "a", "a"),
            SecretFinding(3, 8, "defgh", "b", "b", "ambiguous"),
        ]
        result = resolve_overlaps(findings)
        self.assertEqual(
            [(0, 8, "abcdefgh")], [(f.start, f.end, f.value) for f in result]
        )

    def test_shared_map_does_not_cascade(self):
        out, mapping, _ = server.protect_secret_inputs(
            ['password="first"', 'password="second" pwd="first"']
        )
        self.assertNotEqual(out[0].split('"')[1], out[1].split('"')[1])
        self.assertEqual({"first", "second"}, set(mapping.values()))

    def test_repeated_bare_secret_and_existing_placeholder_are_protected(self):
        secret = "a" * 64
        protected, mapping, _ = server.protect_secret_inputs(
            [
                "Authorization: Bearer " + secret,
                "repeated " + secret,
                "already ⟦SECRET#1⟧ password=newvalue",
            ]
        )
        self.assertNotIn(secret, "".join(protected))
        self.assertNotIn("⟦SECRET#1⟧", mapping)
        protected, _, _ = server.protect_secret_inputs(
            ["password=abc hash=abc" + "f" * 61]
        )
        self.assertNotIn("abc" + "f" * 61, protected[0])


class WorkflowRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_setting_reaches_scan_preview_ti_and_actual_ai_http(self):
        original = httpx.AsyncClient
        for name, (text, secret) in FIXTURES.items():
            for enabled in (True, False):
                config = {k: False for k in MECHANISMS}
                config[name] = enabled
                sent = []
                ti_inputs = []

                async def transport(request):
                    sent.append(json.loads(request.content)["messages"][0]["content"])
                    return httpx.Response(
                        200, json={"choices": [{"message": {"content": "safe report"}}]}
                    )

                async def fake_ti(logs, notes, *args, **kwargs):
                    ti_inputs.extend(logs)
                    return (
                        text,
                        [],
                    )  # TI-produced secrets use identical configuration too.

                def client(*args, **kwargs):
                    return original(
                        *args, transport=httpx.MockTransport(transport), **kwargs
                    )

                request = server.LogAnalysisRequest(
                    logs=[text],
                    mode="groq",
                    api_key="synthetic-key",
                    sanitize=False,
                    secret_protection=config,
                    enable_threat_intel=True,
                    virustotal_api_key="synthetic-ti-key",
                )
                with self.subTest(name=name, enabled=enabled), patch.object(
                    server.httpx, "AsyncClient", client
                ), patch.object(server, "enrich_with_threat_intel", fake_ti):
                    scan = await server.secret_scan_endpoint(
                        server.SecretScanRequest(texts=[text], secret_protection=config)
                    )
                    preview = await server.sanitize_endpoint(
                        server.SanitizationRequest(
                            logs=[text],
                            enable_pattern_sanitization=False,
                            secret_protection=config,
                        )
                    )
                    await server.analyze_logs(request)
                    self.assertEqual(enabled, bool(scan["findings"]))
                    self.assertEqual(not enabled, secret in preview["sanitized_log"])
                    self.assertEqual(not enabled, secret in ti_inputs[0])
                    self.assertEqual(not enabled, secret in sent[0])

    async def test_actual_ti_http_never_receives_credential_hash_or_url(self):
        original = httpx.AsyncClient
        sent = []

        async def transport(request):
            sent.append(str(request.url))
            return httpx.Response(404, json={})

        def client(*args, **kwargs):
            return original(*args, transport=httpx.MockTransport(transport), **kwargs)

        secret = "a" * 64
        logs = [
            "Authorization: Bearer "
            + secret
            + "\nhttps://alice:private-pass@example.com/path\n8.8.8.8"
        ]
        protected, _, _ = server.protect_secret_inputs(logs)
        with patch.object(server.httpx, "AsyncClient", client), patch.object(
            server, "threat_intel_cache", {}
        ), patch.object(server, "_save_threat_intel_cache"):
            await server.enrich_with_threat_intel(
                protected, None, "fake", None, enable_whois=False
            )
        self.assertTrue(sent)
        self.assertNotIn(secret, str(sent))
        self.assertNotIn("private-pass", str(sent))
        self.assertNotIn("alice", str(sent))

    async def test_just_sanitize_is_local_and_has_timings(self):
        with patch.object(
            server.httpx, "AsyncClient", side_effect=AssertionError("external request")
        ):
            result = await server.analyze_logs(
                server.LogAnalysisRequest(
                    logs=["password=abc"],
                    mode="sanitize_only",
                    enable_pattern_sanitization=False,
                    enable_threat_intel=True,
                    virustotal_api_key="fake",
                )
            )
        self.assertNotIn("abc", result.sanitized_log)
        self.assertIn("detection", result.timings_ms)
        self.assertIn("replacement", result.timings_ms)
        self.assertNotIn("ai", result.timings_ms)
        self.assertNotIn("threat_intelligence", result.timings_ms)

    async def test_slow_ti_is_bounded_and_measured_separately(self):
        async def slow(*args, **kwargs):
            await asyncio.sleep(10)

        async def ai(*args):
            await asyncio.sleep(0.02)
            return "ok"

        with patch.object(server, "enrich_with_threat_intel", slow), patch.object(
            server, "call_groq_ai", ai
        ), patch.object(server, "THREAT_INTEL_TIME_BUDGET_SECONDS", 0.04):
            t = time.perf_counter()
            result = await server.analyze_logs(
                server.LogAnalysisRequest(
                    logs=["8.8.8.8"],
                    mode="groq",
                    api_key="fake",
                    enable_threat_intel=True,
                    virustotal_api_key="fake",
                    sanitize=False,
                )
            )
        self.assertLess(time.perf_counter() - t, 1)
        self.assertGreater(result.timings_ms["threat_intelligence"], 30)
        self.assertGreater(result.timings_ms["ai"], 15)

    async def test_scan_failure_cannot_send_and_cancellation_stops_next_stage(self):
        with patch.object(
            server, "scan_secrets", side_effect=RuntimeError("scan failed")
        ), patch.object(server, "call_groq_ai") as ai:
            with self.assertRaises(server.HTTPException):
                await server.analyze_logs(
                    server.LogAnalysisRequest(logs=["x"], mode="groq", api_key="fake")
                )
            ai.assert_not_called()
        entered = asyncio.Event()

        async def slow(*args, **kwargs):
            entered.set()
            await asyncio.sleep(10)

        with patch.object(server, "enrich_with_threat_intel", slow), patch.object(
            server, "call_groq_ai"
        ) as ai:
            task = asyncio.create_task(
                server.analyze_logs(
                    server.LogAnalysisRequest(
                        logs=["8.8.8.8"],
                        request_id="cancel-test",
                        mode="groq",
                        api_key="fake",
                        enable_threat_intel=True,
                        virustotal_api_key="fake",
                    )
                )
            )
            await entered.wait()
            self.assertEqual(
                "Checking threat intelligence",
                (await server.analysis_status("cancel-test"))["phase"],
            )
            await server.cancel_analysis("cancel-test")
            with self.assertRaises(server.HTTPException):
                await task
            ai.assert_not_called()

    async def test_final_scan_failure_and_local_timeout_stop_ai(self):
        original = server.scan_secrets
        calls = 0

        def fail_final(text, config=None, *args):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise ValueError("final scan failed")
            return original(text, config, *args)

        with patch.object(server, "scan_secrets", fail_final), patch.object(
            server, "call_groq_ai"
        ) as ai:
            with self.assertRaises(server.HTTPException):
                await server.analyze_logs(
                    server.LogAnalysisRequest(
                        logs=["safe"], mode="groq", api_key="fake", sanitize=False
                    )
                )
            ai.assert_not_called()

        def slow_scan(*args):
            time.sleep(0.04)
            return []

        with patch.object(server, "scan_secrets", slow_scan), patch.object(
            server, "SCAN_TIMEOUT_SECONDS", 0.01
        ), patch.object(server, "call_groq_ai") as ai:
            with self.assertRaises(server.HTTPException):
                await server.analyze_logs(
                    server.LogAnalysisRequest(
                        logs=["safe"], mode="groq", api_key="fake", sanitize=False
                    )
                )
            ai.assert_not_called()

    async def test_cancel_before_dispatch_is_honored(self):
        await server.cancel_analysis("before-dispatch")
        with patch.object(server, "call_groq_ai") as ai:
            with self.assertRaises(server.HTTPException):
                await server.analyze_logs(
                    server.LogAnalysisRequest(
                        logs=["safe"],
                        request_id="before-dispatch",
                        mode="groq",
                        api_key="fake",
                    )
                )
            ai.assert_not_called()

    async def test_manual_hide_wins_over_keep_in_edited_notes_and_prompt(self):
        sent = []

        async def ai(prompt, key):
            sent.append(prompt)
            return "ok"

        request = server.LogAnalysisRequest(
            logs=["edited secret-value secret-value SECRET-VALUE"],
            analyst_data="secret-value",
            custom_prompt="Use secret-value",
            sanitize=False,
            mode="groq",
            api_key="fake",
            secret_protection={k: False for k in MECHANISMS},
            allowed_ambiguous_secrets=["secret-value"],
            force_hide_values=["secret-value"],
        )
        with patch.object(server, "call_groq_ai", ai):
            await server.analyze_logs(request)
        self.assertNotIn("secret-value", sent[0])
        self.assertIn("SECRET-VALUE", sent[0])


if __name__ == "__main__":
    unittest.main()
