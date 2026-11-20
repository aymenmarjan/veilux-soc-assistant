"""Synthetic credential tests; no real keys and no network access."""

import asyncio
import unittest
from unittest.mock import patch

import server
from secret_detection import detect_secrets, redact_findings


class SecretDetectorTests(unittest.TestCase):
    def assert_hidden(self, text, secret):
        redacted, mapping, _ = redact_findings(text, detect_secrets(text))
        self.assertNotIn(secret, redacted)
        self.assertIn(secret, mapping.values())

    def test_raw_mixed_and_quoted_assignments(self):
        secret = "space enabled password"
        self.assert_hidden('prefix {"password": "' + secret + '"} trailing=raw', secret)

    def test_url_header_cookie_connection_and_command(self):
        fixtures = [
            ("GET https://alice:s3cret-pass@example.test/x", "s3cret-pass"),
            ("Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"),
            ("Cookie: sid=a1b2c3; session=synthetic-cookie", "sid=a1b2c3; session=synthetic-cookie"),
            ("Server=db;User Id=a;Password='db pass phrase';Encrypt=true", "db pass phrase"),
            ('curl --user "alice:command pass" https://example.test', "command pass"),
        ]
        for text, secret in fixtures:
            with self.subTest(text=text):
                self.assert_hidden(text, secret)

    def test_provider_and_complete_multiline_private_key(self):
        self.assert_hidden("token=ghp_" + "A" * 36, "ghp_" + "A" * 36)
        block = "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-REAL\n-----END PRIVATE KEY-----"
        self.assert_hidden("before\n" + block + "\nafter", block)

    def test_ambiguous_pair_requires_context_and_is_reviewable(self):
        finding = detect_secrets("authentication failed for alice:guessme")
        self.assertEqual("ambiguous", finding[0].confidence)
        self.assertEqual([], detect_secrets("mapping alice:guessme in an event"))

    def test_hashes_and_guids_are_reviewable_uncertain_findings(self):
        values = ["550e8400-e29b-41d4-a716-446655440000", "a" * 32, "b" * 40, "c" * 64]
        findings = detect_secrets(" ".join(values))
        self.assertEqual(values, [finding.value for finding in findings])
        self.assertTrue(all(finding.confidence == "ambiguous" for finding in findings))

    def test_overlap_prefers_complete_header_value(self):
        token = "eyJabcde.abcdefgh.ijklmnop"
        findings = detect_secrets("Authorization: Bearer " + token)
        self.assertEqual(1, len(findings))
        self.assertEqual(token, findings[0].value)


class OutboundSafetyTests(unittest.TestCase):
    def test_ai_prompt_excludes_secrets_from_logs_notes_prompt_and_edits(self):
        log_secret = "log secret phrase"
        note_secret = "note secret phrase"
        prompt_secret = "prompt secret phrase"
        sent = []

        async def fake_ai(prompt, api_key):
            sent.append(prompt)
            return "Report keeps ⟦SECRET#1⟧ masked"

        request = server.LogAnalysisRequest(
            logs=[f'{{"password":"{log_secret}"}}'], analyst_data=f'pwd="{note_secret}"',
            custom_prompt=f'client_secret="{prompt_secret}"', mode="groq", api_key="test-provider-key",
            sanitize=False, force_hide_values=["analyst-selected-edit"])
        request.logs.append("edited=analyst-selected-edit")
        with patch.object(server, "call_groq_ai", new=fake_ai):
            response = asyncio.run(server.analyze_logs(request))
        self.assertEqual(1, len(sent))
        for secret in (log_secret, note_secret, prompt_secret, "analyst-selected-edit"):
            self.assertNotIn(secret, sent[0])
        self.assertIn("⟦SECRET#1⟧", response.analysis)

    def test_ti_receives_redacted_inputs_before_ioc_extraction(self):
        credential_url = "https://alice:url-pass@example.com/path"
        captured = []

        async def fake_ti(logs, analyst_data, *args, **kwargs):
            captured.extend(logs)
            return "", []

        async def fake_ai(prompt, api_key):
            return "ok"

        request = server.LogAnalysisRequest(logs=[credential_url], mode="groq", api_key="x",
            sanitize=False, enable_threat_intel=True, virustotal_api_key="test")
        with patch.object(server, "enrich_with_threat_intel", new=fake_ti), \
             patch.object(server, "call_groq_ai", new=fake_ai):
            asyncio.run(server.analyze_logs(request))
        self.assertNotIn("url-pass", "".join(captured))


if __name__ == "__main__":
    unittest.main()
