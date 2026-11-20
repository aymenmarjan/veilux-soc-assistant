"""The backend key every test uses (the backend requires one on each request).
tests/browser_mock.js stores the same value as the extension's paired key."""
import os

TEST_BACKEND_KEY = "veilux-test-backend-key-0123456789"
AUTH = {"X-Veilux-Token": TEST_BACKEND_KEY}


def use_test_key():
    """Call before importing server, so it never creates a key file."""
    os.environ.setdefault("VEILUX_TOKEN", TEST_BACKEND_KEY)
