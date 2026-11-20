"""Shared test setup.

The popup shows one stage at a time (Case, Options, Results, Tools). Tests
address controls by id, so before a Playwright action the harness brings the
control's stage into view through the popup's own VeiluxUI.reveal, the same
function its links between stages use. Moving between stages by hand (the
rail, the tabs inside a stage, the review stage) is covered by
tests/test_popup_stages_ui.py.
"""
from playwright.sync_api import Locator

from backend_key import use_test_key

# The backend needs a key on every request; tests use a fixed one, never a key file.
use_test_key()

_REVEAL = "element => { if (window.VeiluxUI && window.VeiluxUI.reveal) window.VeiluxUI.reveal(element); }"
_ACTIONS = ("click", "dblclick", "fill", "check", "uncheck", "set_checked", "select_option", "press", "type",
            "press_sequentially", "focus", "hover", "set_input_files", "select_text", "clear")


def _revealing(action):
    original = getattr(Locator, action)

    def wrapper(self, *args, **kwargs):
        try:
            self.evaluate(_REVEAL, timeout=2000)
        except Exception:
            pass  # the action itself reports a missing or ambiguous element
        return original(self, *args, **kwargs)
    wrapper.__name__ = action
    return wrapper


for _action in _ACTIONS:
    if hasattr(Locator, _action):
        setattr(Locator, _action, _revealing(_action))
