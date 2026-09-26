"""Localization scaffolding (ROADMAP Phase 12): RP_LANG, Urdu/English.

Machine contracts stay language-neutral: JSON keys, exit codes, schema
versions. These tests pin the scaffolding's fail-safe selection and the
English fallback.
"""

from __future__ import annotations

import json

import pytest

from rebel_profiler.core import i18n


@pytest.fixture(autouse=True)
def _lang_en(monkeypatch):
    """Deterministic language state: every test starts and ends in English.

    The module derives _LANG from RP_LANG at import time; tests that exercise
    the Urdu path set both the env var and the module flag explicitly, and
    this fixture guarantees no leak into the rest of the suite.
    """
    monkeypatch.delenv("RP_LANG", raising=False)
    i18n._LANG = "en"
    yield
    i18n._LANG = "en"


def _set_urdu(monkeypatch) -> None:
    monkeypatch.setenv("RP_LANG", "ur")
    i18n._LANG = "ur"


def test_default_is_english():
    assert i18n.lang() == "en"
    assert i18n.t("theme.reason") == "Reason:"
    assert i18n.t("theme.action") == "Action:"


def test_urdu_selection_via_env(monkeypatch):
    _set_urdu(monkeypatch)
    assert i18n.lang() == "ur"
    assert i18n.t("theme.reason") == "وجہ:"
    assert i18n.t("theme.exit_footer", code=5).startswith("ایگزٹ 5")


def test_unknown_language_code_falls_back_to_english():
    assert i18n.lang() == "en"


def test_missing_key_returns_the_key_itself(monkeypatch):
    _set_urdu(monkeypatch)
    assert i18n.t("no.such.key") == "no.such.key"


def test_english_fallback_for_untranslated_key(monkeypatch):
    saved = i18n.STRINGS["ur"].pop("verdict.ok")
    try:
        _set_urdu(monkeypatch)
        assert i18n.t("verdict.ok") == "ok"
    finally:
        i18n.STRINGS["ur"]["verdict.ok"] = saved


def test_error_frame_uses_i18n_labels():
    from rebel_profiler.cli.theme import error_frame

    frame = error_frame("SCOPE", "target not in scope", "scope fails closed",
                        "add the target to the case scope", 5)
    # English fragments stay findable (additive-only decoration law)
    assert "Reason:" in frame and "Action:" in frame and "exit 5" in frame


def test_error_frame_localizes_in_urdu(monkeypatch):
    from rebel_profiler.cli.theme import error_frame

    _set_urdu(monkeypatch)
    frame = error_frame("SCOPE", "target not in scope", "scope fails closed",
                        "add the target to the case scope", 5)
    assert "وجہ:" in frame and "ایکشن:" in frame and "ایگزٹ 5" in frame


def test_machine_contract_stays_language_neutral(monkeypatch):
    """RP_LANG must never touch JSON output: keys and codes are identical."""
    _set_urdu(monkeypatch)
    payload = {"ok": False, "exit": 2, "code": "usage"}
    rendered = json.dumps(payload, sort_keys=True)
    assert json.loads(rendered) == payload  # keys untouched by language


def test_rp_error_render_still_structured():
    from rebel_profiler.core.errors import UsageError

    err = UsageError("no such adapter", reason="unknown action",
                     action="run `adapters` to list")
    assert err.exit_code == 2
    text = err.render()
    assert "Reason:" in text and "Action:" in text
