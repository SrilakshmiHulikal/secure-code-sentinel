"""
Unit tests for the CodeAnalyzer module.
All LLM calls are mocked — no real API key needed.
Tests run against both the Anthropic and Grok backends via parametrize.
"""

import json
import os
import pytest
from unittest.mock import MagicMock, patch
from tests.conftest import (
    SAMPLE_SQL_INJECTION,
    SAMPLE_CLEAN_CODE,
    MOCK_ANALYSIS_RESULT,
    MOCK_CLEAN_RESULT,
)


# ── Mock helpers ───────────────────────────────────────────────────────────────

def _anthropic_response(data: dict):
    msg = MagicMock()
    msg.content = [MagicMock(text=json.dumps(data))]
    return msg


def _openai_response(data: dict):
    choice = MagicMock()
    choice.message.content = json.dumps(data)
    resp = MagicMock()
    resp.choices = [choice]
    return resp


def _patch_anthropic(data: dict):
    """Patch the Anthropic client inside _AnthropicBackend."""
    import anthropic as _anthropic_mod
    mock_client = MagicMock()
    mock_client.messages.create.return_value = _anthropic_response(data)
    return patch.object(_anthropic_mod, "Anthropic", return_value=mock_client)


def _patch_grok(data: dict):
    """Patch the OpenAI client inside _GrokBackend."""
    from openai import OpenAI as _OpenAI
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _openai_response(data)
    return patch("analyzer.OpenAI", return_value=mock_client)


# ── Parametrised provider fixture ──────────────────────────────────────────────

@pytest.fixture(params=["anthropic", "grok"])
def provider_env(request, monkeypatch):
    """Run each test under both providers."""
    monkeypatch.setenv("PROVIDER", request.param)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("XAI_API_KEY", "test-xai-key")
    return request.param


def _patch_backend(provider: str, data: dict):
    if provider == "grok":
        return _patch_grok(data)
    return _patch_anthropic(data)


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestCodeAnalyzer:

    def test_analyze_returns_structured_result(self, provider_env, monkeypatch):
        import importlib
        import analyzer as az
        importlib.reload(az)   # pick up new PROVIDER env var
        a = az.CodeAnalyzer()

        with _patch_backend(provider_env, MOCK_ANALYSIS_RESULT):
            a._backend = az._make_backend()
            result = a.analyze(SAMPLE_SQL_INJECTION)

        assert result["language"] == "Python"
        assert result["risk_score"] == 85
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["cwe_id"] == "CWE-89"

    def test_analyze_clean_code_returns_empty_vulns(self, provider_env):
        import importlib, analyzer as az
        importlib.reload(az)
        a = az.CodeAnalyzer()

        with _patch_backend(provider_env, MOCK_CLEAN_RESULT):
            a._backend = az._make_backend()
            result = a.analyze(SAMPLE_CLEAN_CODE)

        assert result["risk_score"] == 0
        assert result["vulnerabilities"] == []

    def test_risk_score_fallback_when_model_omits(self, provider_env):
        import importlib, analyzer as az
        importlib.reload(az)
        a = az.CodeAnalyzer()

        data_no_score = {**MOCK_ANALYSIS_RESULT}
        del data_no_score["risk_score"]

        with _patch_backend(provider_env, data_no_score):
            a._backend = az._make_backend()
            result = a.analyze(SAMPLE_SQL_INJECTION)

        assert result["risk_score"] == 10   # 1 CRITICAL × 10

    def test_risk_score_capped_at_100(self, provider_env):
        import importlib, analyzer as az
        importlib.reload(az)
        a = az.CodeAnalyzer()

        many_vulns = {
            "language": "Python",
            "vulnerabilities": [
                {"severity": "CRITICAL", "type": f"V{i}", "cwe_id": f"CWE-{i}"}
                for i in range(20)
            ],
        }
        with _patch_backend(provider_env, many_vulns):
            a._backend = az._make_backend()
            result = a.analyze("some code")

        assert result["risk_score"] <= 100

    def test_analyze_strips_json_fences(self, provider_env):
        import importlib, analyzer as az
        importlib.reload(az)
        a = az.CodeAnalyzer()

        fenced_text = f"```json\n{json.dumps(MOCK_ANALYSIS_RESULT)}\n```"

        if provider_env == "grok":
            choice = MagicMock()
            choice.message.content = fenced_text
            resp = MagicMock()
            resp.choices = [choice]
            with patch("analyzer.OpenAI") as mock_cls:
                mock_cls.return_value.chat.completions.create.return_value = resp
                a._backend = az._make_backend()
                result = a.analyze(SAMPLE_SQL_INJECTION)
        else:
            import anthropic as _am
            msg = MagicMock()
            msg.content = [MagicMock(text=fenced_text)]
            with patch.object(_am, "Anthropic") as mock_cls:
                mock_cls.return_value.messages.create.return_value = msg
                a._backend = az._make_backend()
                result = a.analyze(SAMPLE_SQL_INJECTION)

        assert result["risk_score"] == 85

    def test_suggest_fix_returns_explanation(self, provider_env):
        import importlib, analyzer as az
        importlib.reload(az)
        a = az.CodeAnalyzer()

        fix_data = {
            "explanation": "Direct string concatenation allows injection.",
            "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))",
            "best_practices": ["Use parameterised queries", "Validate input"],
            "references": ["https://owasp.org/A03"],
        }
        vuln = {"type": "SQL Injection", "cwe_id": "CWE-89", "severity": "CRITICAL", "description": "..."}

        with _patch_backend(provider_env, fix_data):
            a._backend = az._make_backend()
            result = a.suggest_fix("query = 'SELECT' + user_input", vuln)

        assert "explanation" in result
        assert len(result["best_practices"]) == 2


class TestAnthropicSpecific:
    """Tests that only apply to the Anthropic backend (prompt caching)."""

    def test_prompt_caching_headers_present(self, monkeypatch):
        monkeypatch.setenv("PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        import importlib, analyzer as az, anthropic as _am
        importlib.reload(az)

        with patch.object(_am, "Anthropic") as mock_cls:
            mock_client = MagicMock()
            mock_client.messages.create.return_value = _anthropic_response(MOCK_CLEAN_RESULT)
            mock_cls.return_value = mock_client

            a = az.CodeAnalyzer()
            a.analyze("x = 1")

            call_kwargs = mock_client.messages.create.call_args[1]
            system = call_kwargs["system"]

        assert isinstance(system, list)
        assert system[0].get("cache_control") == {"type": "ephemeral"}

    def test_provider_property_anthropic(self, monkeypatch):
        monkeypatch.setenv("PROVIDER", "anthropic")
        import importlib, analyzer as az, anthropic as _am
        importlib.reload(az)
        with patch.object(_am, "Anthropic"):
            a = az.CodeAnalyzer()
        assert a.provider == "anthropic"


class TestGrokSpecific:
    """Tests that only apply to the Grok backend."""

    def test_grok_uses_openai_compatible_client(self, monkeypatch):
        monkeypatch.setenv("PROVIDER", "grok")
        monkeypatch.setenv("XAI_API_KEY", "test-xai-key")

        import importlib, analyzer as az
        importlib.reload(az)

        with patch("analyzer.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = _openai_response(MOCK_CLEAN_RESULT)
            mock_cls.return_value = mock_client

            a = az.CodeAnalyzer()
            a.analyze("x = 1")

            # Must be pointed at xAI base URL
            init_kwargs = mock_cls.call_args[1]
            assert "x.ai" in init_kwargs.get("base_url", "")

    def test_grok_does_not_send_cache_control(self, monkeypatch):
        monkeypatch.setenv("PROVIDER", "grok")
        monkeypatch.setenv("XAI_API_KEY", "test-xai-key")

        import importlib, analyzer as az
        importlib.reload(az)

        with patch("analyzer.OpenAI") as mock_cls:
            mock_client = MagicMock()
            mock_client.chat.completions.create.return_value = _openai_response(MOCK_CLEAN_RESULT)
            mock_cls.return_value = mock_client

            a = az.CodeAnalyzer()
            a.analyze("x = 1")

            call_kwargs = mock_client.chat.completions.create.call_args[1]
            messages = call_kwargs["messages"]

        # No cache_control key anywhere in the messages
        for msg in messages:
            assert "cache_control" not in msg

    def test_provider_property_grok(self, monkeypatch):
        monkeypatch.setenv("PROVIDER", "grok")
        import importlib, analyzer as az
        importlib.reload(az)
        with patch("analyzer.OpenAI"):
            a = az.CodeAnalyzer()
        assert a.provider == "grok"
