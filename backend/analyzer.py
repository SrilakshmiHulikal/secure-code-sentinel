"""
Core analysis engine — supports Anthropic (Claude), xAI (Grok), and Groq providers.

Set PROVIDER=anthropic (default) | grok | groq in your .env.

  Anthropic: Anthropic SDK + prompt caching on the system prompt.
  Grok:      OpenAI-compatible SDK → https://api.x.ai/v1  (no caching)
  Groq:      OpenAI-compatible SDK → https://api.groq.com/openai/v1  (no caching)
"""

import json
import re
import os
from typing import Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore  — only required when PROVIDER=grok

# ── Provider config ────────────────────────────────────────────────────────────

PROVIDER = os.getenv("PROVIDER", "anthropic").lower()

# Model defaults — override via MODEL= env var if needed
DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-6",
    "grok": "grok-3",
    "groq": "llama-3.3-70b-versatile",
}
MODEL = os.getenv("MODEL", DEFAULT_MODELS.get(PROVIDER, "claude-opus-4-6"))

# ── Shared system prompts ──────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are SecureCodeSentinel, a world-class application security engineer specialising in \
static code analysis. Your mission is to detect ALL security vulnerabilities in submitted code.

You analyse code for:

## OWASP Top 10 (2021)
- A01:2021 – Broken Access Control (missing authz checks, IDOR, directory traversal)
- A02:2021 – Cryptographic Failures (weak ciphers, hardcoded secrets, plain-text sensitive data)
- A03:2021 – Injection (SQL, OS command, LDAP, XPath, NoSQL, SSTI, Log4Shell, etc.)
- A04:2021 – Insecure Design (business logic flaws, missing rate limits)
- A05:2021 – Security Misconfiguration (default creds, verbose errors, open cloud storage)
- A06:2021 – Vulnerable & Outdated Components (known-CVE imports)
- A07:2021 – Identification & Authentication Failures (weak passwords, broken session mgmt)
- A08:2021 – Software & Data Integrity Failures (unsafe deserialization, unsigned packages)
- A09:2021 – Security Logging & Monitoring Failures (missing audit logs, log injection)
- A10:2021 – Server-Side Request Forgery (unvalidated URL fetch, metadata endpoints)

## Secrets & Credential Leakage
- Hardcoded API keys, tokens, passwords, private keys
- Database connection strings with embedded credentials
- AWS/GCP/Azure credentials

## Injection & Input Validation
- XSS (reflected, stored, DOM-based)
- Path traversal / directory traversal
- XXE (XML External Entity injection)
- Template injection (Jinja2, Twig, Pebble, FreeMarker, etc.)
- Header injection, CRLF injection

## Insecure Patterns
- Insecure random number generation for security purposes
- Use of eval() / exec() with user input
- Race conditions / TOCTOU
- Prototype pollution (JavaScript)
- Insecure direct object references

## Response format
Always return a single, valid JSON object — no markdown, no prose outside JSON:
{
  "language": "<detected language>",
  "risk_score": <0-100 integer>,
  "summary": "<2-3 sentence executive summary>",
  "vulnerabilities": [
    {
      "type": "<short vulnerability name>",
      "owasp_category": "<A0X:2021 – Name>",
      "cwe_id": "<CWE-NNN>",
      "cwe_name": "<CWE name>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "line_start": <int>,
      "line_end": <int>,
      "description": "<clear explanation of the flaw>",
      "vulnerable_code": "<exact offending code snippet>",
      "fix_description": "<how to remediate>",
      "fixed_code": "<complete secure replacement snippet>"
    }
  ]
}

Risk score guidance:
- 0-20: Clean / minimal risk
- 21-40: Low risk — minor issues
- 41-60: Moderate risk — should be fixed before production
- 61-80: High risk — serious vulnerabilities present
- 81-100: Critical — exploitable, immediate remediation required

If no vulnerabilities are found, return an empty array and a risk_score of 0.\
"""

FIX_SYSTEM_PROMPT = """\
You are SecureCodeSentinel, a security remediation expert. Given a specific vulnerability and \
the surrounding code context, provide a thorough, step-by-step remediation guide.

Always return a single valid JSON object:
{
  "explanation": "<detailed explanation of why this is dangerous>",
  "fixed_code": "<complete, production-ready secure replacement>",
  "best_practices": ["<practice 1>", "<practice 2>", "..."],
  "references": ["<OWASP URL>", "<CWE URL>", "..."]
}\
"""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_json(text: str) -> dict:
    """Parse JSON from the model response, handling optional markdown fences."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fence:
        text = fence.group(1).strip()
    return json.loads(text)


def _calculate_risk_score(vulnerabilities: list) -> int:
    """Fallback risk scorer. CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1, cap 100."""
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    score = sum(weights.get(v.get("severity", "LOW"), 1) for v in vulnerabilities)
    return min(score, 100)


def _normalise(result: dict) -> dict:
    """Ensure risk_score is an int in [0, 100]."""
    vulns = result.get("vulnerabilities", [])
    model_score = result.get("risk_score")
    if model_score is None or not (0 <= int(model_score) <= 100):
        result["risk_score"] = _calculate_risk_score(vulns)
    else:
        result["risk_score"] = int(model_score)
    return result


# ── Provider backends ──────────────────────────────────────────────────────────

class _AnthropicBackend:
    """Calls Claude via the Anthropic SDK with prompt caching."""

    def __init__(self):
        import anthropic as _anthropic
        self._client = _anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    def complete(self, system: str, user: str, max_tokens: int) -> str:
        resp = self._client.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user}],
        )
        return resp.content[0].text


class _OpenAICompatibleBackend:
    """Generic OpenAI-compatible backend (used by Grok and Groq)."""

    def __init__(self, api_key: str, base_url: str):
        self._client = OpenAI(api_key=api_key, base_url=base_url)

    def complete(self, system: str, user: str, max_tokens: int) -> str:
        resp = self._client.chat.completions.create(
            model=MODEL,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content


def _make_backend():
    if PROVIDER == "grok":
        return _OpenAICompatibleBackend(
            api_key=os.getenv("XAI_API_KEY", ""),
            base_url="https://api.x.ai/v1",
        )
    if PROVIDER == "groq":
        return _OpenAICompatibleBackend(
            api_key=os.getenv("GROQ_API_KEY", ""),
            base_url="https://api.groq.com/openai/v1",
        )
    return _AnthropicBackend()


# ── Public analyser ────────────────────────────────────────────────────────────

class CodeAnalyzer:
    def __init__(self):
        self._backend = _make_backend()

    def analyze(
        self,
        code: str,
        language: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> dict:
        """Analyse a code snippet and return structured vulnerability data."""
        hints = []
        if filename:
            hints.append(f"The file is named '{filename}'.")
        if language:
            hints.append(f"The programming language is {language}.")

        user_content = (
            f"Analyse the following code for security vulnerabilities. {' '.join(hints)}\n\n"
            f"```\n{code}\n```"
        )

        raw = self._backend.complete(SYSTEM_PROMPT, user_content, max_tokens=4096)
        return _normalise(_extract_json(raw))

    def suggest_fix(self, vulnerable_code: str, vulnerability: dict) -> dict:
        """Return a detailed remediation guide for a single vulnerability."""
        user_content = (
            f"Vulnerability: {vulnerability.get('type')} ({vulnerability.get('cwe_id')})\n"
            f"Severity: {vulnerability.get('severity')}\n"
            f"Description: {vulnerability.get('description')}\n\n"
            f"Vulnerable code:\n```\n{vulnerable_code}\n```\n\n"
            "Provide a detailed remediation guide as JSON."
        )

        raw = self._backend.complete(FIX_SYSTEM_PROMPT, user_content, max_tokens=2048)
        try:
            return _extract_json(raw)
        except (json.JSONDecodeError, ValueError):
            return {
                "explanation": raw,
                "fixed_code": vulnerability.get("fixed_code", ""),
                "best_practices": [],
                "references": [],
            }

    @property
    def provider(self) -> str:
        return PROVIDER

    @property
    def model(self) -> str:
        return MODEL
