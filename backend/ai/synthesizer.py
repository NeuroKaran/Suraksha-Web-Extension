"""
Suraksha — AI Synthesizer
Uses LangChain + Gemini/OpenAI to analyze email content and OSINT evidence,
producing a safety score and human-readable explanation.

Falls back to a rule-based heuristic if no LLM API key is configured.
Optimized: fast-fail on quota exhaustion with cooldown tracking.
"""

import os
import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from models import OSINTReport


# ─── Quota Cooldown Tracking ────────────────────────────────────────
# When a 429 quota error is received, we record the timestamp and skip
# LLM calls for QUOTA_COOLDOWN_SECONDS to avoid wasting time on retries.

_quota_lock = threading.Lock()
_last_quota_failure: float = 0.0
QUOTA_COOLDOWN_SECONDS = 60  # Skip LLM for 60s after a quota error


def _is_quota_cooldown_active() -> bool:
    """Check if we recently hit a quota limit and should skip LLM."""
    with _quota_lock:
        if _last_quota_failure == 0.0:
            return False
        elapsed = time.time() - _last_quota_failure
        return elapsed < QUOTA_COOLDOWN_SECONDS


def _record_quota_failure():
    """Record that a quota error just occurred."""
    global _last_quota_failure
    with _quota_lock:
        _last_quota_failure = time.time()


# ─── Prompt Template ─────────────────────────────────────────────────

ANALYSIS_PROMPT = """You are an expert cybersecurity analyst specializing in phishing and social engineering detection.

Analyze the following email and OSINT intelligence data. Determine if this email is a phishing attempt, social engineering attack, or is legitimate.

## EMAIL DATA
- **Sender:** {sender}
- **Subject:** {subject}
- **Body:**
```
{body}
```

## OSINT INTELLIGENCE
{osint_data}

## YOUR ANALYSIS

Consider these factors:
1. **Urgency & Pressure Tactics**: Does the email create false urgency or threaten consequences?
2. **Impersonation**: Is the sender pretending to be someone authoritative (bank, IT dept, CEO)?
3. **Suspicious Links**: Are there URLs that don't match the supposed sender's organization?
4. **Domain Age**: Is the sender's domain newly registered (common in phishing)?
5. **Data Requests**: Does it ask for passwords, bank details, or personal information?
6. **Grammar & Tone**: Are there suspicious patterns, unusual formatting, or grammar issues?
7. **OSINT Flags**: What do the OSINT tools reveal about the domain and links?

Return your analysis as a VALID JSON object with exactly these fields:
{{
  "score": <integer 1–100, where 1 = extremely dangerous phishing and 100 = perfectly safe>,
  "verdict": "<exactly one of: Dangerous, Suspicious, Safe>",
  "explanation": "<one clear sentence explaining WHY this email is or isn't suspicious>"
}}

IMPORTANT: Return ONLY the JSON object, nothing else. No markdown, no code blocks, no extra text."""


def format_osint_data(osint_report: OSINTReport) -> str:
    """Format OSINT report into readable text for the LLM."""
    sections = []

    if osint_report.domain_age:
        da = osint_report.domain_age
        status = "⚠️ SUSPICIOUS" if da.is_suspicious else "✅ Legitimate"
        age_str = f"{da.age_days} days old" if da.age_days is not None else "Unknown age"
        sections.append(f"**Domain Check:** {da.domain} — {status} ({age_str})")
        if da.error:
            sections.append(f"  - Note: {da.error}")

    if osint_report.link_scan:
        sections.append("**Link Scan Results:**")
        for ls in osint_report.link_scan:
            if ls.error:
                sections.append(f"  - {ls.url} — ⚠️ {ls.error}")
            elif ls.is_flagged:
                sections.append(f"  - {ls.url} — 🚩 FLAGGED ({ls.malicious_count} malicious, {ls.suspicious_count} suspicious)")
            else:
                sections.append(f"  - {ls.url} — ✅ Clean")

    if osint_report.email_breach:
        eb = osint_report.email_breach
        if eb.error:
            sections.append(f"**Email Breach Check:** {eb.error}")
        elif eb.is_breached:
            sections.append(f"**Email Breach Check:** ⚠️ Found in {eb.breach_count} breach(es): {', '.join(eb.breaches[:5])}")
        else:
            sections.append(f"**Email Breach Check:** ✅ No known breaches")

    return "\n".join(sections) if sections else "No OSINT data available."


def parse_llm_response(text: str) -> dict:
    """Parse LLM JSON response, handling markdown code blocks and extra text."""
    text = text.strip()

    # Strip markdown code blocks if present
    if text.startswith("```"):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

    # Try to find JSON object in the response
    match = re.search(r'\{[^{}]*"score"[^{}]*\}', text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        result = json.loads(text)
        # Validate required fields
        score = int(result.get("score", 50))
        score = max(1, min(100, score))
        verdict = result.get("verdict", "Suspicious")
        explanation = result.get("explanation", "Analysis complete.")
        return {"score": score, "verdict": verdict, "explanation": explanation}
    except (json.JSONDecodeError, ValueError, TypeError):
        return {"score": 50, "verdict": "Suspicious", "explanation": "Could not parse AI analysis."}


def _is_quota_error(error: Exception) -> bool:
    """Check if an exception is a quota/rate-limit error (429)."""
    error_str = str(error)
    return "429" in error_str or "ResourceExhausted" in error_str or "quota" in error_str.lower()


# ─── LLM Analysis ───────────────────────────────────────────────────

def analyze_with_llm(sender: str, subject: str, body: str, osint_report: OSINTReport) -> dict:
    """
    Analyze email using LangChain + configured LLM provider.
    Optimized with:
    - max_retries=1 (fast-fail instead of 5 retries)
    - Configurable timeout (default 10s)
    - Quota cooldown tracking (skips LLM for 60s after a 429)
    """
    # ── Quota cooldown check ──
    if _is_quota_cooldown_active():
        print("[Suraksha] ⏩ Skipping LLM — quota cooldown active (will retry in <60s)")
        return None

    provider = os.getenv("LLM_PROVIDER", "gemini").lower()
    llm_timeout = int(os.getenv("LLM_TIMEOUT", "10"))
    osint_data = format_osint_data(osint_report)

    prompt = ANALYSIS_PROMPT.format(
        sender=sender,
        subject=subject,
        body=body[:3000],  # Truncate very long emails
        osint_data=osint_data
    )

    try:
        if provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY", "").strip()
            if not api_key:
                raise ValueError("No OpenAI API key configured")

            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(
                model="gpt-4o-mini",
                api_key=api_key,
                temperature=0.1,
                max_tokens=300,
                max_retries=1,       # Fast-fail: 1 retry instead of default 5
                request_timeout=llm_timeout
            )
        else:
            # Default: Gemini
            api_key = os.getenv("GEMINI_API_KEY", "").strip()
            if not api_key:
                raise ValueError("No Gemini API key configured")

            from langchain_google_genai import ChatGoogleGenerativeAI
            llm = ChatGoogleGenerativeAI(
                model="gemini-2.0-flash",
                google_api_key=api_key,
                temperature=0.1,
                max_output_tokens=300,
                max_retries=1,       # Fast-fail: 1 retry instead of default 5
                timeout=llm_timeout
            )

        # Run with a hard timeout to prevent hanging
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(llm.invoke, prompt)
            try:
                response = future.result(timeout=llm_timeout + 5)  # Extra 5s grace
                return parse_llm_response(response.content)
            except FuturesTimeoutError:
                print(f"[Suraksha] ⏱️  LLM timed out after {llm_timeout + 5}s")
                return None

    except Exception as e:
        error_msg = str(e)
        if _is_quota_error(e):
            _record_quota_failure()
            print(f"[Suraksha] 🚫 Quota exhausted — activating {QUOTA_COOLDOWN_SECONDS}s cooldown")
        else:
            print(f"[Suraksha] LLM analysis failed: {error_msg[:200]}")
        return None


# ─── Rule-Based Fallback ────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "right now", "asap", "within 24 hours",
    "suspended", "locked", "verify your", "confirm your", "click here",
    "act now", "limited time", "expire", "deadline", "warning",
    "unauthorized", "suspicious activity", "unusual sign-in"
]

PHISHING_KEYWORDS = [
    "password", "bank account", "credit card", "social security",
    "ssn", "login credentials", "wire transfer", "bitcoin",
    "gift card", "prize", "winner", "lottery", "inheritance",
    "nigerian prince", "bank details", "routing number"
]


def analyze_with_rules(sender: str, subject: str, body: str, osint_report: OSINTReport) -> dict:
    """Rule-based phishing heuristic as a fallback when no LLM is available."""
    score = 80  # Start optimistic
    reasons = []

    combined_text = f"{subject} {body}".lower()

    # Check urgency keywords
    urgency_hits = sum(1 for kw in URGENCY_KEYWORDS if kw in combined_text)
    if urgency_hits >= 3:
        score -= 30
        reasons.append("Multiple urgency/pressure tactics detected")
    elif urgency_hits >= 1:
        score -= 15
        reasons.append("Urgency language detected")

    # Check phishing keywords
    phishing_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in combined_text)
    if phishing_hits >= 2:
        score -= 25
        reasons.append("Requests for sensitive information detected")
    elif phishing_hits >= 1:
        score -= 10
        reasons.append("Possible sensitive data request")

    # Check OSINT: domain age
    if osint_report.domain_age and osint_report.domain_age.is_suspicious:
        score -= 20
        reasons.append(f"Sender domain is newly registered or suspicious")

    # Check OSINT: link scan
    flagged_links = [ls for ls in osint_report.link_scan if ls.is_flagged]
    if flagged_links:
        score -= 25
        reasons.append(f"{len(flagged_links)} malicious link(s) detected")

    # Check OSINT: email breach
    if osint_report.email_breach and osint_report.email_breach.is_breached:
        score -= 10
        reasons.append("Sender email found in data breaches")

    # Clamp score
    score = max(1, min(100, score))

    # Determine verdict
    if score < 40:
        verdict = "Dangerous"
    elif score < 70:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    explanation = "; ".join(reasons) if reasons else "No significant phishing indicators found."

    return {"score": score, "verdict": verdict, "explanation": explanation}


# ─── Main Entry Point ───────────────────────────────────────────────

def analyze_email(sender: str, subject: str, body: str, osint_report: OSINTReport) -> dict:
    """
    Analyze an email for phishing indicators.
    Tries LLM first, falls back to rule-based analysis.
    """
    llm_start = time.time()

    # Try LLM analysis first
    result = analyze_with_llm(sender, subject, body, osint_report)

    llm_elapsed = time.time() - llm_start

    if result is not None:
        print(f"[Suraksha] ✅ AI analysis complete ({llm_elapsed:.1f}s)")
        return result

    # LLM unavailable — use rule-based fallback
    print(f"[Suraksha] 🔄 Falling back to rule-based analysis ({llm_elapsed:.1f}s wasted on LLM)")
    result = analyze_with_rules(sender, subject, body, osint_report)
    return result
