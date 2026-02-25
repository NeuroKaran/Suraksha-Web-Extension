"""
Suraksha — Page Synthesizer (AI)
Analyzes webpage signals and OSINT data to detect risky interactions.
Uses LangChain + Gemini/OpenAI with a webpage-specific prompt.

Falls back to rule-based heuristic if no LLM API key is configured.
"""

import os
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from models import PageSignals, OSINTReport


# ─── Prompt Template ─────────────────────────────────────────────────

PAGE_ANALYSIS_PROMPT = """You are an expert cybersecurity analyst specializing in detecting phishing websites, scam pages, and risky web interactions.

Analyze the following webpage signals and OSINT intelligence. Determine if this page poses a risk to the user.

## PAGE INFO
- **URL:** {url}
- **Page Type:** {page_type}
- **Title:** {title}
- **HTTPS:** {is_https}

## CLIENT-SIDE SIGNALS
{signals_text}

## OSINT INTELLIGENCE
{osint_data}

## YOUR ANALYSIS

Consider these factors:
1. **Suspicious Forms**: Are there login/payment forms submitting data to cross-domain or unrelated servers?
2. **Hidden Fields**: Forms with many hidden inputs could be collecting data covertly.
3. **Link Mismatches**: Links where the visible text doesn't match the actual URL are a phishing red flag.
4. **URL Shorteners**: Shortened URLs hide the real destination.
5. **Urgency / Scam Language**: Fake warnings, countdown timers, "your computer is infected", prize claims.
6. **HTTPS Status**: Login or payment pages without HTTPS are dangerous.
7. **Domain Reputation**: OSINT checks on the page's domain and links.
8. **Brand Impersonation**: Is the page mimicking a well-known brand's login or payment page?

Return your analysis as a VALID JSON object with exactly these fields:
{{
  "score": <integer 1–100, where 1 = extremely dangerous and 100 = perfectly safe>,
  "verdict": "<exactly one of: Dangerous, Suspicious, Safe>",
  "explanation": "<one clear sentence explaining WHY this page is or isn't risky>",
  "risk_factors": ["<list of specific risk factors found, empty if safe>"]
}}

IMPORTANT: Return ONLY the JSON object, nothing else. No markdown, no code blocks, no extra text."""


def format_signals_text(signals: PageSignals) -> str:
    """Format client-extracted signals into readable text for the LLM."""
    sections = []

    sections.append(f"- **Total forms on page:** {signals.form_count}")
    sections.append(f"- **Total links on page:** {signals.link_count}")
    sections.append(f"- **Has login form:** {'Yes' if signals.has_login_form else 'No'}")
    sections.append(f"- **Has payment form:** {'Yes' if signals.has_payment_form else 'No'}")

    if signals.suspicious_forms:
        sections.append("\n**Suspicious Forms Detected:**")
        for i, form in enumerate(signals.suspicious_forms[:5], 1):
            flags = []
            if form.is_cross_domain:
                flags.append("⚠️ CROSS-DOMAIN")
            if form.has_password_field:
                flags.append("🔑 Has password field")
            if form.has_hidden_fields:
                flags.append(f"👁️ {form.hidden_field_count} hidden fields")
            sections.append(f"  {i}. Action: {form.action} ({form.method}) — {', '.join(flags) if flags else 'No specific flags'}")

    if signals.suspicious_links:
        sections.append("\n**Suspicious Links Detected:**")
        for i, link in enumerate(signals.suspicious_links[:10], 1):
            flags = []
            if link.is_mismatched:
                flags.append("⚠️ TEXT/URL MISMATCH")
            if link.is_shortened:
                flags.append("🔗 SHORTENED URL")
            sections.append(f"  {i}. Text: \"{link.visible_text[:60]}\" → {link.href[:100]} {' — '.join(flags)}")

    if signals.urgency_keywords_found:
        sections.append(f"\n**Urgency Keywords Found:** {', '.join(signals.urgency_keywords_found[:10])}")

    if signals.scam_keywords_found:
        sections.append(f"\n**Scam Keywords Found:** {', '.join(signals.scam_keywords_found[:10])}")

    if signals.external_domain_forms:
        sections.append(f"\n**Forms posting to external domains:** {', '.join(signals.external_domain_forms[:5])}")

    return "\n".join(sections) if sections else "No significant signals detected."


def format_osint_for_page(osint_report: OSINTReport) -> str:
    """Format OSINT report for page analysis context."""
    sections = []

    if osint_report.domain_age:
        da = osint_report.domain_age
        status = "⚠️ SUSPICIOUS" if da.is_suspicious else "✅ Legitimate"
        age_str = f"{da.age_days} days old" if da.age_days is not None else "Unknown age"
        sections.append(f"**Page Domain Check:** {da.domain} — {status} ({age_str})")

    if osint_report.link_scan:
        sections.append("**Link Scan Results:**")
        for ls in osint_report.link_scan:
            if ls.error:
                sections.append(f"  - {ls.url} — ⚠️ {ls.error}")
            elif ls.is_flagged:
                sections.append(f"  - {ls.url} — 🚩 FLAGGED ({ls.malicious_count} malicious)")
            else:
                sections.append(f"  - {ls.url} — ✅ Clean")

    return "\n".join(sections) if sections else "No OSINT data available."


def parse_page_llm_response(text: str) -> dict | None:
    """Parse LLM JSON response for page analysis."""
    text = text.strip()

    # Strip markdown code blocks if present
    if text.startswith("```"):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

    # Try to find JSON object
    match = re.search(r'\{[^{}]*"score"[^{}]*\}', text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        result = json.loads(text)
        score = max(1, min(100, int(result.get("score", 50))))
        verdict = result.get("verdict", "Suspicious")
        explanation = result.get("explanation", "Analysis complete.")
        risk_factors = result.get("risk_factors", [])
        if isinstance(risk_factors, str):
            risk_factors = [risk_factors]
        return {
            "score": score,
            "verdict": verdict,
            "explanation": explanation,
            "risk_factors": risk_factors
        }
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


# ─── LLM Analysis ───────────────────────────────────────────────────

def analyze_page_with_llm(url: str, page_type: str, title: str,
                          signals: PageSignals, osint_report: OSINTReport) -> dict | None:
    """Analyze a webpage using LangChain + configured LLM provider."""
    # Import quota check from the email synthesizer (shared cooldown)
    from ai.synthesizer import _is_quota_cooldown_active, _record_quota_failure, _is_quota_error

    if _is_quota_cooldown_active():
        print("[Suraksha] ⏩ Skipping LLM for page — quota cooldown active")
        return None

    provider = os.getenv("LLM_PROVIDER", "gemini").lower()
    llm_timeout = int(os.getenv("LLM_TIMEOUT", "10"))

    signals_text = format_signals_text(signals)
    osint_data = format_osint_for_page(osint_report)

    prompt = PAGE_ANALYSIS_PROMPT.format(
        url=url,
        page_type=page_type,
        title=title[:200],
        is_https="Yes" if signals.is_https else "⚠️ NO — NOT SECURE",
        signals_text=signals_text,
        osint_data=osint_data,
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
                max_tokens=400,
                max_retries=1,
                request_timeout=llm_timeout
            )
        else:
            api_key = os.getenv("GEMINI_API_KEY", "").strip()
            if not api_key:
                raise ValueError("No Gemini API key configured")

            from langchain_google_genai import ChatGoogleGenerativeAI
            llm = ChatGoogleGenerativeAI(
                model="gemini-2.0-flash",
                google_api_key=api_key,
                temperature=0.1,
                max_output_tokens=400,
                max_retries=1,
                timeout=llm_timeout
            )

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(llm.invoke, prompt)
            try:
                response = future.result(timeout=llm_timeout + 5)
                return parse_page_llm_response(response.content)
            except FuturesTimeoutError:
                print(f"[Suraksha] ⏱️  Page LLM timed out after {llm_timeout + 5}s")
                return None

    except Exception as e:
        if _is_quota_error(e):
            _record_quota_failure()
            print("[Suraksha] 🚫 Quota exhausted for page analysis")
        else:
            print(f"[Suraksha] Page LLM analysis failed: {str(e)[:200]}")
        return None


# ─── Rule-Based Fallback ────────────────────────────────────────────

SCAM_KEYWORDS = [
    "your computer is infected", "virus detected", "call this number",
    "tech support", "microsoft warning", "apple security",
    "your account has been locked", "immediate action required",
    "you have won", "congratulations", "claim your prize",
    "free gift card", "limited time offer", "act now",
    "your device is compromised", "unauthorized access detected",
    "bitcoin investment", "guaranteed returns", "double your money",
    "nigerian prince", "inheritance fund", "click here to claim",
    "verify your identity", "update your payment"
]

# Well-known URL shorteners
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "bl.ink", "short.io"
]

# Well-known safe domains (won't flag these pages)
KNOWN_SAFE_PAGE_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "reddit.com",
    "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "x.com", "linkedin.com",
    "instagram.com", "netflix.com", "spotify.com",
    "stripe.com", "paypal.com", "notion.so", "figma.com",
}


def _is_safe_domain(domain: str) -> bool:
    """Check if a domain is in the known safe list."""
    parts = domain.lower().split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in KNOWN_SAFE_PAGE_DOMAINS:
            return True
    return False


def analyze_page_with_rules(url: str, page_type: str, title: str,
                            signals: PageSignals, osint_report: OSINTReport) -> dict:
    """Rule-based webpage analysis as fallback when no LLM is available."""
    score = 85  # Start optimistic
    risk_factors = []

    # ── Known safe domain shortcut ──
    if _is_safe_domain(signals.page_domain):
        return {
            "score": 90,
            "verdict": "Safe",
            "explanation": f"This is a well-known, trusted website ({signals.page_domain}).",
            "risk_factors": []
        }

    # ── HTTPS check ──
    if not signals.is_https:
        if signals.has_login_form:
            score -= 35
            risk_factors.append("Login form on non-HTTPS page — credentials would be sent unencrypted")
        elif signals.has_payment_form:
            score -= 40
            risk_factors.append("Payment form on non-HTTPS page — extremely dangerous")
        else:
            score -= 10
            risk_factors.append("Page does not use HTTPS")

    # ── Suspicious forms ──
    for form in signals.suspicious_forms[:5]:
        if form.is_cross_domain:
            score -= 20
            risk_factors.append(f"Form submits data to external domain: {form.action[:80]}")
        if form.has_password_field and form.is_cross_domain:
            score -= 15
            risk_factors.append("Password field in cross-domain form — possible credential theft")
        if form.hidden_field_count > 3:
            score -= 10
            risk_factors.append(f"Form has {form.hidden_field_count} hidden fields — possible covert data collection")

    # ── Suspicious links ──
    mismatched = sum(1 for l in signals.suspicious_links if l.is_mismatched)
    shortened = sum(1 for l in signals.suspicious_links if l.is_shortened)

    if mismatched >= 3:
        score -= 25
        risk_factors.append(f"{mismatched} links where visible text doesn't match the actual URL")
    elif mismatched >= 1:
        score -= 10
        risk_factors.append(f"{mismatched} link(s) with mismatched text/URL")

    if shortened >= 3:
        score -= 15
        risk_factors.append(f"{shortened} shortened URLs hiding real destinations")
    elif shortened >= 1:
        score -= 5
        risk_factors.append(f"{shortened} shortened URL(s) detected")

    # ── Scam / urgency keywords ──
    if len(signals.scam_keywords_found) >= 3:
        score -= 30
        risk_factors.append(f"Multiple scam indicators: {', '.join(signals.scam_keywords_found[:5])}")
    elif len(signals.scam_keywords_found) >= 1:
        score -= 15
        risk_factors.append(f"Scam language detected: {', '.join(signals.scam_keywords_found[:3])}")

    if len(signals.urgency_keywords_found) >= 3:
        score -= 20
        risk_factors.append("Excessive urgency/pressure language detected")
    elif len(signals.urgency_keywords_found) >= 1:
        score -= 10
        risk_factors.append("Urgency language detected")

    # ── OSINT domain check ──
    if osint_report.domain_age and osint_report.domain_age.is_suspicious:
        score -= 20
        risk_factors.append("Page domain is newly registered or suspicious")

    # ── OSINT link scan ──
    flagged_links = [ls for ls in osint_report.link_scan if ls.is_flagged]
    if flagged_links:
        score -= 25
        risk_factors.append(f"{len(flagged_links)} malicious link(s) detected by VirusTotal")

    # ── External domain forms ──
    if signals.external_domain_forms:
        score -= 15
        risk_factors.append(f"Forms sending data to: {', '.join(signals.external_domain_forms[:3])}")

    # Clamp score
    score = max(1, min(100, score))

    # Determine verdict
    if score < 40:
        verdict = "Dangerous"
    elif score < 70:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    explanation = "; ".join(risk_factors) if risk_factors else "No significant risk indicators found on this page."

    return {
        "score": score,
        "verdict": verdict,
        "explanation": explanation,
        "risk_factors": risk_factors
    }


# ─── Main Entry Point ───────────────────────────────────────────────

def analyze_page(url: str, page_type: str, title: str,
                 signals: PageSignals, osint_report: OSINTReport) -> dict:
    """
    Analyze a webpage for risk indicators.
    Tries LLM first, falls back to rule-based analysis.
    """
    llm_start = time.time()

    result = analyze_page_with_llm(url, page_type, title, signals, osint_report)

    llm_elapsed = time.time() - llm_start

    if result is not None:
        print(f"[Suraksha] ✅ Page AI analysis complete ({llm_elapsed:.1f}s)")
        return result

    print(f"[Suraksha] 🔄 Page fallback to rule-based analysis ({llm_elapsed:.1f}s)")
    return analyze_page_with_rules(url, page_type, title, signals, osint_report)
