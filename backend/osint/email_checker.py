"""
Suraksha — Email Breach Checker (OSINT)
Checks HaveIBeenPwned API for known breaches associated with the sender's email.
Gracefully degrades if no API key is configured.
"""

import os
import requests
from models import EmailBreachResult


def check_email(email: str) -> EmailBreachResult:
    """
    Check if an email address has been involved in known data breaches
    using the HaveIBeenPwned API.
    """
    api_key = os.getenv("HIBP_API_KEY", "").strip()

    if not api_key:
        return EmailBreachResult(
            email=email,
            error="No HaveIBeenPwned API key configured (optional)"
        )

    try:
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "Suraksha-Extension"
        }

        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            params={"truncateResponse": "true"},
            timeout=10
        )

        if resp.status_code == 200:
            breaches = resp.json()
            breach_names = [b.get("Name", "Unknown") for b in breaches]
            return EmailBreachResult(
                email=email,
                is_breached=True,
                breach_count=len(breach_names),
                breaches=breach_names
            )
        elif resp.status_code == 404:
            # No breaches found — this is a good sign
            return EmailBreachResult(email=email, is_breached=False)
        elif resp.status_code == 401:
            return EmailBreachResult(email=email, error="Invalid HIBP API key")
        elif resp.status_code == 429:
            return EmailBreachResult(email=email, error="HIBP rate limit exceeded")
        else:
            return EmailBreachResult(
                email=email,
                error=f"HIBP returned status {resp.status_code}"
            )

    except Exception as e:
        return EmailBreachResult(email=email, error=str(e))
