"""
Suraksha — Domain Age Checker (OSINT)
Uses python-whois to check how old a sender's domain is.
New domains (< 90 days) are flagged as suspicious.
"""

import whois
from datetime import datetime, timezone
from models import DomainAgeResult

# Well-known domains that should never be flagged as suspicious
# even if WHOIS lookup fails or returns unexpected data
KNOWN_SAFE_DOMAINS = {
    "gmail.com", "google.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "microsoft.com",
    "yahoo.com", "yahoo.co.uk", "ymail.com",
    "icloud.com", "apple.com", "me.com",
    "protonmail.com", "proton.me",
    "linkedin.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "amazon.com", "aws.amazon.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "reddit.com",
    "haveibeenpwned.com",
    "zoom.us", "slack.com", "notion.so", "figma.com",
    "stripe.com", "paypal.com",
    "netlify.com", "vercel.com", "heroku.com",
    "isc2.org",
}


def _is_known_safe(domain: str) -> bool:
    """Check if domain or its parent domain is in the safelist."""
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in KNOWN_SAFE_DOMAINS:
            return True
    return False


def check_domain(email: str) -> DomainAgeResult:
    """
    Extract domain from email and check its registration age.
    Domains less than 90 days old are flagged as suspicious.
    """
    try:
        domain = email.split("@")[-1].strip().lower()

        # Skip WHOIS for well-known domains
        if _is_known_safe(domain):
            return DomainAgeResult(
                domain=domain,
                is_suspicious=False,
                error="Known safe domain — WHOIS skipped"
            )

        w = whois.whois(domain)

        # creation_date can be a list or a single value
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return DomainAgeResult(
                domain=domain,
                is_suspicious=False,  # WHOIS data unavailable ≠ suspicious
                error="Could not determine domain registration date"
            )

        # Make timezone-aware if needed
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        return DomainAgeResult(
            domain=domain,
            creation_date=creation_date.isoformat(),
            age_days=age_days,
            is_suspicious=age_days < 90
        )

    except Exception as e:
        # Domain doesn't exist or WHOIS lookup failed
        domain = email.split("@")[-1].strip().lower() if "@" in email else email

        # If it's a known safe domain, don't flag it
        if _is_known_safe(domain):
            return DomainAgeResult(
                domain=domain,
                is_suspicious=False,
                error=f"Known safe domain (WHOIS error: {e})"
            )

        return DomainAgeResult(
            domain=domain,
            is_suspicious=True,  # unknown domain + lookup failure → suspicious
            error=str(e)
        )

