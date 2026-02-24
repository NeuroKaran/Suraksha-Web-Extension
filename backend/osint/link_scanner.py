"""
Suraksha — Link Scanner (OSINT)
Uses VirusTotal API v3 to scan URLs found in email body.
Gracefully degrades if no API key is configured.
"""

import os
import re
import base64
import requests
from models import LinkScanResult


# Regex to extract URLs from text
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    urls = URL_PATTERN.findall(text)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for url in urls:
        # Strip trailing punctuation
        url = url.rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def scan_single_url(url: str, api_key: str) -> LinkScanResult:
    """Scan a single URL using VirusTotal API v3."""
    try:
        # VirusTotal expects base64url-encoded URL (no padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if resp.status_code == 404:
            # URL not in VT database — submit it for scanning
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            if submit_resp.status_code == 200:
                analysis = submit_resp.json().get("data", {}).get("attributes", {})
                stats = analysis.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return LinkScanResult(
                    url=url,
                    malicious_count=malicious,
                    suspicious_count=suspicious,
                    is_flagged=(malicious + suspicious) > 0
                )
            return LinkScanResult(url=url, error="Submitted for scan, results pending")

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return LinkScanResult(
                url=url,
                malicious_count=malicious,
                suspicious_count=suspicious,
                is_flagged=(malicious + suspicious) > 0
            )

        return LinkScanResult(url=url, error=f"VT returned status {resp.status_code}")

    except Exception as e:
        return LinkScanResult(url=url, error=str(e))


def scan_links(body: str) -> list[LinkScanResult]:
    """
    Extract all URLs from email body and scan them with VirusTotal.
    Returns empty list if no API key is configured.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    urls = extract_urls(body)

    if not urls:
        return []

    if not api_key:
        # No API key — return URLs found but mark as unchecked
        return [
            LinkScanResult(url=url, error="No VirusTotal API key configured")
            for url in urls
        ]

    # Scan each URL (VT free tier: 4 requests/minute — be cautious)
    results = []
    for url in urls[:5]:  # Limit to 5 URLs to stay within rate limits
        results.append(scan_single_url(url, api_key))

    return results
