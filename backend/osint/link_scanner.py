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


def _extract_malware_details(data: dict) -> dict:
    """
    Extract rich malware details from a VirusTotal URL/analysis response.
    Parses `last_analysis_results` for per-engine threat categories and names,
    and `categories` for URL categorisation labels.

    Returns dict with: malware_types, threat_names, detection_engines, categories
    """
    malware_types = set()
    threat_names = set()
    detection_engines = []

    # ── Per-engine verdicts ───────────────────────────────────────────
    analysis_results = data.get("last_analysis_results", {})
    for engine_name, engine_data in analysis_results.items():
        category = engine_data.get("category", "")
        result = engine_data.get("result", "")

        if category in ("malicious", "suspicious"):
            detection_engines.append(engine_name)
            if result:
                # Normalise common threat type prefixes
                threat_names.add(result)
                result_lower = result.lower()
                for mtype in ("trojan", "ransomware", "adware", "spyware",
                              "worm", "backdoor", "rootkit", "keylogger",
                              "dropper", "cryptominer", "rat", "botnet",
                              "exploit", "downloader"):
                    if mtype in result_lower:
                        malware_types.add(mtype.capitalize())
                        break
                else:
                    # Generic fallback based on VT category
                    malware_types.add("Malware" if category == "malicious" else "Suspicious")

    # ── URL categories (e.g. {"Forcepoint": "malware", "Comodo": "phishing"}) ─
    url_categories = set()
    categories_dict = data.get("categories", {})
    for _vendor, cat_label in categories_dict.items():
        if cat_label:
            url_categories.add(cat_label.strip().lower())

    return {
        "malware_types": sorted(malware_types)[:5],
        "threat_names": sorted(threat_names)[:5],
        "detection_engines": detection_engines[:10],
        "categories": sorted(url_categories)[:5],
    }


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
                details = _extract_malware_details(analysis)
                return LinkScanResult(
                    url=url,
                    malicious_count=malicious,
                    suspicious_count=suspicious,
                    is_flagged=(malicious + suspicious) > 0,
                    **details
                )
            return LinkScanResult(url=url, error="Submitted for scan, results pending")

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            details = _extract_malware_details(data)
            return LinkScanResult(
                url=url,
                malicious_count=malicious,
                suspicious_count=suspicious,
                is_flagged=(malicious + suspicious) > 0,
                **details
            )

        return LinkScanResult(url=url, error=f"VT returned status {resp.status_code}")

    except Exception as e:
        return LinkScanResult(url=url, error=str(e))


def scan_links(body: str) -> list[LinkScanResult]:
    """
    Extract all URLs from email body and scan them with VirusTotal.
    Returns empty list if no API key is configured.
    URLs are scanned in parallel for performance.
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

    # Scan URLs in parallel (VT free tier: 4 requests/minute — limit to 5 URLs)
    from concurrent.futures import ThreadPoolExecutor, as_completed

    urls_to_scan = urls[:5]
    results = []

    with ThreadPoolExecutor(max_workers=min(3, len(urls_to_scan))) as executor:
        future_to_url = {
            executor.submit(scan_single_url, url, api_key): url
            for url in urls_to_scan
        }
        for future in as_completed(future_to_url):
            try:
                results.append(future.result())
            except Exception as e:
                url = future_to_url[future]
                results.append(LinkScanResult(url=url, error=str(e)))

    return results
