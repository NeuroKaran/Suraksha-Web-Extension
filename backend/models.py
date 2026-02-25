"""
Suraksha — Pydantic Models
Request and response schemas for the /analyze-email endpoint.
"""

import re
from pydantic import BaseModel, Field, field_validator
from typing import Optional

# Simple email regex — no extra dependencies needed
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


class EmailRequest(BaseModel):
    """Incoming email data from the Chrome extension."""
    sender: str = Field(..., description="Sender's email address")
    subject: str = Field(..., max_length=500, description="Email subject line")
    body: str = Field(..., max_length=50000, description="Full email body text (max ~50KB)")

    @field_validator("sender")
    @classmethod
    def validate_sender_email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError(f"Invalid email format: {v}")
        return v


class DomainAgeResult(BaseModel):
    """Result of WHOIS domain age check."""
    domain: str
    creation_date: Optional[str] = None
    age_days: Optional[int] = None
    is_suspicious: bool = False
    error: Optional[str] = None


class LinkScanResult(BaseModel):
    """Result of VirusTotal link scan for a single URL."""
    url: str
    malicious_count: int = 0
    suspicious_count: int = 0
    is_flagged: bool = False
    malware_types: list[str] = []         # e.g. ["trojan", "malware", "phishing"]
    threat_names: list[str] = []          # e.g. ["Trojan.GenericKD.46543"]
    detection_engines: list[str] = []     # e.g. ["Kaspersky", "BitDefender"]
    categories: list[str] = []            # e.g. ["malware", "phishing"]
    error: Optional[str] = None


class EmailBreachResult(BaseModel):
    """Result of HaveIBeenPwned email breach check."""
    email: str
    is_breached: bool = False
    breach_count: int = 0
    breaches: list[str] = []
    error: Optional[str] = None


class OSINTReport(BaseModel):
    """Compiled OSINT evidence report."""
    domain_age: Optional[DomainAgeResult] = None
    link_scan: list[LinkScanResult] = []
    email_breach: Optional[EmailBreachResult] = None


class AnalysisResponse(BaseModel):
    """Final analysis response sent back to the Chrome extension."""
    score: int = Field(..., ge=1, le=100, description="Safety score: 1 = extremely dangerous, 100 = perfectly safe")
    verdict: str = Field(..., description="One-word verdict: Safe, Suspicious, or Dangerous")
    explanation: str = Field(..., description="One-sentence human-readable explanation")
    details: OSINTReport = Field(default_factory=OSINTReport, description="Detailed OSINT evidence")
    sender: Optional[str] = None
    checks_completed: list[str] = Field(
        default_factory=list,
        description="List of OSINT checks that ran successfully (e.g. 'domain_age', 'link_scan', 'email_breach')"
    )


# ═══════════════════════════════════════════════════════════════
# Webpage Analysis Models (multi-site risk detection)
# ═══════════════════════════════════════════════════════════════

class FormSignal(BaseModel):
    """A suspicious form detected on the page."""
    action: str = ""
    method: str = "GET"
    has_password_field: bool = False
    has_hidden_fields: bool = False
    hidden_field_count: int = 0
    is_cross_domain: bool = False
    input_types: list[str] = []

class LinkSignal(BaseModel):
    """A suspicious link detected on the page."""
    href: str
    visible_text: str = ""
    is_mismatched: bool = False
    is_shortened: bool = False

class PageSignals(BaseModel):
    """Client-side extracted signals from a webpage (privacy-first: no raw page content)."""
    suspicious_forms: list[FormSignal] = []
    suspicious_links: list[LinkSignal] = []
    urgency_keywords_found: list[str] = []
    scam_keywords_found: list[str] = []
    has_login_form: bool = False
    has_payment_form: bool = False
    is_https: bool = True
    external_domain_forms: list[str] = []
    page_domain: str = ""
    link_count: int = 0
    form_count: int = 0

class PageAnalysisRequest(BaseModel):
    """Incoming webpage data from the Chrome extension."""
    url: str = Field(..., max_length=2000, description="Current page URL")
    page_type: str = Field(..., description="Detected page type: gmail, social_media, ecommerce, generic")
    title: str = Field("", max_length=500, description="Page title")
    signals: PageSignals = Field(default_factory=PageSignals, description="Client-extracted signals")
    urls_to_scan: list[str] = Field(default_factory=list, description="Suspicious URLs to scan via VirusTotal")

    @field_validator("page_type")
    @classmethod
    def validate_page_type(cls, v: str) -> str:
        allowed = {"gmail", "social_media", "ecommerce", "generic"}
        if v not in allowed:
            raise ValueError(f"Invalid page_type: {v}. Must be one of {allowed}")
        return v

class PageAnalysisResponse(BaseModel):
    """Analysis response for a webpage scan."""
    score: int = Field(..., ge=1, le=100, description="Safety score: 1 = extremely dangerous, 100 = perfectly safe")
    verdict: str = Field(..., description="One-word verdict: Safe, Suspicious, or Dangerous")
    explanation: str = Field(..., description="One-sentence human-readable explanation")
    risk_factors: list[str] = Field(default_factory=list, description="Specific risk factors found")
    page_type: str = Field(..., description="What type of page was analyzed")
    page_url: str = ""
    checks_completed: list[str] = Field(
        default_factory=list,
        description="List of checks that ran successfully"
    )
    details: OSINTReport = Field(default_factory=OSINTReport, description="OSINT evidence (link scans, domain check)")
