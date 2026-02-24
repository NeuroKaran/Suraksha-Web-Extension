"""
Suraksha — Pydantic Models
Request and response schemas for the /analyze-email endpoint.
"""

from pydantic import BaseModel, Field
from typing import Optional


class EmailRequest(BaseModel):
    """Incoming email data from the Chrome extension."""
    sender: str = Field(..., description="Sender's email address")
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Full email body text")


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
