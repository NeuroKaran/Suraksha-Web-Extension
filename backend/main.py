"""
Suraksha — FastAPI Backend
Central hub connecting the Chrome Extension to OSINT tools and AI analysis.
"""

import asyncio
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from models import (
    EmailRequest, AnalysisResponse, OSINTReport, DomainAgeResult, EmailBreachResult,
    PageAnalysisRequest, PageAnalysisResponse
)
from osint.domain_checker import check_domain
from osint.link_scanner import scan_links, scan_single_url, extract_urls
from osint.email_checker import check_email
from ai.synthesizer import analyze_email
from ai.page_synthesizer import analyze_page

# Load environment variables from .env file
load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("🛡️  Suraksha Backend — Starting Up")
    print("=" * 60)
    yield
    print("\n🛡️  Suraksha Backend — Shutting Down")


app = FastAPI(
    title="Suraksha API",
    description="AI-powered phishing detection backend with OSINT tools",
    version="1.0.0",
    lifespan=lifespan
)

# CORS — only allow Chrome extension and local dev to call this server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "chrome-extension://*",   # Chrome extensions
        "http://localhost:3000",   # Local dev frontend
    ],
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "Suraksha"}


@app.post("/analyze-email", response_model=AnalysisResponse)
async def analyze_email_endpoint(request: EmailRequest):
    """
    Main analysis endpoint.
    Receives email data, runs OSINT checks, synthesizes with AI,
    and returns a safety score with explanation.
    """
    start_time = time.time()

    print(f"\n{'─' * 60}")
    print(f"📧 Analyzing email from: {request.sender}")
    print(f"   Subject: {request.subject}")
    print(f"{'─' * 60}")

    # ── Step 1: Run OSINT checks in parallel ──────────────────────
    print("🔍 Running OSINT checks...")

    loop = asyncio.get_event_loop()
    checks_completed = []

    # Run blocking OSINT functions in thread pool
    domain_task = loop.run_in_executor(None, check_domain, request.sender)
    links_task = loop.run_in_executor(None, scan_links, request.body)
    email_task = loop.run_in_executor(None, check_email, request.sender)

    # Use return_exceptions=True so one failure doesn't cancel the others
    results = await asyncio.gather(
        domain_task, links_task, email_task,
        return_exceptions=True
    )

    # Safely unpack results — replace exceptions with defaults
    if isinstance(results[0], Exception):
        print(f"   ⚠️ Domain check failed: {results[0]}")
        domain_result = DomainAgeResult(domain=request.sender.split('@')[-1], error=str(results[0]))
    else:
        domain_result = results[0]
        checks_completed.append("domain_age")

    if isinstance(results[1], Exception):
        print(f"   ⚠️ Link scan failed: {results[1]}")
        link_results = []
    else:
        link_results = results[1]
        checks_completed.append("link_scan")

    if isinstance(results[2], Exception):
        print(f"   ⚠️ Email check failed: {results[2]}")
        email_result = EmailBreachResult(email=request.sender, error=str(results[2]))
    else:
        email_result = results[2]
        checks_completed.append("email_breach")

    # Compile OSINT report
    osint_report = OSINTReport(
        domain_age=domain_result,
        link_scan=link_results,
        email_breach=email_result
    )

    print(f"   🌐 Domain: {domain_result.domain} — {'⚠️ Suspicious' if domain_result.is_suspicious else '✅ OK'}")
    print(f"   🔗 Links scanned: {len(link_results)}")
    flagged = sum(1 for l in link_results if l.is_flagged)
    if flagged:
        print(f"   🚩 Flagged links: {flagged}")
        for l in link_results:
            if l.is_flagged:
                types = ", ".join(l.malware_types) if l.malware_types else "Unknown"
                threats = ", ".join(l.threat_names[:3]) if l.threat_names else "—"
                engines = ", ".join(l.detection_engines[:3]) if l.detection_engines else "—"
                print(f"      🦠 {l.url[:60]}")
                print(f"         Type: {types} | Threats: {threats}")
                print(f"         Detected by: {engines}")
    if email_result.error:
        print(f"   📧 Email check: {email_result.error}")
    else:
        print(f"   📧 Email breach: {'⚠️ Yes' if email_result.is_breached else '✅ No'}")
    print(f"   ✅ Checks completed: {', '.join(checks_completed) if checks_completed else 'none'}")

    # ── Step 2: AI Synthesis ──────────────────────────────────────
    print("🧠 Running AI analysis...")

    ai_result = await loop.run_in_executor(
        None, analyze_email, request.sender, request.subject, request.body, osint_report
    )

    elapsed = time.time() - start_time

    # ── Step 3: Build response ────────────────────────────────────
    response = AnalysisResponse(
        score=ai_result["score"],
        verdict=ai_result["verdict"],
        explanation=ai_result["explanation"],
        details=osint_report,
        sender=request.sender,
        checks_completed=checks_completed
    )

    # Terminal output for live demo
    verdict_icon = {"Dangerous": "🔴", "Suspicious": "🟡", "Safe": "🟢"}.get(ai_result["verdict"], "⚪")
    print(f"\n{'═' * 60}")
    print(f"   {verdict_icon} VERDICT: {ai_result['verdict']} (Score: {ai_result['score']}/100)")
    print(f"   💬 {ai_result['explanation']}")
    print(f"   ⏱️  Completed in {elapsed:.2f}s")
    print(f"{'═' * 60}\n")

    return response


@app.post("/analyze-page", response_model=PageAnalysisResponse)
async def analyze_page_endpoint(request: PageAnalysisRequest):
    """
    Webpage analysis endpoint.
    Receives client-extracted page signals, runs OSINT checks,
    and returns a safety score with risk factors.
    """
    start_time = time.time()

    print(f"\n{'─' * 60}")
    print(f"🌐 Analyzing page: {request.url[:80]}")
    print(f"   Type: {request.page_type} | Title: {request.title[:60]}")
    print(f"{'─' * 60}")

    # ── Step 1: Run OSINT checks ──────────────────────────────────
    print("🔍 Running OSINT checks on page...")

    loop = asyncio.get_event_loop()
    checks_completed = []

    # Domain check on the page's own domain
    page_domain = request.signals.page_domain or request.url.split('//')[-1].split('/')[0]
    domain_task = loop.run_in_executor(None, check_domain, f"user@{page_domain}")

    # Link scan — scan suspicious URLs extracted by the client
    urls_to_scan = request.urls_to_scan[:5]  # Cap at 5 URLs
    link_results = []
    if urls_to_scan:
        links_task = loop.run_in_executor(
            None, scan_links, " ".join(urls_to_scan)
        )
    else:
        links_future = loop.create_future()
        links_future.set_result([])
        links_task = links_future

    results = await asyncio.gather(
        domain_task, links_task,
        return_exceptions=True
    )

    # Safely unpack
    if isinstance(results[0], Exception):
        print(f"   ⚠️ Domain check failed: {results[0]}")
        domain_result = DomainAgeResult(domain=page_domain, error=str(results[0]))
    else:
        domain_result = results[0]
        checks_completed.append("domain_age")

    if isinstance(results[1], Exception):
        print(f"   ⚠️ Link scan failed: {results[1]}")
        link_results = []
    else:
        link_results = results[1]
        if link_results:
            checks_completed.append("link_scan")

    osint_report = OSINTReport(
        domain_age=domain_result,
        link_scan=link_results,
    )

    print(f"   🌐 Domain: {domain_result.domain} — {'⚠️ Suspicious' if domain_result.is_suspicious else '✅ OK'}")
    print(f"   🔗 Links scanned: {len(link_results)}")
    print(f"   📝 Signals: {len(request.signals.suspicious_forms)} forms, {len(request.signals.suspicious_links)} suspicious links")
    print(f"   ✅ Checks completed: {', '.join(checks_completed) if checks_completed else 'none'}")

    # ── Step 2: AI Synthesis ──────────────────────────────────────
    print("🧠 Running AI page analysis...")

    ai_result = await loop.run_in_executor(
        None, analyze_page,
        request.url, request.page_type, request.title,
        request.signals, osint_report
    )

    elapsed = time.time() - start_time

    # ── Step 3: Build response ────────────────────────────────────
    response = PageAnalysisResponse(
        score=ai_result["score"],
        verdict=ai_result["verdict"],
        explanation=ai_result["explanation"],
        risk_factors=ai_result.get("risk_factors", []),
        page_type=request.page_type,
        page_url=request.url,
        checks_completed=checks_completed,
        details=osint_report,
    )

    verdict_icon = {"Dangerous": "🔴", "Suspicious": "🟡", "Safe": "🟢"}.get(ai_result["verdict"], "⚪")
    print(f"\n{'═' * 60}")
    print(f"   {verdict_icon} PAGE VERDICT: {ai_result['verdict']} (Score: {ai_result['score']}/100)")
    print(f"   💬 {ai_result['explanation'][:100]}")
    if ai_result.get('risk_factors'):
        print(f"   ⚠️  Risk factors: {len(ai_result['risk_factors'])}")
    print(f"   ⏱️  Completed in {elapsed:.2f}s")
    print(f"{'═' * 60}\n")

    return response


# ─── Run with: uvicorn main:app --reload ─────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
