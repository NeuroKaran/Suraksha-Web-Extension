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

from models import EmailRequest, AnalysisResponse, OSINTReport
from osint.domain_checker import check_domain
from osint.link_scanner import scan_links
from osint.email_checker import check_email
from ai.synthesizer import analyze_email

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

# CORS — allow Chrome extension to call this server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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

    # Run blocking OSINT functions in thread pool
    domain_task = loop.run_in_executor(None, check_domain, request.sender)
    links_task = loop.run_in_executor(None, scan_links, request.body)
    email_task = loop.run_in_executor(None, check_email, request.sender)

    domain_result, link_results, email_result = await asyncio.gather(
        domain_task, links_task, email_task
    )

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
    if email_result.error:
        print(f"   📧 Email check: {email_result.error}")
    else:
        print(f"   📧 Email breach: {'⚠️ Yes' if email_result.is_breached else '✅ No'}")

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
        sender=request.sender
    )

    # Terminal output for live demo
    verdict_icon = {"Dangerous": "🔴", "Suspicious": "🟡", "Safe": "🟢"}.get(ai_result["verdict"], "⚪")
    print(f"\n{'═' * 60}")
    print(f"   {verdict_icon} VERDICT: {ai_result['verdict']} (Score: {ai_result['score']}/100)")
    print(f"   💬 {ai_result['explanation']}")
    print(f"   ⏱️  Completed in {elapsed:.2f}s")
    print(f"{'═' * 60}\n")

    return response


# ─── Run with: uvicorn main:app --reload ─────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
