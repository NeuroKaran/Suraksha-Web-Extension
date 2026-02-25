// Suraksha — Gmail Content Script
// Scrapes email data, runs client-side pre-filter, injects analysis banner
// Privacy-first: extracts local signals before sending to backend

(function () {
    "use strict";

    let lastAnalyzedEmail = null;
    let bannerElement = null;
    let hashCheckInterval = null;
    let domObserver = null;

    // ─── Extension Context Check ─────────────────────────────────────
    // When the extension is reloaded/updated, the old content script
    // stays alive but chrome.runtime becomes invalid. This helper
    // lets us detect that and bail out gracefully.

    function isExtensionContextValid() {
        try {
            return !!chrome.runtime && !!chrome.runtime.id;
        } catch (e) {
            return false;
        }
    }

    function cleanupOnInvalidContext() {
        console.warn("[Suraksha] ⚠️ Extension context invalidated. Cleaning up…");
        if (hashCheckInterval) { clearInterval(hashCheckInterval); hashCheckInterval = null; }
        if (domObserver) { domObserver.disconnect(); domObserver = null; }
        if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
        const banner = document.getElementById("Suraksha-banner");
        if (banner) banner.remove();
    }

    // ─── HTML Escape (XSS Prevention) ────────────────────────────────

    function escapeHtml(str) {
        if (!str) return "";
        const div = document.createElement("div");
        div.textContent = String(str);
        return div.innerHTML;
    }

    // ─── Client-Side Pre-Filter (Privacy) ────────────────────────────
    // Extracts local signals from the email without sending raw content
    // to backend — addresses "without excessive surveillance" constraint

    const URGENCY_KEYWORDS = [
        "urgent", "immediately", "right now", "asap", "within 24 hours",
        "suspended", "locked", "verify your", "confirm your", "click here",
        "act now", "limited time", "expire", "deadline", "warning",
        "unauthorized", "suspicious activity", "unusual sign-in",
        "verify your identity", "account suspension", "payment failed"
    ];

    const PHISHING_KEYWORDS = [
        "password", "bank account", "credit card", "social security",
        "ssn", "login credentials", "wire transfer", "bitcoin",
        "gift card", "prize", "winner", "lottery", "inheritance",
        "bank details", "routing number", "one-time code", "otp"
    ];

    function extractLocalSignals(sender, subject, body) {
        const combined = `${subject} ${body}`.toLowerCase();

        // Count urgency hits
        const urgencyHits = URGENCY_KEYWORDS.filter(kw => combined.includes(kw));

        // Count phishing keyword hits
        const phishingHits = PHISHING_KEYWORDS.filter(kw => combined.includes(kw));

        // Extract URLs from body
        const urlMatches = body.match(/https?:\/\/[^\s<>"'\)\]]+/gi) || [];
        const urls = [...new Set(urlMatches.map(u => u.replace(/[.,;:!?)]+$/, "")))];

        // Check sender domain
        const senderDomain = sender.split("@").pop()?.toLowerCase() || "";

        // Quick local verdict — can we skip the backend call?
        const riskScore = urgencyHits.length * 10 + phishingHits.length * 15 + (urls.length > 3 ? 10 : 0);

        return {
            urgencyCount: urgencyHits.length,
            urgencyKeywords: urgencyHits.slice(0, 5),
            phishingCount: phishingHits.length,
            phishingKeywords: phishingHits.slice(0, 5),
            urlCount: urls.length,
            urls: urls.slice(0, 10),
            senderDomain,
            localRiskScore: Math.min(riskScore, 100),
            bodyLength: body.length,
        };
    }

    // ─── Email Scraping ──────────────────────────────────────────────

    /**
     * Find the currently visible/active email message container.
     * Gmail keeps old email DOM nodes around when navigating, so we
     * need the LAST (most recently opened) visible message, not the first.
     */
    function getActiveMessageContainer() {
        // All open email messages — Gmail uses div.a3s.aiL for the body
        // The last one in the DOM is typically the currently viewed email
        const bodies = document.querySelectorAll("div.a3s.aiL");
        if (bodies.length === 0) return null;

        // Return the last visible one (most recently rendered by Gmail)
        for (let i = bodies.length - 1; i >= 0; i--) {
            if (bodies[i].offsetParent !== null) return bodies[i].closest('[data-message-id]') || bodies[i];
        }
        // Fallback to the last one regardless
        return bodies[bodies.length - 1].closest('[data-message-id]') || bodies[bodies.length - 1];
    }

    function getSenderEmail() {
        const container = getActiveMessageContainer();

        if (container) {
            // Strategy 1: Look for .gD (Gmail "From" header) — most reliable
            // Walk up to find the message wrapper that contains both header and body
            const messageWrapper = container.closest('.gs') || container.closest('.h7') ||
                container.closest('[data-message-id]') || container.parentElement;

            if (messageWrapper) {
                // .gD is the specific "From" name element in Gmail with an email attribute
                const fromHeader = messageWrapper.querySelector(".gD");
                if (fromHeader) {
                    const email = fromHeader.getAttribute("email");
                    if (email) return email;
                }

                // Strategy 2: Look for span[email] but only in the header area (not body)
                // The header row typically lives in a .kv or .iw div
                const headerArea = messageWrapper.querySelector(".kv") || messageWrapper.querySelector(".iw");
                if (headerArea) {
                    const senderSpan = headerArea.querySelector('span[email]');
                    if (senderSpan) return senderSpan.getAttribute("email");
                }

                // Strategy 3: Any span[email] in the message wrapper, but NOT inside the body
                const bodyEl = messageWrapper.querySelector("div.a3s.aiL");
                const allSpans = messageWrapper.querySelectorAll('span[email]');
                for (const span of allSpans) {
                    // Skip if this span is inside the email body content
                    if (bodyEl && bodyEl.contains(span)) continue;
                    return span.getAttribute("email");
                }
            }
        }

        // Fallback: find .gD elements (From headers) — these are the most specific
        // Use the LAST one as it's the most recently rendered email
        const allFromHeaders = document.querySelectorAll(".gD");
        if (allFromHeaders.length > 0) {
            const last = allFromHeaders[allFromHeaders.length - 1];
            const email = last.getAttribute("email");
            if (email) return email;
            return last.textContent.trim();
        }

        // Last resort: span[email] NOT inside any email body
        const allBodies = document.querySelectorAll("div.a3s.aiL");
        const allSenders = document.querySelectorAll('span[email]');
        for (let i = allSenders.length - 1; i >= 0; i--) {
            let insideBody = false;
            for (const body of allBodies) {
                if (body.contains(allSenders[i])) { insideBody = true; break; }
            }
            if (!insideBody) return allSenders[i].getAttribute("email");
        }

        return null;
    }

    function getSubjectLine() {
        // Subject is typically global (one per thread view) — grab the last h2.hP
        const subjectEls = document.querySelectorAll("h2.hP");
        if (subjectEls.length > 0) return subjectEls[subjectEls.length - 1].textContent.trim();

        // Fallback: document title often contains the subject
        const title = document.title.replace(" - Gmail", "").trim();
        return title || null;
    }

    function getEmailBody() {
        const container = getActiveMessageContainer();
        if (container) {
            // If container IS the body div, use it directly
            if (container.classList.contains("a3s")) return container.innerText.trim();
            // Otherwise find the body within it
            const bodyEl = container.querySelector("div.a3s.aiL");
            if (bodyEl) return bodyEl.innerText.trim();
            // Last resort: get the text content of the container
            return container.innerText.trim();
        }

        // Fallback: last body div in the DOM
        const allBodies = document.querySelectorAll("div.a3s.aiL");
        if (allBodies.length > 0) return allBodies[allBodies.length - 1].innerText.trim();

        const msgBody = document.querySelector('[data-message-id] .ii.gt');
        if (msgBody) return msgBody.innerText.trim();

        return null;
    }

    // ─── Banner UI ───────────────────────────────────────────────────

    function createBanner() {
        // Reuse only if the banner is still attached to the live DOM
        if (bannerElement && document.contains(bannerElement)) return bannerElement;

        bannerElement = document.createElement("div");
        bannerElement.id = "Suraksha-banner";

        // Guard chrome.runtime.getURL — context may be invalidated
        let iconUrl = '';
        try {
            if (isExtensionContextValid()) {
                iconUrl = chrome.runtime.getURL('icons/icon48.png');
            }
        } catch (e) {
            console.warn("[Suraksha] Could not get icon URL — extension context invalid");
        }

        bannerElement.innerHTML = `
      <div class="Suraksha-inner">
        <div class="Suraksha-icon">
          ${iconUrl ? `<img src="${iconUrl}" alt="Suraksha" width="22" height="22" style="border-radius: 50%;" />` : '<span style="font-size:18px;">🛡️</span>'}
        </div>
        <div class="Suraksha-content">
          <span class="Suraksha-title">Suraksha</span>
          <span class="Suraksha-message">Analyzing email…</span>
        </div>
        <div class="Suraksha-score-badge">
          <span class="Suraksha-score">—</span>
        </div>
        <button class="Suraksha-close" title="Dismiss">&times;</button>
      </div>
      <div class="Suraksha-details" style="display:none;">
        <div class="Suraksha-details-content"></div>
      </div>
      <div class="Suraksha-feedback" style="display:none;">
        <span class="Suraksha-feedback-label">Was this analysis helpful?</span>
        <button class="Suraksha-feedback-btn Suraksha-feedback-up" title="Accurate">👍</button>
        <button class="Suraksha-feedback-btn Suraksha-feedback-down" title="Inaccurate">👎</button>
        <span class="Suraksha-feedback-thanks" style="display:none;">Thanks for your feedback!</span>
      </div>
    `;

        bannerElement.querySelector(".Suraksha-close").addEventListener("click", () => {
            bannerElement.classList.add("Suraksha-hidden");
        });

        bannerElement.querySelector(".Suraksha-inner").addEventListener("click", (e) => {
            if (e.target.closest(".Suraksha-close")) return;
            const details = bannerElement.querySelector(".Suraksha-details");
            details.style.display = details.style.display === "none" ? "block" : "none";
        });

        // Feedback button handlers
        bannerElement.querySelectorAll(".Suraksha-feedback-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const isPositive = btn.classList.contains("Suraksha-feedback-up");
                saveFeedback(isPositive);
                // Show thanks, hide buttons
                bannerElement.querySelectorAll(".Suraksha-feedback-btn").forEach(b => b.style.display = "none");
                bannerElement.querySelector(".Suraksha-feedback-label").style.display = "none";
                bannerElement.querySelector(".Suraksha-feedback-thanks").style.display = "inline";
            });
        });

        return bannerElement;
    }

    function saveFeedback(isPositive) {
        if (!isExtensionContextValid()) return;
        try {
            chrome.storage.local.get("feedbackHistory", (data) => {
                if (chrome.runtime.lastError) return;
                const history = data.feedbackHistory || [];
                history.push({
                    fingerprint: lastAnalyzedEmail,
                    feedback: isPositive ? "accurate" : "inaccurate",
                    timestamp: Date.now()
                });
                // Keep last 100 feedback entries
                if (history.length > 100) history.splice(0, history.length - 100);
                chrome.storage.local.set({ feedbackHistory: history });
                console.log(`[Suraksha] 📝 Feedback saved: ${isPositive ? "👍 accurate" : "👎 inaccurate"}`);
            });
        } catch (e) {
            console.warn("[Suraksha] Could not save feedback — extension context invalid");
        }
    }

    function injectBanner() {
        const existing = document.getElementById("Suraksha-banner");
        if (existing) existing.remove();

        const banner = createBanner();
        banner.className = "Suraksha-loading";
        banner.classList.remove("Suraksha-hidden");

        // Inject into the email view — target the message header area
        const emailContainer =
            document.querySelector(".nH.aHU") ||  // email view wrapper
            document.querySelector(".nH.bkK") ||  // alternative wrapper
            document.querySelector('[role="main"]');

        if (emailContainer) {
            emailContainer.insertBefore(banner, emailContainer.firstChild);
        } else {
            document.body.appendChild(banner);
        }

        return banner;
    }

    function updateBanner(result) {
        if (!bannerElement) return;

        const { score, verdict, explanation, details, checks_completed } = result;

        // Determine state
        let state = "safe";
        if (score < 40) state = "dangerous";
        else if (score < 70) state = "suspicious";

        // Update classes
        bannerElement.className = `Suraksha-${state}`;

        // Update content
        bannerElement.querySelector(".Suraksha-message").textContent = explanation || verdict;
        bannerElement.querySelector(".Suraksha-score").textContent = score;

        // Build details panel — all values are HTML-escaped to prevent XSS
        const detailsContent = bannerElement.querySelector(".Suraksha-details-content");

        // Score description — human-readable label for the numeric score
        let scoreLabel, scoreColorClass;
        if (score >= 80) {
            scoreLabel = "Excellent";
            scoreColorClass = "score-safe";
        } else if (score >= 70) {
            scoreLabel = "Good";
            scoreColorClass = "score-safe";
        } else if (score >= 55) {
            scoreLabel = "Moderate Risk";
            scoreColorClass = "score-suspicious";
        } else if (score >= 40) {
            scoreLabel = "High Risk";
            scoreColorClass = "score-suspicious";
        } else if (score >= 20) {
            scoreLabel = "Dangerous";
            scoreColorClass = "score-dangerous";
        } else {
            scoreLabel = "Critical Threat";
            scoreColorClass = "score-dangerous";
        }

        // Use the actual explanation from the backend instead of a generic message
        const scoreDesc = explanation || verdict || "Analysis complete.";

        let detailsHTML = `
          <div class="Suraksha-score-description">
            <div class="Suraksha-score-header">
              <span class="Suraksha-score-label ${scoreColorClass}">${escapeHtml(scoreLabel)}</span>
              <span class="Suraksha-score-value ${scoreColorClass}">${score}/100</span>
            </div>
            <div class="Suraksha-score-bar">
              <div class="Suraksha-score-fill ${scoreColorClass}" style="width: ${score}%"></div>
            </div>
            <div class="Suraksha-score-desc">${escapeHtml(scoreDesc)}</div>
          </div>
          <strong>Verdict:</strong> ${escapeHtml(verdict)}<br>`;

        // Show which OSINT checks completed (transparency)
        if (checks_completed && checks_completed.length > 0) {
            detailsHTML += `<div class="Suraksha-detail-item">
              <strong>✅ Checks completed:</strong> ${escapeHtml(checks_completed.join(", "))}
            </div>`;
        } else if (checks_completed && checks_completed.length === 0) {
            detailsHTML += `<div class="Suraksha-detail-item">
              <strong>⚠️ Warning:</strong> No OSINT checks could be completed — result is based on AI/rules only
            </div>`;
        }

        if (details) {
            if (details.domain_age) {
                const da = details.domain_age;
                detailsHTML += `<div class="Suraksha-detail-item">
          <strong>🌐 Domain:</strong> ${escapeHtml(da.domain)} — 
          ${da.is_suspicious ? "⚠️ Suspicious" : "✅ Legitimate"} 
          (${da.age_days != null ? da.age_days + " days old" : "Unknown age"})
        </div>`;
            }
            if (details.link_scan && details.link_scan.length > 0) {
                detailsHTML += `<div class="Suraksha-detail-item"><strong>🔗 Link Scan:</strong><ul>`;
                details.link_scan.forEach((l) => {
                    const icon = l.is_flagged ? "🚩" : "✅";
                    detailsHTML += `<li>${icon} ${escapeHtml(l.url)} (${parseInt(l.malicious_count) || 0} malicious detections)`;
                    if (l.is_flagged) {
                        if (l.malware_types && l.malware_types.length > 0) {
                            detailsHTML += `<br><span style="margin-left:8px;color:#ff6b6b;">🦠 Type: <strong>${escapeHtml(l.malware_types.join(', '))}</strong></span>`;
                        }
                        if (l.threat_names && l.threat_names.length > 0) {
                            detailsHTML += `<br><span style="margin-left:8px;color:#ffa94d;">⚠️ Threats: ${escapeHtml(l.threat_names.slice(0, 3).join(', '))}</span>`;
                        }
                        if (l.detection_engines && l.detection_engines.length > 0) {
                            detailsHTML += `<br><span style="margin-left:8px;color:#868e96;">🔍 Detected by: ${escapeHtml(l.detection_engines.slice(0, 5).join(', '))}</span>`;
                        }
                        if (l.categories && l.categories.length > 0) {
                            detailsHTML += `<br><span style="margin-left:8px;color:#da77f2;">🏷️ Categories: ${escapeHtml(l.categories.join(', '))}</span>`;
                        }
                    }
                    detailsHTML += `</li>`;
                });
                detailsHTML += `</ul></div>`;
            }
            if (details.email_breach) {
                const eb = details.email_breach;
                detailsHTML += `<div class="Suraksha-detail-item">
          <strong>📧 Email Reputation:</strong> 
          ${eb.is_breached ? `⚠️ Found in ${parseInt(eb.breach_count) || 0} breach(es)` : "✅ No known breaches"}
        </div>`;
            }
        }

        detailsContent.innerHTML = detailsHTML;

        // Show feedback buttons
        const feedbackEl = bannerElement.querySelector(".Suraksha-feedback");
        if (feedbackEl) feedbackEl.style.display = "flex";

        // Store result for popup — include timestamp and fingerprint for staleness detection
        if (isExtensionContextValid()) {
            try {
                chrome.storage.local.set({
                    lastAnalysis: {
                        ...result,
                        fingerprint: lastAnalyzedEmail,
                        timestamp: Date.now()
                    }
                });
            } catch (e) {
                console.warn("[Suraksha] Could not save analysis result — extension context invalid");
            }
        }
    }

    function showBannerError(message) {
        if (!bannerElement) return;
        bannerElement.className = "Suraksha-error";
        bannerElement.querySelector(".Suraksha-message").textContent = message;
        bannerElement.querySelector(".Suraksha-score").textContent = "!";
    }

    // ─── Analysis Pipeline ──────────────────────────────────────────

    async function analyzeCurrentEmail() {
        // Bail out early if extension was reloaded
        if (!isExtensionContextValid()) {
            cleanupOnInvalidContext();
            return;
        }

        const sender = getSenderEmail();
        const subject = getSubjectLine();
        const body = getEmailBody();

        if (!sender || !body) return; // Not viewing a full email

        // Avoid re-analyzing the same email
        const emailFingerprint = `${sender}|${subject}|${body.substring(0, 100)}`;
        if (emailFingerprint === lastAnalyzedEmail) return;
        lastAnalyzedEmail = emailFingerprint;

        // ── Client-side pre-filter (privacy-first) ──
        const signals = extractLocalSignals(sender, subject, body);
        console.log(`[Suraksha] 🔍 Local signals: risk=${signals.localRiskScore}, urgency=${signals.urgencyCount}, phishing=${signals.phishingCount}, urls=${signals.urlCount}`);

        // Inject the banner
        injectBanner();

        try {
            // Check again right before the API call
            if (!isExtensionContextValid()) {
                cleanupOnInvalidContext();
                return;
            }

            const response = await chrome.runtime.sendMessage({
                type: "ANALYZE_EMAIL",
                payload: {
                    sender,
                    subject,
                    body,
                    // Include local signals so the backend knows what was pre-filtered
                    local_signals: signals
                },
            });

            if (!response || !response.success) {
                throw new Error(response?.error || "No response from background");
            }

            updateBanner(response.data);
        } catch (err) {
            // Detect context-invalidated specifically and clean up
            if (err.message?.includes("Extension context invalidated")) {
                cleanupOnInvalidContext();
                return;
            }
            console.error("[Suraksha] Analysis failed:", err);
            showBannerError("Could not connect to Suraksha server");
        }
    }

    // ─── Gmail DOM Observer ──────────────────────────────────────────

    let lastUrlHash = location.hash;
    let debounceTimer = null;

    function startObserving() {
        // Watch for Gmail URL hash changes (e.g. switching emails)
        // Gmail uses hash-based routing like #inbox/FMfcgzQXKbvf...
        hashCheckInterval = setInterval(() => {
            // Stop polling if extension was reloaded
            if (!isExtensionContextValid()) {
                cleanupOnInvalidContext();
                return;
            }
            if (location.hash !== lastUrlHash) {
                lastUrlHash = location.hash;
                lastAnalyzedEmail = null; // Reset so the new email gets analyzed
                bannerElement = null;     // Reset banner for fresh injection
                console.log("[Suraksha] 📬 Navigation detected, ready for new email");
                // Give Gmail time to render the new email
                if (debounceTimer) clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    debounceTimer = null;
                    analyzeCurrentEmail();
                }, 1200);
            }
        }, 500);

        // Observe DOM changes in email pane only (not entire body)
        // This dramatically reduces unnecessary mutation callbacks
        const observeTarget = document.querySelector('[role="main"]') || document.body;

        domObserver = new MutationObserver(() => {
            // Stop observing if extension was reloaded
            if (!isExtensionContextValid()) {
                cleanupOnInvalidContext();
                return;
            }
            const emailView = document.querySelector("div.a3s.aiL") || document.querySelector("h2.hP");
            if (emailView && !debounceTimer) {
                debounceTimer = setTimeout(() => {
                    debounceTimer = null;
                    analyzeCurrentEmail();
                }, 1200);
            }
        });

        domObserver.observe(observeTarget, {
            childList: true,
            subtree: true,
        });

        console.log("[Suraksha] 🛡️ Content script loaded. Watching for emails…");
    }

    // ─── Page Scanning (Non-Gmail) ───────────────────────────────────
    // Multi-page risk detection: scans forms, links, and content on any webpage

    let pageAnalyzed = false;
    let pageBannerElement = null;

    function createPageBanner() {
        if (pageBannerElement && document.contains(pageBannerElement)) return pageBannerElement;

        pageBannerElement = document.createElement("div");
        pageBannerElement.id = "Suraksha-banner";
        pageBannerElement.className = "Suraksha-page-banner";

        let iconUrl = '';
        try {
            if (isExtensionContextValid()) {
                iconUrl = chrome.runtime.getURL('icons/icon48.png');
            }
        } catch (e) { /* extension context invalid */ }

        pageBannerElement.innerHTML = `
      <div class="Suraksha-inner">
        <div class="Suraksha-icon">
          ${iconUrl ? `<img src="${iconUrl}" alt="Suraksha" width="22" height="22" style="border-radius: 50%;" />` : '<span style="font-size:18px;">🛡️</span>'}
        </div>
        <div class="Suraksha-content">
          <span class="Suraksha-title">Suraksha</span>
          <span class="Suraksha-message">Analyzing page…</span>
        </div>
        <div class="Suraksha-score-badge">
          <span class="Suraksha-score">—</span>
        </div>
        <button class="Suraksha-close" title="Dismiss">&times;</button>
      </div>
      <div class="Suraksha-details" style="display:none;">
        <div class="Suraksha-details-content"></div>
      </div>
      <div class="Suraksha-feedback" style="display:none;">
        <span class="Suraksha-feedback-label">Was this analysis helpful?</span>
        <button class="Suraksha-feedback-btn Suraksha-feedback-up" title="Accurate">👍</button>
        <button class="Suraksha-feedback-btn Suraksha-feedback-down" title="Inaccurate">👎</button>
        <span class="Suraksha-feedback-thanks" style="display:none;">Thanks for your feedback!</span>
      </div>
    `;

        pageBannerElement.querySelector(".Suraksha-close").addEventListener("click", () => {
            pageBannerElement.classList.add("Suraksha-hidden");
        });

        pageBannerElement.querySelector(".Suraksha-inner").addEventListener("click", (e) => {
            if (e.target.closest(".Suraksha-close")) return;
            const details = pageBannerElement.querySelector(".Suraksha-details");
            details.style.display = details.style.display === "none" ? "block" : "none";
        });

        pageBannerElement.querySelectorAll(".Suraksha-feedback-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const isPositive = btn.classList.contains("Suraksha-feedback-up");
                saveFeedback(isPositive);
                pageBannerElement.querySelectorAll(".Suraksha-feedback-btn").forEach(b => b.style.display = "none");
                pageBannerElement.querySelector(".Suraksha-feedback-label").style.display = "none";
                pageBannerElement.querySelector(".Suraksha-feedback-thanks").style.display = "inline";
            });
        });

        return pageBannerElement;
    }

    function injectPageBanner() {
        const existing = document.getElementById("Suraksha-banner");
        if (existing) existing.remove();

        const banner = createPageBanner();
        banner.className = "Suraksha-page-banner Suraksha-loading";
        banner.classList.remove("Suraksha-hidden");

        document.body.appendChild(banner);
        return banner;
    }

    function updatePageBanner(result) {
        if (!pageBannerElement) return;

        const { score, verdict, explanation, risk_factors, page_type, checks_completed } = result;

        let state = "safe";
        if (score < 40) state = "dangerous";
        else if (score < 70) state = "suspicious";

        pageBannerElement.className = `Suraksha-page-banner Suraksha-${state}`;
        pageBannerElement.querySelector(".Suraksha-message").textContent = explanation || verdict;
        pageBannerElement.querySelector(".Suraksha-score").textContent = score;

        // Build details panel
        const detailsContent = pageBannerElement.querySelector(".Suraksha-details-content");

        let scoreLabel, scoreColorClass;
        if (score >= 80) { scoreLabel = "Excellent"; scoreColorClass = "score-safe"; }
        else if (score >= 70) { scoreLabel = "Good"; scoreColorClass = "score-safe"; }
        else if (score >= 55) { scoreLabel = "Moderate Risk"; scoreColorClass = "score-suspicious"; }
        else if (score >= 40) { scoreLabel = "High Risk"; scoreColorClass = "score-suspicious"; }
        else if (score >= 20) { scoreLabel = "Dangerous"; scoreColorClass = "score-dangerous"; }
        else { scoreLabel = "Critical Threat"; scoreColorClass = "score-dangerous"; }

        const typeIcons = { social_media: "💬", ecommerce: "🛒", generic: "🌐" };
        const typeIcon = typeIcons[page_type] || "🌐";

        let detailsHTML = `
          <div class="Suraksha-score-description">
            <div class="Suraksha-score-header">
              <span class="Suraksha-score-label ${scoreColorClass}">${typeIcon} ${escapeHtml(scoreLabel)}</span>
              <span class="Suraksha-score-value ${scoreColorClass}">${score}/100</span>
            </div>
            <div class="Suraksha-score-bar">
              <div class="Suraksha-score-fill ${scoreColorClass}" style="width: ${score}%"></div>
            </div>
            <div class="Suraksha-score-desc">${escapeHtml(explanation || verdict)}</div>
          </div>
          <strong>Verdict:</strong> ${escapeHtml(verdict)}<br>`;

        // Show risk factors
        if (risk_factors && risk_factors.length > 0) {
            detailsHTML += `<div class="Suraksha-detail-item">
              <strong>⚠️ Risk Factors:</strong><ul>`;
            risk_factors.forEach(rf => {
                detailsHTML += `<li>🚩 ${escapeHtml(rf)}</li>`;
            });
            detailsHTML += `</ul></div>`;
        }

        // Show link scan details with malware info (from OSINT report)
        if (result.details && result.details.link_scan && result.details.link_scan.length > 0) {
            detailsHTML += `<div class="Suraksha-detail-item"><strong>🔗 Link Scan:</strong><ul>`;
            result.details.link_scan.forEach((l) => {
                const icon = l.is_flagged ? "🚩" : "✅";
                detailsHTML += `<li>${icon} ${escapeHtml(l.url)} (${parseInt(l.malicious_count) || 0} malicious detections)`;
                if (l.is_flagged) {
                    if (l.malware_types && l.malware_types.length > 0) {
                        detailsHTML += `<br><span style="margin-left:8px;color:#ff6b6b;">🦠 Type: <strong>${escapeHtml(l.malware_types.join(', '))}</strong></span>`;
                    }
                    if (l.threat_names && l.threat_names.length > 0) {
                        detailsHTML += `<br><span style="margin-left:8px;color:#ffa94d;">⚠️ Threats: ${escapeHtml(l.threat_names.slice(0, 3).join(', '))}</span>`;
                    }
                    if (l.detection_engines && l.detection_engines.length > 0) {
                        detailsHTML += `<br><span style="margin-left:8px;color:#868e96;">🔍 Detected by: ${escapeHtml(l.detection_engines.slice(0, 5).join(', '))}</span>`;
                    }
                    if (l.categories && l.categories.length > 0) {
                        detailsHTML += `<br><span style="margin-left:8px;color:#da77f2;">🏷️ Categories: ${escapeHtml(l.categories.join(', '))}</span>`;
                    }
                }
                detailsHTML += `</li>`;
            });
            detailsHTML += `</ul></div>`;
        }

        // Show checks completed
        if (checks_completed && checks_completed.length > 0) {
            detailsHTML += `<div class="Suraksha-detail-item">
              <strong>✅ Checks completed:</strong> ${escapeHtml(checks_completed.join(", "))}
            </div>`;
        }

        detailsContent.innerHTML = detailsHTML;

        // Show feedback
        const feedbackEl = pageBannerElement.querySelector(".Suraksha-feedback");
        if (feedbackEl) feedbackEl.style.display = "flex";

        // Store for popup
        if (isExtensionContextValid()) {
            try {
                chrome.storage.local.set({
                    lastPageAnalysis: {
                        ...result,
                        timestamp: Date.now(),
                        url: window.location.href
                    }
                });
            } catch (e) { /* context invalid */ }
        }
    }

    async function runPageScan() {
        if (pageAnalyzed) return;
        if (!isExtensionContextValid()) return;
        if (!window.SurakshaPageDetectors) {
            console.log("[Suraksha] 🌐 Page detectors not loaded, skipping page scan");
            return;
        }

        const scanResult = window.SurakshaPageDetectors.detect();
        if (!scanResult) return; // Gmail page — handled by email observer

        pageAnalyzed = true;
        console.log(`[Suraksha] 🌐 Page scan running (${scanResult.riskType}): ${scanResult.signals.suspicious_forms.length} suspicious forms, ${scanResult.signals.suspicious_links.length} suspicious links`);

        // Inject loading banner
        injectPageBanner();

        // Collect suspicious URLs for VirusTotal scanning
        const urlsToScan = scanResult.signals.suspicious_links
            .map(l => l.href)
            .filter(href => href.startsWith("http"))
            .slice(0, 5);

        try {
            if (!isExtensionContextValid()) return;

            const response = await chrome.runtime.sendMessage({
                type: "ANALYZE_PAGE",
                payload: {
                    url: window.location.href,
                    page_type: scanResult.riskType,
                    title: document.title || "",
                    signals: scanResult.signals,
                    urls_to_scan: urlsToScan,
                },
            });

            if (!response || !response.success) {
                throw new Error(response?.error || "No response from background");
            }

            updatePageBanner(response.data);
        } catch (err) {
            if (err.message?.includes("Extension context invalidated")) {
                cleanupOnInvalidContext();
                return;
            }
            console.error("[Suraksha] Page analysis failed:", err);
            if (pageBannerElement) {
                pageBannerElement.className = "Suraksha-page-banner Suraksha-error";
                pageBannerElement.querySelector(".Suraksha-message").textContent = "Could not connect to Suraksha server";
                pageBannerElement.querySelector(".Suraksha-score").textContent = "!";
            }
        }
    }

    // ─── Initialization ──────────────────────────────────────────────

    function initialize() {
        const siteType = window.SurakshaDetectSiteType ? window.SurakshaDetectSiteType() : "unknown";

        if (siteType === "gmail") {
            // Gmail: use existing email observer
            startObserving();
        } else {
            // Non-Gmail pages: run page scanner after a brief delay
            console.log(`[Suraksha] 🛡️ Content script loaded on ${siteType} page. Scanning for risks…`);
            setTimeout(runPageScan, 2000);
        }
    }

    // Wait for page to fully load
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize);
    } else {
        initialize();
    }
})();

