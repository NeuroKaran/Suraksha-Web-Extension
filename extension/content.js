// Suraksha — Gmail Content Script
// Scrapes email data and injects analysis banner

(function () {
    "use strict";

    let lastAnalyzedEmail = null;
    let bannerElement = null;

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
        bannerElement.innerHTML = `
      <div class="Suraksha-inner">
        <div class="Suraksha-icon">
          <img src="${chrome.runtime.getURL('icons/icon48.png')}" alt="Suraksha" width="22" height="22" style="border-radius: 50%;" />
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
    `;

        bannerElement.querySelector(".Suraksha-close").addEventListener("click", () => {
            bannerElement.classList.add("Suraksha-hidden");
        });

        bannerElement.querySelector(".Suraksha-inner").addEventListener("click", (e) => {
            if (e.target.closest(".Suraksha-close")) return;
            const details = bannerElement.querySelector(".Suraksha-details");
            details.style.display = details.style.display === "none" ? "block" : "none";
        });

        return bannerElement;
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

        const { score, verdict, explanation, details } = result;

        // Determine state
        let state = "safe";
        if (score < 40) state = "dangerous";
        else if (score < 70) state = "suspicious";

        // Update classes
        bannerElement.className = `Suraksha-${state}`;

        // Update content
        bannerElement.querySelector(".Suraksha-message").textContent = explanation || verdict;
        bannerElement.querySelector(".Suraksha-score").textContent = score;

        // Build details panel
        const detailsContent = bannerElement.querySelector(".Suraksha-details-content");
        let detailsHTML = `<strong>Verdict:</strong> ${verdict}<br>`;

        if (details) {
            if (details.domain_age) {
                const da = details.domain_age;
                detailsHTML += `<div class="Suraksha-detail-item">
          <strong>🌐 Domain:</strong> ${da.domain} — 
          ${da.is_suspicious ? "⚠️ Suspicious" : "✅ Legitimate"} 
          (${da.age_days != null ? da.age_days + " days old" : "Unknown age"})
        </div>`;
            }
            if (details.link_scan && details.link_scan.length > 0) {
                detailsHTML += `<div class="Suraksha-detail-item"><strong>🔗 Link Scan:</strong><ul>`;
                details.link_scan.forEach((l) => {
                    const icon = l.is_flagged ? "🚩" : "✅";
                    detailsHTML += `<li>${icon} ${l.url} (${l.malicious_count} malicious detections)</li>`;
                });
                detailsHTML += `</ul></div>`;
            }
            if (details.email_breach) {
                const eb = details.email_breach;
                detailsHTML += `<div class="Suraksha-detail-item">
          <strong>📧 Email Reputation:</strong> 
          ${eb.is_breached ? `⚠️ Found in ${eb.breach_count} breach(es)` : "✅ No known breaches"}
        </div>`;
            }
        }

        detailsContent.innerHTML = detailsHTML;

        // Store result for popup
        chrome.storage.local.set({ lastAnalysis: result });
    }

    function showBannerError(message) {
        if (!bannerElement) return;
        bannerElement.className = "Suraksha-error";
        bannerElement.querySelector(".Suraksha-message").textContent = message;
        bannerElement.querySelector(".Suraksha-score").textContent = "!";
    }

    // ─── Analysis Pipeline ──────────────────────────────────────────

    async function analyzeCurrentEmail() {
        const sender = getSenderEmail();
        const subject = getSubjectLine();
        const body = getEmailBody();

        if (!sender || !body) return; // Not viewing a full email

        // Avoid re-analyzing the same email
        const emailFingerprint = `${sender}|${subject}|${body.substring(0, 100)}`;
        if (emailFingerprint === lastAnalyzedEmail) return;
        lastAnalyzedEmail = emailFingerprint;

        // Inject the banner
        injectBanner();

        try {
            const response = await chrome.runtime.sendMessage({
                type: "ANALYZE_EMAIL",
                payload: { sender, subject, body },
            });

            if (!response || !response.success) {
                throw new Error(response?.error || "No response from background");
            }

            updateBanner(response.data);
        } catch (err) {
            console.error("[Suraksha] Analysis failed:", err);
            showBannerError("Could not connect to Suraksha server");
        }
    }

    // ─── Gmail DOM Observer ──────────────────────────────────────────

    let lastUrlHash = location.hash;

    function startObserving() {
        // Watch for Gmail URL hash changes (e.g. switching emails)
        // Gmail uses hash-based routing like #inbox/FMfcgzQXKbvf...
        setInterval(() => {
            if (location.hash !== lastUrlHash) {
                lastUrlHash = location.hash;
                lastAnalyzedEmail = null; // Reset so the new email gets analyzed
                bannerElement = null;     // Reset banner for fresh injection
                console.log("[Suraksha] 📬 Navigation detected, ready for new email");
                // Give Gmail time to render the new email
                clearTimeout(window.__SurakshaTimeout);
                window.__SurakshaTimeout = setTimeout(analyzeCurrentEmail, 1200);
            }
        }, 500);

        // Also observe DOM changes as a secondary trigger
        const observer = new MutationObserver((mutations) => {
            const emailView = document.querySelector("div.a3s.aiL") || document.querySelector("h2.hP");
            if (emailView) {
                clearTimeout(window.__SurakshaTimeout);
                window.__SurakshaTimeout = setTimeout(analyzeCurrentEmail, 1200);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
        });

        console.log("[Suraksha] 🛡️ Content script loaded. Watching for emails…");
    }

    // Wait for Gmail to fully load
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", startObserving);
    } else {
        startObserving();
    }
})();

