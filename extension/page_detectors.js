// Suraksha — Page Detectors
// Site-specific detector modules for multi-webpage risk detection
// Each detector extracts signals WITHOUT sending raw page content to backend

"use strict";

// ─── Shared Constants ────────────────────────────────────────────────

const URGENCY_KEYWORDS_PAGE = [
    "urgent", "immediately", "right now", "asap", "within 24 hours",
    "suspended", "locked", "verify your", "confirm your", "click here",
    "act now", "limited time", "expire", "deadline", "warning",
    "unauthorized", "suspicious activity", "unusual sign-in",
    "action required", "final notice", "last chance", "account compromised",
    "security alert", "your account has been", "payment failed",
    "your computer", "virus detected", "malware found"
];

const SCAM_KEYWORDS_PAGE = [
    "your computer is infected", "call this number", "tech support",
    "microsoft warning", "apple security alert", "you have won",
    "congratulations winner", "claim your prize", "free gift card",
    "limited time offer", "double your money", "guaranteed returns",
    "bitcoin investment", "nigerian prince", "inheritance fund",
    "click here to claim", "update your payment", "verify your identity",
    "your device is compromised", "unauthorized access detected",
    "lottery winner", "you've been selected", "exclusive deal"
];

const URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "bl.ink", "short.io", "tiny.cc"
];

const SOCIAL_MEDIA_DOMAINS = [
    "facebook.com", "twitter.com", "x.com", "linkedin.com",
    "instagram.com", "reddit.com", "tiktok.com", "threads.net",
    "mastodon.social"
];

const ECOMMERCE_DOMAINS = [
    "amazon.com", "ebay.com", "etsy.com", "shopify.com",
    "alibaba.com", "aliexpress.com", "walmart.com", "flipkart.com",
    "myntra.com", "ajio.com"
];

// Brands commonly impersonated by phishing pages
const IMPERSONATION_TARGETS = [
    "google", "microsoft", "apple", "paypal", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "adobe", "zoom", "slack", "github", "steam", "epic games",
    "bank of america", "chase", "wells fargo", "citibank", "hdfc",
    "icici", "sbi", "axis bank", "kotak"
];

// ─── Utility Functions ───────────────────────────────────────────────

function getPageDomain() {
    try {
        return new URL(window.location.href).hostname.replace(/^www\./, "");
    } catch {
        return window.location.hostname;
    }
}

function isDomainMatch(domain, target) {
    return domain === target || domain.endsWith("." + target);
}

function isCurrentSiteDomain(url) {
    try {
        const linkDomain = new URL(url).hostname.replace(/^www\./, "");
        return isDomainMatch(linkDomain, getPageDomain());
    } catch {
        return true; // If we can't parse, assume same domain
    }
}

function isShortenedUrl(url) {
    try {
        const hostname = new URL(url).hostname.replace(/^www\./, "");
        return URL_SHORTENERS.some(s => isDomainMatch(hostname, s));
    } catch {
        return false;
    }
}

function extractVisibleText(el) {
    return (el.textContent || el.innerText || "").trim().substring(0, 200);
}

function scanForKeywords(text, keywordList) {
    const lower = text.toLowerCase();
    return keywordList.filter(kw => lower.includes(kw));
}

// ─── Site Type Detection ─────────────────────────────────────────────

function detectSiteType() {
    const domain = getPageDomain();
    const url = window.location.href;

    // Gmail — use existing email detector (handled separately in content.js)
    if (isDomainMatch(domain, "mail.google.com")) {
        return "gmail";
    }

    // Social media
    if (SOCIAL_MEDIA_DOMAINS.some(d => isDomainMatch(domain, d))) {
        return "social_media";
    }

    // E-commerce
    if (ECOMMERCE_DOMAINS.some(d => isDomainMatch(domain, d))) {
        return "ecommerce";
    }

    // Check for checkout/payment indicators in URL
    const paymentPaths = ["checkout", "payment", "pay", "cart", "order", "billing"];
    const pathname = window.location.pathname.toLowerCase();
    if (paymentPaths.some(p => pathname.includes(p))) {
        return "ecommerce";
    }

    return "generic";
}

// ─── Generic Page Detector ───────────────────────────────────────────
// Runs on ANY webpage — scans forms, links, and page content for red flags

const GenericDetector = {
    name: "generic",
    label: "🌐 Web Page",

    scan() {
        const signals = {
            suspicious_forms: [],
            suspicious_links: [],
            urgency_keywords_found: [],
            scam_keywords_found: [],
            has_login_form: false,
            has_payment_form: false,
            is_https: window.location.protocol === "https:",
            external_domain_forms: [],
            page_domain: getPageDomain(),
            link_count: 0,
            form_count: 0,
        };

        // Scan forms
        this._scanForms(signals);

        // Scan links
        this._scanLinks(signals);

        // Scan page text for keywords
        this._scanPageText(signals);

        // Check for brand impersonation
        this._checkImpersonation(signals);

        return {
            signals,
            shouldAnalyze: this._shouldTriggerAnalysis(signals),
            riskType: "generic",
            contextLabel: "Web Page Scan",
        };
    },

    _scanForms(signals) {
        const forms = document.querySelectorAll("form");
        signals.form_count = forms.length;

        forms.forEach(form => {
            const action = form.getAttribute("action") || "";
            const method = (form.getAttribute("method") || "GET").toUpperCase();
            const inputs = form.querySelectorAll("input");
            const inputTypes = [...inputs].map(i => (i.type || "text").toLowerCase());

            const hasPassword = inputTypes.includes("password");
            const hasEmail = inputTypes.includes("email");
            const hasCreditCard = inputTypes.some(t => t === "tel" || t === "number") &&
                form.innerHTML.toLowerCase().match(/card|credit|cvv|expir/);
            const hiddenInputs = [...inputs].filter(i => i.type === "hidden");

            // Check if form action goes to a different domain
            let isCrossDomain = false;
            let actionDomain = "";
            if (action && action.startsWith("http")) {
                try {
                    actionDomain = new URL(action).hostname.replace(/^www\./, "");
                    isCrossDomain = !isDomainMatch(actionDomain, getPageDomain());
                } catch { /* invalid URL */ }
            }

            if (hasPassword) signals.has_login_form = true;
            if (hasCreditCard) signals.has_payment_form = true;

            // Flag as suspicious if: cross-domain, has password, or excessive hidden fields
            const isSuspicious = isCrossDomain || (hasPassword && !signals.is_https) ||
                hiddenInputs.length > 4 || (hasPassword && hiddenInputs.length > 2);

            if (isSuspicious) {
                signals.suspicious_forms.push({
                    action: action.substring(0, 200),
                    method: method,
                    has_password_field: hasPassword,
                    has_hidden_fields: hiddenInputs.length > 0,
                    hidden_field_count: hiddenInputs.length,
                    is_cross_domain: isCrossDomain,
                    input_types: inputTypes.slice(0, 10),
                });

                if (isCrossDomain && actionDomain) {
                    signals.external_domain_forms.push(actionDomain);
                }
            }
        });
    },

    _scanLinks(signals) {
        const links = document.querySelectorAll("a[href]");
        signals.link_count = links.length;

        links.forEach(link => {
            const href = link.getAttribute("href") || "";
            const visibleText = extractVisibleText(link);

            // Skip empty, anchor, or javascript links
            if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;

            let isMismatched = false;
            let isShortened = false;

            // Check for text/URL mismatch (link text looks like URL but doesn't match href)
            const textLooksLikeUrl = /https?:\/\/\S+/i.test(visibleText);
            if (textLooksLikeUrl && href.startsWith("http")) {
                try {
                    const textDomain = new URL(visibleText.match(/https?:\/\/\S+/i)[0]).hostname;
                    const hrefDomain = new URL(href).hostname;
                    if (textDomain !== hrefDomain) {
                        isMismatched = true;
                    }
                } catch { /* invalid URL in text */ }
            }

            // Check for URL shorteners
            if (href.startsWith("http")) {
                isShortened = isShortenedUrl(href);
            }

            if (isMismatched || isShortened) {
                signals.suspicious_links.push({
                    href: href.substring(0, 300),
                    visible_text: visibleText.substring(0, 100),
                    is_mismatched: isMismatched,
                    is_shortened: isShortened,
                });
            }
        });
    },

    _scanPageText(signals) {
        // Get page text efficiently — title + visible body text (limit scan area)
        const title = document.title || "";
        // Only scan main content area to avoid noise
        const mainContent = document.querySelector("main") ||
            document.querySelector('[role="main"]') ||
            document.querySelector("article") ||
            document.body;

        const pageText = (title + " " + (mainContent?.innerText || "")).substring(0, 10000);

        signals.urgency_keywords_found = scanForKeywords(pageText, URGENCY_KEYWORDS_PAGE).slice(0, 10);
        signals.scam_keywords_found = scanForKeywords(pageText, SCAM_KEYWORDS_PAGE).slice(0, 10);
    },

    _checkImpersonation(signals) {
        const title = (document.title || "").toLowerCase();
        const domain = getPageDomain();

        // Check if page title mentions a brand but domain doesn't match
        for (const brand of IMPERSONATION_TARGETS) {
            if (title.includes(brand) && !domain.includes(brand.replace(/\s+/g, ""))) {
                signals.scam_keywords_found.push(`possible ${brand} impersonation`);
            }
        }
    },

    _shouldTriggerAnalysis(signals) {
        // Only trigger if there's something worth reporting
        return (
            signals.suspicious_forms.length > 0 ||
            signals.suspicious_links.length >= 2 ||
            signals.scam_keywords_found.length >= 2 ||
            signals.urgency_keywords_found.length >= 3 ||
            (signals.has_login_form && !signals.is_https) ||
            (signals.has_payment_form && !signals.is_https) ||
            signals.external_domain_forms.length > 0
        );
    }
};


// ─── Social Media Detector ──────────────────────────────────────────
// Extends generic with social-media-specific checks

const SocialMediaDetector = {
    name: "social_media",
    label: "💬 Social Media",

    scan() {
        // Start with generic scan
        const result = GenericDetector.scan();
        result.riskType = "social_media";
        result.contextLabel = "Social Media Scan";

        // Add social-media-specific checks
        this._checkSocialSignals(result.signals);

        // Re-evaluate trigger
        result.shouldAnalyze = result.shouldAnalyze ||
            result.signals.scam_keywords_found.length >= 1 ||
            result.signals.suspicious_links.length >= 1;

        return result;
    },

    _checkSocialSignals(signals) {
        // Check for suspicious DM/message content
        const messageContainers = document.querySelectorAll(
            '[role="dialog"], [data-testid="messageEntry"], ' +
            '.msg-conversation-card, .message-body, .direct-message, ' +
            '[class*="message"], [class*="chat"], [class*="inbox"]'
        );

        messageContainers.forEach(container => {
            const text = (container.innerText || "").substring(0, 5000);
            const msgScamHits = scanForKeywords(text, SCAM_KEYWORDS_PAGE);
            if (msgScamHits.length > 0) {
                signals.scam_keywords_found.push(...msgScamHits);
            }
        });

        // Deduplicate
        signals.scam_keywords_found = [...new Set(signals.scam_keywords_found)];

        // Check for links in messages (common DM phishing vector)
        messageContainers.forEach(container => {
            const links = container.querySelectorAll("a[href]");
            links.forEach(link => {
                const href = link.getAttribute("href") || "";
                if (href.startsWith("http") && !isCurrentSiteDomain(href)) {
                    const isShortened = isShortenedUrl(href);
                    // External links in DMs are higher risk
                    if (isShortened || !isCurrentSiteDomain(href)) {
                        signals.suspicious_links.push({
                            href: href.substring(0, 300),
                            visible_text: extractVisibleText(link).substring(0, 100),
                            is_mismatched: false,
                            is_shortened: isShortened,
                        });
                    }
                }
            });
        });
    }
};


// ─── E-Commerce Detector ────────────────────────────────────────────
// Focuses on checkout/payment page safety

const ECommerceDetector = {
    name: "ecommerce",
    label: "🛒 E-Commerce",

    scan() {
        // Start with generic scan
        const result = GenericDetector.scan();
        result.riskType = "ecommerce";
        result.contextLabel = "E-Commerce Scan";

        // Add e-commerce-specific checks
        this._checkPaymentSafety(result.signals);
        this._checkPricingScams(result.signals);

        // E-commerce pages with payment forms always get analyzed
        result.shouldAnalyze = result.shouldAnalyze ||
            result.signals.has_payment_form ||
            (result.signals.has_login_form && !result.signals.is_https);

        return result;
    },

    _checkPaymentSafety(signals) {
        // Look for card input patterns
        const allInputs = document.querySelectorAll("input");
        const cardPatterns = /card|credit|debit|cvv|cvc|expir|billing|routing|account\s*num/i;

        let hasCardInputs = false;
        allInputs.forEach(input => {
            const name = (input.name || "").toLowerCase();
            const placeholder = (input.placeholder || "").toLowerCase();
            const ariaLabel = (input.getAttribute("aria-label") || "").toLowerCase();
            const combined = `${name} ${placeholder} ${ariaLabel}`;

            if (cardPatterns.test(combined)) {
                hasCardInputs = true;
            }
        });

        if (hasCardInputs) {
            signals.has_payment_form = true;
            if (!signals.is_https) {
                signals.scam_keywords_found.push("payment form on non-HTTPS page");
            }
        }
    },

    _checkPricingScams(signals) {
        const pageText = (document.body?.innerText || "").substring(0, 15000).toLowerCase();

        // Check for unrealistic discount language
        const discountPatterns = [
            /\b9[5-9]%\s*off\b/,
            /\bfree\b.*\b(iphone|macbook|laptop|samsung|ps5)\b/,
            /\b(only|just)\s*\$[01]\./,
            /\bwas\s*\$\d{3,}.*now\s*\$\d{1,2}\b/,
        ];

        discountPatterns.forEach(pattern => {
            if (pattern.test(pageText)) {
                signals.scam_keywords_found.push("unrealistic discount or pricing");
            }
        });

        // Check for fake urgency timers
        const timerElements = document.querySelectorAll(
            '[class*="timer"], [class*="countdown"], [class*="hurry"], [class*="stock"]'
        );
        if (timerElements.length > 0 && signals.scam_keywords_found.length > 0) {
            signals.urgency_keywords_found.push("countdown timer with scam indicators");
        }
    }
};


// ─── Detector Registry ──────────────────────────────────────────────

const PageDetectors = {
    generic: GenericDetector,
    social_media: SocialMediaDetector,
    ecommerce: ECommerceDetector,

    getDetector(siteType) {
        return this[siteType] || this.generic;
    },

    detect() {
        const siteType = detectSiteType();
        if (siteType === "gmail") return null; // Handled by email logic in content.js
        const detector = this.getDetector(siteType);
        return detector.scan();
    }
};

// Export for content.js
if (typeof window !== "undefined") {
    window.SurakshaPageDetectors = PageDetectors;
    window.SurakshaDetectSiteType = detectSiteType;
}
