// Suraksha — Popup Script
// Reads last analysis results from chrome.storage.local and displays them
// Supports both email analysis and page analysis results

document.addEventListener("DOMContentLoaded", () => {
    chrome.storage.local.get(["lastAnalysis", "lastPageAnalysis"], (data) => {
        const emailResult = data.lastAnalysis;
        const pageResult = data.lastPageAnalysis;

        let hasResult = false;

        // ── Show email analysis result ──
        if (emailResult && !isStale(emailResult)) {
            hasResult = true;
            showEmailResult(emailResult);
        }

        // ── Show page analysis result ──
        if (pageResult && !isStale(pageResult)) {
            hasResult = true;
            showPageResult(pageResult);
        }

        // If we have results, hide idle
        if (hasResult) {
            document.getElementById("status-idle").style.display = "none";
        }
    });
});

function isStale(result) {
    if (!result.timestamp) return false;
    const ageMinutes = (Date.now() - result.timestamp) / 60000;
    return ageMinutes > 30;
}

function getStateInfo(score) {
    if (score < 40) return { state: "dangerous", label: "🚨 Dangerous" };
    if (score < 70) return { state: "suspicious", label: "⚠️ Suspicious" };
    return { state: "safe", label: "✅ Safe" };
}

function showEmailResult(result) {
    document.getElementById("email-result-container").style.display = "block";

    const { state, label } = getStateInfo(result.score);

    const scoreCircle = document.getElementById("email-result-score-circle");
    scoreCircle.className = `result-score-circle ${state}`;
    document.getElementById("email-result-score").textContent = result.score;

    document.getElementById("email-result-verdict").textContent = label;
    document.getElementById("email-result-explanation").textContent =
        result.explanation || result.verdict || "Analysis complete.";

    const senderEl = document.getElementById("email-result-sender");
    let metaText = "";
    if (result.sender) metaText += `Sender: ${result.sender}`;
    if (result.checks_completed) {
        if (result.checks_completed.length > 0) {
            metaText += ` • Checks: ${result.checks_completed.join(", ")}`;
        } else {
            metaText += " • ⚠️ No OSINT checks completed";
        }
    }
    // Show malware summary if any flagged links have malware details
    if (result.details && result.details.link_scan) {
        const flagged = result.details.link_scan.filter(l => l.is_flagged);
        if (flagged.length > 0) {
            const allTypes = [...new Set(flagged.flatMap(l => l.malware_types || []))];
            const allEngines = [...new Set(flagged.flatMap(l => l.detection_engines || []))];
            if (allTypes.length > 0) {
                metaText += ` • 🦠 Malware: ${allTypes.slice(0, 3).join(", ")}`;
            }
            if (allEngines.length > 0) {
                metaText += ` (${allEngines.length} engines)`;
            }
        }
    }
    senderEl.textContent = metaText;
}

function showPageResult(result) {
    document.getElementById("page-result-container").style.display = "block";

    const { state, label } = getStateInfo(result.score);

    // Type badge
    const typeIcons = { social_media: "💬 Social Media", ecommerce: "🛒 E-Commerce", generic: "🌐 Web Page" };
    document.getElementById("page-type-badge").textContent =
        (typeIcons[result.page_type] || "🌐 Page") + " Analysis";

    const scoreCircle = document.getElementById("page-result-score-circle");
    scoreCircle.className = `result-score-circle ${state}`;
    document.getElementById("page-result-score").textContent = result.score;

    document.getElementById("page-result-verdict").textContent = label;
    document.getElementById("page-result-explanation").textContent =
        result.explanation || result.verdict || "Analysis complete.";

    const metaEl = document.getElementById("page-result-meta");
    let metaText = "";
    if (result.page_url) {
        try {
            metaText += new URL(result.page_url).hostname;
        } catch {
            metaText += result.page_url.substring(0, 40);
        }
    }
    if (result.checks_completed && result.checks_completed.length > 0) {
        metaText += ` • Checks: ${result.checks_completed.join(", ")}`;
    }
    if (result.risk_factors && result.risk_factors.length > 0) {
        metaText += ` • ${result.risk_factors.length} risk factor(s)`;
    }
    metaEl.textContent = metaText;
}
