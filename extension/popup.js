// Suraksha — Popup Script
// Reads last analysis result from chrome.storage.local and displays it

document.addEventListener("DOMContentLoaded", () => {
    chrome.storage.local.get("lastAnalysis", (data) => {
        const result = data.lastAnalysis;
        if (!result) return; // Keep showing idle state

        // Hide idle, show result
        document.getElementById("status-idle").style.display = "none";
        document.getElementById("result-container").style.display = "block";

        // Determine state
        let state = "safe";
        let verdictLabel = "✅ Safe";
        if (result.score < 40) {
            state = "dangerous";
            verdictLabel = "🚨 Dangerous";
        } else if (result.score < 70) {
            state = "suspicious";
            verdictLabel = "⚠️ Suspicious";
        }

        // Score circle
        const scoreCircle = document.getElementById("result-score-circle");
        scoreCircle.className = `result-score-circle ${state}`;
        document.getElementById("result-score").textContent = result.score;

        // Verdict & explanation
        document.getElementById("result-verdict").textContent = verdictLabel;
        document.getElementById("result-explanation").textContent =
            result.explanation || result.verdict || "Analysis complete.";

        // Sender info
        if (result.sender) {
            document.getElementById("result-sender").textContent = `Sender: ${result.sender}`;
        }
    });
});
