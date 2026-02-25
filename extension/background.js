// Suraksha — Background Service Worker
// Proxies fetch requests from the content script to the backend
// Handles both email analysis and page analysis requests

const BACKEND_URL = "http://localhost:8000";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYZE_EMAIL") {
        fetch(`${BACKEND_URL}/analyze-email`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(message.payload),
        })
            .then(async (response) => {
                if (!response.ok) {
                    throw new Error(`Server returned ${response.status}`);
                }
                const data = await response.json();
                sendResponse({ success: true, data });
            })
            .catch((err) => {
                console.error("[Suraksha BG] Email analysis failed:", err);
                sendResponse({ success: false, error: err.message });
            });

        return true; // async sendResponse
    }

    if (message.type === "ANALYZE_PAGE") {
        fetch(`${BACKEND_URL}/analyze-page`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(message.payload),
        })
            .then(async (response) => {
                if (!response.ok) {
                    throw new Error(`Server returned ${response.status}`);
                }
                const data = await response.json();
                sendResponse({ success: true, data });
            })
            .catch((err) => {
                console.error("[Suraksha BG] Page analysis failed:", err);
                sendResponse({ success: false, error: err.message });
            });

        return true; // async sendResponse
    }
});
