# 🛡️ Suraksha — AI-Powered Phishing Detection

A Chrome Extension that analyzes emails in Gmail in real-time using OSINT intelligence and AI to detect phishing, social engineering, and impersonation attacks.

## Architecture

```
┌─────────────────┐     POST /analyze-email     ┌──────────────────┐
│  Chrome Extension│ ─────────────────────────► │  FastAPI Backend  │
│  (Gmail Content  │ ◄───────────────────────── │                  │
│   Script + UI)   │     {score, verdict, ...}  │  ┌────────────┐  │
└─────────────────┘                             │  │ OSINT Tools│  │
                                                │  │ ─ WHOIS    │  │
                                                │  │ ─ VirusTotal│ │
                                                │  │ ─ HIBP     │  │
                                                │  └────────────┘  │
                                                │  ┌────────────┐  │
                                                │  │ LLM Agent  │  │
                                                │  │ (LangChain │  │
                                                │  │  + Gemini) │  │
                                                │  └────────────┘  │
                                                └──────────────────┘
```

## Quick Start

### 1. Backend Setup

```bash
cd backend
pip install -r requirements.txt

# Copy env template and add your API keys
cp .env.example .env
# Edit .env with your keys (Gemini, VirusTotal, etc.)

# Start the server
python main.py
```

The server starts at `http://localhost:8000`.
API docs available at `http://localhost:8000/docs`.

### 2. Chrome Extension Setup

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. Navigate to Gmail → open any email
5. Watch the Suraksha banner appear!

## API Keys

| Service | Required? | Get it at |
|---------|-----------|-----------|
| Gemini API | Recommended | [Google AI Studio](https://aistudio.google.com/apikey) |
| VirusTotal | Optional | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| HaveIBeenPwned | Optional | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |

> **Note:** Suraksha works without any API keys using rule-based analysis. API keys enable full AI + OSINT capabilities.

## Testing the API

```bash
curl -X POST http://localhost:8000/analyze-email \
  -H "Content-Type: application/json" \
  -d '{"sender":"scammer@fake-domain.com","subject":"URGENT: Verify Account","body":"Click here immediately to avoid account suspension: http://evil-site.com/login"}'
```

## Demo

For hackathon demos, the backend logs OSINT checks and AI analysis in real-time to the terminal — perfect for showing the audience what's happening behind the scenes.

## Tech Stack

- **Frontend:** Chrome Extension (Manifest V3)
- **Backend:** Python + FastAPI
- **AI:** LangChain + Gemini API
- **OSINT:** python-whois, VirusTotal API, HaveIBeenPwned API
