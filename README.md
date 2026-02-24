<p align="center">
  <img src="Gemini_Generated_Image_oh5wxzoh5wxzoh5w-removebg-preview.png" alt="Suraksha Logo" width="180" />
</p>

<h1 align="center">Suraksha</h1>
<p align="center"><em>सुरक्षा — AI-Powered Phishing Detection for Gmail</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/Chrome-Extension-4285F4?logo=googlechrome&logoColor=white" />
  <img src="https://img.shields.io/badge/Manifest-V3-34A853?logo=googlechrome&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Gemini-AI-886FBF?logo=googlegemini&logoColor=white" />
  <img src="https://img.shields.io/badge/LangChain-Agent-1C3C3C?logo=langchain&logoColor=white" />
</p>

---

**Suraksha** is a Chrome Extension that monitors your Gmail inbox in real-time, analyzing every email you open using **OSINT intelligence** and **AI** to detect phishing, social engineering, and impersonation attacks — all without leaving your inbox.

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Real-Time Analysis** | Automatically scans emails the moment you open them in Gmail |
| 🧠 **AI-Powered Verdicts** | LangChain + Gemini LLM synthesizes OSINT data into a safety score (1–100) |
| 🌐 **WHOIS Domain Check** | Flags newly registered or suspicious sender domains |
| 🔗 **VirusTotal Link Scan** | Checks every URL in the email body against 70+ antivirus engines |
| 📧 **HaveIBeenPwned** | Verifies if the sender's email has appeared in data breaches |
| 🎯 **Smart Fallback** | Rule-based heuristic engine works even without any API keys |
| 🏷️ **In-Gmail Banner** | Color-coded banner (🟢 Safe / 🟡 Suspicious / 🔴 Dangerous) injected directly into gmail |
| 📊 **Expandable Details** | Click the banner to see full OSINT evidence breakdown |
| ⚡ **Parallel OSINT** | All OSINT checks run concurrently for fast results |
| 🔒 **Privacy First** | Your emails never leave your machine — backend runs on `localhost` |

---

## 🏗️ Architecture

```
                          ┌──────────────────────────────────────────────────────────┐
                          │                    CHROME EXTENSION                      │
                          │                    (Manifest V3)                         │
                          │                                                          │
                          │  ┌──────────────┐  ┌──────────┐  ┌───────────────────┐  │
                          │  │ content.js   │  │ popup.js │  │  background.js    │  │
                          │  │ ─ Scrapes    │  │ ─ Status │  │  ─ Proxy between  │  │
                          │  │   Gmail DOM  │  │   UI     │  │    content script │  │
                          │  │ ─ Injects    │  │ ─ Last   │  │    & backend API  │  │
                          │  │   banner     │  │   result │  │                   │  │
                          │  │ ─ URL hash   │  │          │  │                   │  │
                          │  │   observer   │  │          │  │                   │  │
                          │  └──────┬───────┘  └──────────┘  └────────┬──────────┘  │
                          │         │ sendMessage()                    │              │
                          │         └─────────────►───────────────────►│              │
                          └──────────────────────────────────────────┬─┘──────────────┘
                                                                    │
                                                      POST /analyze-email
                                                        (JSON payload)
                                                                    │
                                                                    ▼
                          ┌──────────────────────────────────────────────────────────┐
                          │                    FASTAPI BACKEND                       │
                          │                   (localhost:8000)                       │
                          │                                                          │
                          │   ┌─────────────────────────────────────────────────┐    │
                          │   │              OSINT LAYER (Parallel)             │    │
                          │   │                                                 │    │
                          │   │  ┌────────────────┐  ┌───────────────────────┐  │    │
                          │   │  │ domain_checker │  │    link_scanner      │  │    │
                          │   │  │ ─ WHOIS lookup │  │ ─ VirusTotal API     │  │    │
                          │   │  │ ─ Domain age   │  │ ─ 70+ AV engines    │  │    │
                          │   │  │ ─ Suspicious   │  │ ─ URL extraction    │  │    │
                          │   │  │   flag         │  │ ─ Malicious count   │  │    │
                          │   │  └────────────────┘  └───────────────────────┘  │    │
                          │   │  ┌────────────────┐                             │    │
                          │   │  │ email_checker  │                             │    │
                          │   │  │ ─ HIBP API     │                             │    │
                          │   │  │ ─ Breach count │                             │    │
                          │   │  │ ─ Breach list  │                             │    │
                          │   │  └────────────────┘                             │    │
                          │   └──────────────────────────┬──────────────────────┘    │
                          │                              │ OSINTReport               │
                          │                              ▼                           │
                          │   ┌─────────────────────────────────────────────────┐    │
                          │   │               AI SYNTHESIZER                    │    │
                          │   │                                                 │    │
                          │   │  ┌────────────┐    ┌─────────────────────────┐  │    │
                          │   │  │ LangChain  │───►│  Gemini LLM            │  │    │
                          │   │  │ Prompt     │    │  ─ Score (1-100)       │  │    │
                          │   │  │ Template   │    │  ─ Verdict            │  │    │
                          │   │  │            │    │  ─ Explanation        │  │    │
                          │   │  └────────────┘    └─────────────────────────┘  │    │
                          │   │                                                 │    │
                          │   │  ┌────────────────────────────────────────────┐  │    │
                          │   │  │ Rule-Based Fallback (no API key needed)   │  │    │
                          │   │  │ ─ Urgency keyword detection              │  │    │
                          │   │  │ ─ Suspicious pattern matching            │  │    │
                          │   │  │ ─ OSINT signal scoring                   │  │    │
                          │   │  └────────────────────────────────────────────┘  │    │
                          │   └─────────────────────────────────────────────────┘    │
                          │                              │                           │
                          │                              ▼                           │
                          │                     AnalysisResponse                     │
                          │              {score, verdict, explanation,               │
                          │                    osint_details}                        │
                          └──────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
suraksha/
├── extension/                   # Chrome Extension (Manifest V3)
│   ├── manifest.json            # Extension config & permissions
│   ├── content.js               # Gmail DOM scraper + banner injection
│   ├── background.js            # Service worker — proxies API calls
│   ├── popup.html               # Extension popup UI
│   ├── popup.js                 # Popup logic & last result display
│   ├── styles.css               # Banner & popup styles
│   └── icons/                   # Extension icons (16, 48, 128px)
│
├── backend/                     # FastAPI Backend
│   ├── main.py                  # App entry point, /analyze-email endpoint
│   ├── models.py                # Pydantic request/response schemas
│   ├── requirements.txt         # Python dependencies
│   ├── .env.example             # API key template
│   ├── osint/                   # OSINT Intelligence Modules
│   │   ├── domain_checker.py    # WHOIS domain age & reputation
│   │   ├── link_scanner.py      # VirusTotal URL scanning
│   │   └── email_checker.py     # HaveIBeenPwned breach lookup
│   └── ai/                      # AI Analysis Layer
│       └── synthesizer.py       # LangChain + Gemini synthesis & rule-based fallback
│
└── README.md
```

---

## 🚀 Quick Start

### 1. Backend Setup

```bash
cd backend
pip install -r requirements.txt

# Copy the env template and add your API keys
cp .env.example .env
# Edit .env with your keys (Gemini, VirusTotal, HIBP)

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

---

## 🔑 API Keys

| Service | Required? | Get it at |
|---------|-----------|-----------|
| Gemini API | Recommended | [Google AI Studio](https://aistudio.google.com/apikey) |
| VirusTotal | Optional | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| HaveIBeenPwned | Optional | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |

> **Note:** Suraksha works without any API keys using its built-in rule-based analysis engine. API keys unlock the full AI + OSINT capabilities.

---

## 🧪 Testing the API

```bash
curl -X POST http://localhost:8000/analyze-email \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "scammer@fake-domain.com",
    "subject": "URGENT: Verify Account",
    "body": "Click here immediately to avoid account suspension: http://evil-site.com/login"
  }'
```

**Expected Response:**
```json
{
  "score": 15,
  "verdict": "Dangerous",
  "explanation": "Multiple phishing indicators detected...",
  "details": {
    "domain_age": { "domain": "fake-domain.com", "is_suspicious": true },
    "link_scan": [{ "url": "http://evil-site.com/login", "is_flagged": true }],
    "email_breach": { "is_breached": false }
  }
}
```

---

## 🎬 Demo

For hackathon demos, the backend logs every OSINT check and AI analysis step in real-time to the terminal — perfect for showing the audience what's happening behind the scenes.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Extension** | Chrome Manifest V3, Vanilla JavaScript, CSS |
| **Backend** | Python, FastAPI, Uvicorn |
| **AI Engine** | LangChain, Google Gemini API |
| **OSINT** | python-whois, VirusTotal API, HaveIBeenPwned API |
| **Data Models** | Pydantic v2 |

---

## 📄 License

This project is built for the hackathon and is open-source.

---

<p align="center">
  Built with 🛡️ by <strong>Team Suraksha</strong>
</p>
