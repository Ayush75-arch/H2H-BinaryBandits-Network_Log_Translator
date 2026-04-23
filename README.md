#DEPLOYEMENT LINK - 
https://h2-h-binary-bandits-network-log-translator-i1vowmdke.vercel.app


#YOUTUBE LINK - 
https://youtu.be/MiMeLyFchn8




# Network Log Translator
### Turn raw network logs into plain English — instantly.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python) ![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi) ![React](https://img.shields.io/badge/React-18-61DAFB?logo=react) ![Groq](https://img.shields.io/badge/LLM-Groq%20%2F%20LLaMA%203.1-orange) ![Vercel](https://img.shields.io/badge/Deployed-Vercel-black?logo=vercel)

---

## Problem Statement

Network logs are the ground truth of what's happening inside a system — but they're written for machines, not people. A single security event can scatter context across dozens of raw lines like:

```
Apr 15 10:14:55 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2
```

SOC analysts spend **minutes to hours** manually correlating these entries, figuring out what happened, how severe it is, and what to do next. For non-technical stakeholders, the logs might as well be binary. This delay between an event occurring and someone understanding it is where breaches slip through.

---

## Proposed Solution

Network Log Translator is an end-to-end pipeline that takes raw Syslog, SNMP trap, and AWS VPC Flow logs and converts them into structured, human-readable incident reports — in seconds.

It doesn't just parse. It detects anomalies, correlates related events into incidents, scores risk, and generates plain-English explanations using an LLM. The result is something a junior analyst *or* a non-technical manager can read and act on immediately.

What makes it different: the **Time-to-Clarity (TTC)** metric — we explicitly benchmark how fast the system goes from raw log input to an understandable, actionable insight.

---

## Tech Stack

| Layer | Tools |
|---|---|
| **Backend** | Python 3.11, FastAPI, Uvicorn |
| **Log Parsing** | Custom regex-based parser (Syslog, SNMP, VPC) |
| **Anomaly Detection** | Rule-based engine + Isolation Forest (scikit-learn) |
| **AI Summarization** | Groq API — LLaMA 3.1 8B Instant |
| **Frontend** | React 18, Vite, Tailwind CSS, Framer Motion |
| **Deployment** | Vercel (frontend), Render (backend) |
| **Other** | Pydantic, python-dotenv, SSE (streaming responses) |

---

## Features

- **Multi-format log parsing** — handles Syslog, SNMP traps, and AWS VPC Flow Logs out of the box
- **Anomaly detection** — flags brute-force attempts, port scans, traffic spikes, and repeated auth failures
- **Incident correlation** — groups related log entries into named incidents with attack chain classification
- **AI-powered explanations** — LLaMA 3.1 generates plain-English summaries per log entry and per incident
- **Risk scoring** — every log and incident gets a severity score (INFO → CRITICAL) with reasoning
- **Natural language querying** — ask questions about the analyzed logs in plain English via a chat-style query panel
- **Live streaming** — results stream back via SSE so the UI updates progressively, not all at once
- **Benchmark mode** — built-in TTC (Time-to-Clarity) benchmarking to measure pipeline performance
- **Compromise detection** — cross-references failed and successful auth events to surface potentially compromised hosts

---

## Architecture / Flow

```
Raw Log Input (Syslog / SNMP / VPC)
            │
            ▼
     ┌─────────────┐
     │  Log Parser  │  ← regex extraction: timestamp, source IP, event, host
     └──────┬──────┘
            │ Structured JSON
            ▼
  ┌──────────────────┐
  │ Anomaly Detector │  ← rule-based + optional Isolation Forest
  └────────┬─────────┘
           │ flagged entries
           ▼
  ┌─────────────────┐
  │   Classifier    │  ← severity tagging: INFO / LOW / MEDIUM / HIGH / CRITICAL
  └────────┬────────┘
           │
           ▼
  ┌──────────────────────┐
  │  Pipeline (v7)       │  ← incident correlation, compromise detection,
  │                      │    attack chain classification, risk scoring
  └────────┬─────────────┘
           │
           ▼
  ┌──────────────────────┐
  │   LLM Summarizer     │  ← Groq / LLaMA 3.1 generates human-readable
  │   (llm_summarizer)   │    explanation per log + per incident
  └────────┬─────────────┘
           │
           ▼
  ┌──────────────────────┐
  │   FastAPI (app.py)   │  ← REST + SSE endpoints, query interface,
  │                      │    context persistence between requests
  └────────┬─────────────┘
           │
           ▼
  ┌──────────────────────┐
  │  React Dashboard     │  ← log table, incident modal, query panel,
  │                      │    benchmark view, streaming results
  └──────────────────────┘
```

---

## Setup Instructions

### Prerequisites
- Python 3.11+
- Node.js 18+
- A [Groq API key](https://console.groq.com) (free tier works)

### 1. Clone the repo

```bash
git clone https://github.com/Ayush75-arch/H2H-BinaryBandits-Network_Log_Translator.git
cd H2H-BinaryBandits-Network_Log_Translator
```

### 2. Set up the backend

```bash
cd backend
pip install -r requirements.txt
```

Create a `.env` file in the `backend/` directory:

```
GROQ_API_KEY=your_groq_api_key_here
```

Start the backend server:

```bash
uvicorn app:app --reload --port 8000
```

### 3. Set up the frontend

```bash
cd ../frontend
npm install
npm run dev
```

The app will be running at `http://localhost:5173`.

### 4. Using the app

- Paste raw log text into the input panel and select the log type (Syslog / SNMP / VPC)
- Hit **Analyze** — results stream in live
- Click any log entry to see the full AI explanation
- Use the **Query** panel to ask natural language questions about the analyzed logs
- Switch to **Benchmark** mode to measure Time-to-Clarity performance

---

## Demo / Screenshots

> #YOUTUBE LINK - 
https://youtu.be/MiMeLyFchn8
>
> **Live deployment:** [https://h2-h-binary-bandits-network-log-translator-i1vowmdke.vercel.app](https://h2-h-binary-bandits-network-log-translator-i1vowmdke.vercel.app)

---

## Team Members

| Name | Role | GitHub |
|---|---|---|
| Ayush Krishnan P | Backend, Pipeline, AI Integration | [@Ayush75-arch](https://github.com/Ayush75-arch) |
| Hithashree P | Frontend, UI/UX, Integration |[@HITHASHREE-GIT] https://github.com/HITHASHREE-GIT |

---

## Deployed Link

🔗 **[https://h2-h-binary-bandits-network-log-translator-i1vowmdke.vercel.app](https://h2-h-binary-bandits-network-log-translator-i1vowmdke.vercel.app)**
