
# 🚀 AI-Powered Network Log Translator

## 📌 Overview

The **AI-Powered Network Log Translator** is a cybersecurity tool that converts raw network logs (Syslog, SNMP, AWS VPC Flow Logs) into **human-readable insights** using parsing, anomaly detection, and AI-based summarization.

It helps reduce **incident response time** by making complex logs understandable for both technical and non-technical users.

---

## 🎯 Problem Statement

Network logs are:

* Complex and hard to read
* Time-consuming to analyze manually
* Difficult for non-experts to interpret

➡️ This leads to **delayed incident response** and missed threats.

---

## 💡 Solution

This project:

1. Parses raw logs into structured data
2. Detects anomalies (rule-based + optional ML)
3. Classifies severity levels
4. Uses AI to generate **plain English explanations**

---

## 🧱 Architecture

```
Raw Logs
   ↓
Parser (Regex / Log Extraction)
   ↓
Structured JSON
   ↓
Anomaly Detection
   ↓
Log Classification
   ↓
AI Summarization (LLM)
   ↓
Human-Readable Output / Dashboard
```

---

## ⚙️ Tech Stack

* **Python**
* **Pandas** – data handling
* **Regex** – log parsing
* **OpenAI / LLM API** – natural language generation
* **Scikit-learn (optional)** – anomaly detection
* **FastAPI (optional)** – API backend
* **JSON / CSV logs**

---

## 📂 Project Structure

```
ai-log-translator/
│
├── logs/
│   ├── syslog.log
│   ├── snmp.log
│   └── vpc_flow.log
│
├── parser/
│   └── log_parser.py
│
├── detection/
│   └── anomaly_detector.py
│
├── classification/
│   └── classifier.py
│
├── summarizer/
│   └── llm_summarizer.py
│
├── pipeline.py
├── app.py (optional FastAPI)
├── requirements.txt
└── README.md
```

---

## 🔍 Features

### ✅ Log Parsing

* Extracts:

  * Timestamp
  * Source IP
  * Severity
  * Message

* Supports:

  * Syslog
  * SNMP traps
  * AWS VPC Flow Logs

---

### 🚨 Anomaly Detection

* Rule-based detection:

  * Repeated login failures
  * Port scanning
  * Traffic spikes

* Optional ML:

  * Isolation Forest (outlier detection)

---

### 🏷️ Log Classification

Each log is categorized as:

* 🔴 **Critical** – attacks, failures, intrusions
* 🟡 **Warning** – unusual activity
* 🟢 **Informational** – normal operations

---

### 🤖 AI-Powered Explanation

Example:

**Input Log:**

```
Failed SSH login from 192.168.1.10 on port 22
```

**Output:**

```
A device at IP 192.168.1.10 attempted to access the system via SSH but failed authentication. This may indicate unauthorized access attempts.
```

---

## 🚀 Installation

```bash
git clone https://github.com/your-username/ai-log-translator.git
cd ai-log-translator

pip install -r requirements.txt
```

---

## 🔑 Environment Setup

Create a `.env` file:

```
OPENAI_API_KEY=your_api_key_here
```

---

## ▶️ Usage

Run the pipeline:

```bash
python pipeline.py
```

Optional (API mode):

```bash
uvicorn app:app --reload
```

---

## 📊 Output Example

```json
{
  "timestamp": "2026-04-15 10:15:23",
  "source_ip": "192.168.1.10",
  "severity": "HIGH",
  "category": "CRITICAL",
  "anomaly": true,
  "summary": "Multiple failed login attempts detected, indicating a possible brute-force attack."
}
```

---

## ⏱️ Time-to-Clarity Metric

This project measures:

> ⏳ Time taken from raw log → understandable insight

### Goal:

Reduce analysis time from **minutes → seconds**

---

## 🔐 Security Use Cases

* SOC (Security Operations Center)
* Incident response automation
* Threat detection
* Log monitoring systems (SIEM enhancement)

---

## 🔮 Future Improvements

* Real-time log streaming (Kafka integration)
* Dashboard (React + charts)
* Multi-language explanations
* Integration with SIEM tools (Splunk, ELK)
* Advanced ML models for anomaly detection

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Ayush Krishnan P & Hithashree P

