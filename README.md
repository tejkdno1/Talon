# 🦅 Talon (Alpha)
> **The Autonomous AI Phishing Hunter.** > Stop guessing. Let an AI Agent detonate, photograph, and judge suspicious links for you.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Playwright](https://img.shields.io/badge/Engine-Playwright-green.svg)](https://playwright.dev/)

---

## 🚀 Why Talon?
Cybersecurity analysts suffer from **Alert Fatigue**. Every day, they manually check hundreds of "suspicious" emails. 

**Talon** is an autonomous agent designed to handle the "Golden Hour" of incident response. It doesn't just check a blacklist; it **thinks** like an analyst. It opens the link in a virtual "containment cell" (headless browser), takes a screenshot, and uses **Computer Vision + LLMs** to determine if a site is a visual clone of a trusted brand.

### Key "Revolutionary" Features:
* **🕵️ Headless Detonation:** Safely follows nested redirects (bit.ly → tinyurl → malicious-site).
* **👁️ Visual Phishing Detection:** Uses AI Vision to identify "Brand Jacking" (e.g., a site that *looks* like Microsoft but lives on a `.ru` domain).
* **🧠 Agentic Verdicts:** Instead of "Clean/Infected," get a natural language report: *"This is a credential harvester targeting Outlook users."*
* **🛡️ Evidence Capture:** Automatically saves full-page PNGs and DOM snapshots for forensic reports.

---

## 🛠️ How it Works
1.  **Ingest:** Feed Talon a URL or an `.eml` file.
2.  **Detonate:** Talon launches a stealth Chromium instance via **Playwright**.
3.  **Analyze:** It scrapes the final URL, SSL certs, and visual layout.
4.  **Verdict:** The AI Agent compares the evidence and gives a confidence score.

---

## 📦 Installation

```bash
# Clone the repository
git clone [https://github.com/tejkdno1/Talon.git](https://github.com/tejkdno1/Talon.git)
cd Talon

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

## ▶️ Basic V1 Usage

Run a first phishing analysis on a URL:

```bash
python talon_v1.py "https://example.com"
```

Optional flags:

```bash
python talon_v1.py "example.com/login" --output-dir evidence --timeout-ms 20000
```

This V1 script will:
- Open the URL in headless Chromium
- Follow redirects and collect final URL + status
- Save screenshot + DOM snapshot
- Generate a simple heuristic phishing verdict JSON report