# 🦅 Talon (Alpha)

> **The Autonomous AI Phishing Hunter**
> Detonate suspicious URLs, capture evidence, and get a fast phishing-risk verdict.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Engine: Playwright](https://img.shields.io/badge/Engine-Playwright-green.svg)](https://playwright.dev/)
[![Sandbox: Docker](https://img.shields.io/badge/Sandbox-Docker-2496ED.svg)](https://www.docker.com/)

Talon is a practical phishing URL analysis tool that:
- detonates suspicious links in headless Chromium,
- captures forensic evidence (screenshot + DOM snapshot),
- returns an LLM-assisted phishing risk verdict (with heuristic fallback).

---

## ✨ Features (V1)

- **🕵️ URL detonation:** opens a target URL safely in Playwright.
- **🔁 Redirect awareness:** records the final resolved URL after redirects.
- **🧾 Evidence capture:** stores full-page screenshot and DOM snapshot.
- **🤖 LLM analysis:** uses an LLM for smarter risk reasoning.
- **📊 Structured output:** writes a JSON report with score, level, reasons, and method.
- **🧱 Docker sandbox mode:** runs analysis in a hardened container profile.

---

## ⚙️ How It Works

1. **Ingest**: receive a URL input.
2. **Detonate**: load it in headless Chromium.
3. **Collect**: save final URL, HTTP status, title, screenshot, and DOM.
4. **Verdict**: assign a heuristic risk score and reasons.

---

## 📁 Project Structure

```text
.
├── talon_v1.py
├── requirements.txt
├── Dockerfile
├── docker-compose.sandbox.yml
├── .gitignore
└── evidence/              # generated at runtime (ignored by git)
```

---

## 🚀 Local Setup

```bash
git clone https://github.com/tejkdno1/Talon.git
cd Talon
python3 -m pip install -r requirements.txt
python3 -m playwright install chromium
```

---

## ▶️ Quick Start (Host Run)

```bash
python3 talon_v1.py "https://example.com"
```

With LLM enabled (default), set your API key:

```bash
export OPENAI_API_KEY="your_api_key_here"
python3 talon_v1.py "https://example.com"
```

Optional:

```bash
python3 talon_v1.py "example.com/login" --output-dir evidence --timeout-ms 20000
```

Force heuristic-only mode:

```bash
python3 talon_v1.py "https://example.com" --no-llm
```

Optional model override:

```bash
export TALON_LLM_MODEL="gpt-4o-mini"
```

---

## 🛡️ Docker Sandbox Run (Recommended)

Build once:

```bash
docker compose -f docker-compose.sandbox.yml build
```

Run analysis:

```bash
TARGET_URL="https://leadscruise.com" docker compose -f docker-compose.sandbox.yml run --rm talon
```

The sandbox profile includes:
- read-only root filesystem,
- all Linux capabilities dropped,
- `no-new-privileges`,
- CPU/memory/PID limits,
- output only through mounted `./evidence`.

---

## 📦 Output Artifacts

Each run generates files in `evidence/`:
- `report_<timestamp>.json`
- `screenshot_<timestamp>.png`
- `dom_<timestamp>.html`

`report_<timestamp>.json` includes `analysis_method` (`llm` or `heuristic`).

---

## 🔐 Security Note

Docker sandboxing significantly reduces risk compared to running directly on the host, but no sandbox is perfect. For high-risk investigations, use a dedicated VM and isolated network segment.