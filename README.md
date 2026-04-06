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
4. **Verdict**: run LLM analysis (`ollama` / `openai`) with heuristic fallback.

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

### Local Ollama (Gemma4) - recommended for your setup

Start Ollama and pull model:

```bash
ollama pull gemma4
```

Run Talon using Ollama backend:

```bash
export TALON_LLM_PROVIDER="ollama"
export TALON_LLM_MODEL="gemma4"
export OLLAMA_HOST="http://localhost:11434"
python3 talon_v1.py "https://example.com"
```

### OpenAI (optional)

If you want cloud LLM instead:

```bash
export OPENAI_API_KEY="your_api_key_here"
export TALON_LLM_PROVIDER="openai"
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
export TALON_LLM_MODEL="gemma4"
```

Optional provider override per run:

```bash
python3 talon_v1.py "https://example.com" --llm-provider ollama --llm-model gemma4
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

For Docker + host Ollama, default `OLLAMA_HOST` is set to:

```bash
http://host.docker.internal:11434
```

You can override it if needed:

```bash
OLLAMA_HOST="http://host.docker.internal:11434" TARGET_URL="https://example.com" docker compose -f docker-compose.sandbox.yml run --rm talon
```

The sandbox profile includes:
- read-only root filesystem,
- all Linux capabilities dropped,
- `no-new-privileges`,
- CPU/memory/PID limits,
- output only through mounted `./evidence`.

---

## 📦 Output Artifacts

Each scan now creates a dedicated run folder:

- `evidence/run_<timestamp>/report.json`
- `evidence/run_<timestamp>/screenshot.png`
- `evidence/run_<timestamp>/dom.html`

Each `report.json` includes `analysis_method`:
- `llm-ollama`
- `llm-openai`
- `heuristic`

Run logs are also appended to:
- `logs/runs.jsonl` (one JSON entry per scan)

---

## 🔐 Security Note

Docker sandboxing significantly reduces risk compared to running directly on the host, but no sandbox is perfect. For high-risk investigations, use a dedicated VM and isolated network segment.