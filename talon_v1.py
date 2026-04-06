#!/usr/bin/env python3
"""Talon V1: URL detonation + evidence capture + heuristic/LLM verdict."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from playwright.sync_api import sync_playwright

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


SUSPICIOUS_TLDS = {
    "ru",
    "tk",
    "top",
    "xyz",
    "click",
    "work",
    "gq",
    "fit",
    "cf",
    "ml",
    "ga",
}

PHISH_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "banking",
    "microsoft",
    "outlook",
    "paypal",
}


@dataclass
class Verdict:
    risk_score: int
    risk_level: str
    reasons: list[str]
    method: str


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def build_verdict(final_url: str, page_title: str) -> Verdict:
    parsed = urlparse(final_url)
    host = (parsed.hostname or "").lower()
    path_query = f"{parsed.path} {parsed.query}".lower()
    reasons: list[str] = []
    score = 0

    if "xn--" in host:
        score += 30
        reasons.append("Host contains punycode (possible homograph attack).")

    if is_ip_host(host):
        score += 25
        reasons.append("URL host is a raw IP address.")

    if "@" in final_url:
        score += 20
        reasons.append("URL contains '@' which can obscure real destination.")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Top-level domain '.{tld}' is commonly abused.")

    kw_hits = [kw for kw in PHISH_KEYWORDS if kw in path_query or kw in host]
    if kw_hits:
        score += min(30, 8 * len(kw_hits))
        reasons.append(f"Phishing-like keywords found: {', '.join(sorted(kw_hits))}.")

    title_lower = page_title.lower()
    if any(brand in title_lower for brand in ("microsoft", "google", "paypal", "bank")):
        if not any(brand in host for brand in ("microsoft", "google", "paypal", "bank")):
            score += 20
            reasons.append("Title suggests trusted brand, but host does not match.")

    score = max(0, min(100, score))
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("No obvious phishing indicators found by V1 heuristics.")

    return Verdict(risk_score=score, risk_level=level, reasons=reasons, method="heuristic")


def strip_html_for_prompt(html: str, max_chars: int = 3000) -> str:
    text = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


def parse_llm_verdict(content: str) -> Verdict | None:
    text = content.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", text, re.IGNORECASE)
        if match:
            text = match.group(1).strip()
    if not text.startswith("{"):
        match = re.search(r"(\{[\s\S]*\})", text)
        if match:
            text = match.group(1).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None

    try:
        score = int(data.get("risk_score", 0))
    except (TypeError, ValueError):
        score = 0
    level = str(data.get("risk_level", "LOW")).upper()
    reasons = data.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    if level not in {"LOW", "MEDIUM", "HIGH"}:
        if score >= 70:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

    return Verdict(
        risk_score=max(0, min(100, score)),
        risk_level=level,
        reasons=[str(r) for r in reasons[:6]] or ["No reasons returned by LLM."],
        method="llm",
    )


def build_prompt(
    input_url: str,
    final_url: str,
    page_title: str,
    http_status: int | None,
    dom_html: str,
) -> str:
    content_text = strip_html_for_prompt(dom_html)
    return (
        "You are a phishing detection analyst. "
        "Classify risk for this URL visit and return strict JSON only.\n\n"
        f"Input URL: {input_url}\n"
        f"Final URL: {final_url}\n"
        f"HTTP status: {http_status}\n"
        f"Page title: {page_title}\n"
        f"Page text excerpt: {content_text}\n\n"
        "Return JSON with keys:\n"
        "- risk_score (0-100 integer)\n"
        "- risk_level ('LOW'|'MEDIUM'|'HIGH')\n"
        "- reasons (array of short strings)\n"
    )


def build_openai_verdict(prompt: str, model: str) -> Verdict | None:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key or OpenAI is None:
        return None

    client = OpenAI(api_key=api_key)
    try:
        response = client.responses.create(
            model=model,
            input=prompt,
            max_output_tokens=400,
        )
        raw = response.output_text.strip()
        verdict = parse_llm_verdict(raw)
        if verdict:
            verdict.method = "llm-openai"
        return verdict
    except Exception:
        return None


def build_ollama_verdict(prompt: str, model: str) -> Verdict | None:
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    endpoint = f"{host}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "format": "json",
        "stream": False,
    }
    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=60) as resp:
            body = resp.read().decode("utf-8")
        data = json.loads(body)
        raw = str(data.get("response", "")).strip()
        verdict = parse_llm_verdict(raw)
        if verdict:
            verdict.method = "llm-ollama"
        return verdict
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def build_llm_verdict(
    input_url: str,
    final_url: str,
    page_title: str,
    http_status: int | None,
    dom_html: str,
    llm_provider: str = "auto",
    llm_model: str | None = None,
) -> Verdict | None:
    provider = llm_provider.lower()
    ollama_model = llm_model or os.getenv("TALON_LLM_MODEL", "gemma4")
    openai_model = os.getenv("TALON_OPENAI_MODEL", "gpt-4o-mini")
    prompt = build_prompt(input_url, final_url, page_title, http_status, dom_html)

    if provider == "openai":
        return build_openai_verdict(prompt, llm_model or openai_model)
    if provider == "ollama":
        return build_ollama_verdict(prompt, ollama_model)

    # auto: prefer local ollama first, then openai.
    return build_ollama_verdict(prompt, ollama_model) or build_openai_verdict(prompt, openai_model)


def analyze_url(
    url: str,
    output_dir: Path,
    timeout_ms: int = 15000,
    use_llm: bool = True,
    llm_provider: str = "auto",
    llm_model: str | None = None,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = run_dir / "screenshot.png"
    dom_path = run_dir / "dom.html"
    report_path = run_dir / "report.json"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        page.wait_for_timeout(1000)

        final_url = page.url
        title = page.title()
        status = response.status if response else None

        page.screenshot(path=str(screenshot_path), full_page=True)
        dom_html = page.content()
        dom_path.write_text(dom_html, encoding="utf-8")

        llm_verdict = None
        if use_llm:
            llm_verdict = build_llm_verdict(
                url,
                final_url,
                title,
                status,
                dom_html,
                llm_provider=llm_provider,
                llm_model=llm_model,
            )
        verdict = llm_verdict or build_verdict(final_url, title)
        report = {
            "input_url": url,
            "final_url": final_url,
            "http_status": status,
            "page_title": title,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "analysis_method": verdict.method,
            "verdict": asdict(verdict),
            "evidence": {
                "screenshot": str(screenshot_path),
                "dom_snapshot": str(dom_path),
            },
        }
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        context.close()
        browser.close()

    report["report_path"] = str(report_path)
    report["run_dir"] = str(run_dir)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Talon V1: analyze a URL with LLM + heuristic fallback."
    )
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument(
        "--output-dir",
        default="evidence",
        help="Directory where screenshot/DOM/report will be saved",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=15000,
        help="Navigation timeout in milliseconds",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM analysis and use heuristics only",
    )
    parser.add_argument(
        "--llm-provider",
        choices=["auto", "ollama", "openai"],
        default=os.getenv("TALON_LLM_PROVIDER", "auto"),
        help="LLM backend provider (default: env TALON_LLM_PROVIDER or auto)",
    )
    parser.add_argument(
        "--llm-model",
        default=os.getenv("TALON_LLM_MODEL", "gemma4"),
        help="LLM model name (default: env TALON_LLM_MODEL or gemma4)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    normalized = normalize_url(args.url)
    report = analyze_url(
        normalized,
        Path(args.output_dir),
        timeout_ms=args.timeout_ms,
        use_llm=not args.no_llm,
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
    )

    print("=== TALON V1 REPORT ===")
    print(f"Input URL:   {report['input_url']}")
    print(f"Final URL:   {report['final_url']}")
    print(f"HTTP Status: {report['http_status']}")
    print(f"Page Title:  {report['page_title']}")
    print(
        f"Risk:        {report['verdict']['risk_level']} "
        f"({report['verdict']['risk_score']}/100)"
    )
    print(f"Method:      {report['analysis_method']}")
    for reason in report["verdict"]["reasons"]:
        print(f"- {reason}")
    print(f"Run Dir:     {report['run_dir']}")
    print(f"Report JSON: {report['report_path']}")
    print(f"Screenshot:  {report['evidence']['screenshot']}")
    print(f"DOM:         {report['evidence']['dom_snapshot']}")


if __name__ == "__main__":
    main()
