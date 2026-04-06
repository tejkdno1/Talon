#!/usr/bin/env python3
"""Talon V1: URL detonation + evidence capture + heuristic/LLM verdict."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# For one-file executable builds, ensure browsers are stored in a persistent path.
if "PLAYWRIGHT_BROWSERS_PATH" not in os.environ:
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(Path.home() / ".cache" / "ms-playwright")

from playwright.sync_api import sync_playwright
from playwright._impl._errors import Error as PlaywrightError

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

SECTALON_CONFIG_PATH = Path.home() / ".config" / "sectalon" / "config.json"


def print_banner() -> None:
    # Green-accent terminal banner for a distinct CLI look-and-feel.
    green = "\033[92m"
    bold = "\033[1m"
    reset = "\033[0m"
    dim = "\033[2m"

    art = [
        "  _____ ______ _____ _______       _      ____  _   _ ",
        " / ____|  ____/ ____|__   __|/\\   | |    / __ \\| \\ | |",
        "| (___ | |__ | |       | |  /  \\  | |   | |  | |  \\| |",
        " \\___ \\|  __|| |       | | / /\\ \\ | |   | |  | | . ` |",
        " ____) | |___| |____   | |/ ____ \\| |___| |__| | |\\  |",
        "|_____/|______\\_____|  |_/_/    \\_\\______\\____/|_| \\_|",
    ]

    print()
    print(f"{green}{bold}{'=' * 64}{reset}")
    for line in art:
        print(f"{green}{bold}{line}{reset}")
    print(f"{green}{bold}{'=' * 64}{reset}")
    print(f"{green}{bold}          S E C T A L O N   |   A I   P H I S H I N G   H U N T E R{reset}")
    print(f"{dim}          Smart URL detonation, evidence capture, and LLM verdicts.{reset}")
    print()


def print_onboard_banner() -> None:
    green = "\033[92m"
    bold = "\033[1m"
    reset = "\033[0m"
    print()
    print(f"{green}{bold}🛡️  Sectalon Onboarding{reset}")
    print(f"{green}{'-' * 34}{reset}")
    print("Connect your LLM backend once, then use intent-aware commands.")
    print()


def load_config() -> dict:
    if not SECTALON_CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(SECTALON_CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_config(config: dict) -> None:
    SECTALON_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    SECTALON_CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def apply_config_env(config: dict) -> None:
    mapping = {
        "llm_provider": "TALON_LLM_PROVIDER",
        "llm_model": "TALON_LLM_MODEL",
        "ollama_host": "OLLAMA_HOST",
        "ollama_timeout_sec": "OLLAMA_TIMEOUT_SEC",
        "openai_api_key": "OPENAI_API_KEY",
        "openai_model": "TALON_OPENAI_MODEL",
    }
    for key, env_name in mapping.items():
        value = config.get(key)
        if value and env_name not in os.environ:
            os.environ[env_name] = str(value)


def run_onboarding() -> int:
    print_onboard_banner()
    current = load_config()
    if current:
        print("Found existing config. Leave input blank to keep current values.")
    else:
        print("No existing config found. Let's create one.")

    provider_default = current.get("llm_provider", "ollama")
    provider = (
        input(f"LLM provider [ollama/openai/auto] (default: {provider_default}): ").strip().lower()
        or provider_default
    )
    if provider not in {"ollama", "openai", "auto"}:
        provider = provider_default

    model_default = current.get("llm_model", "gemma4")
    model = input(f"Default LLM model (default: {model_default}): ").strip() or model_default

    ollama_host_default = current.get("ollama_host", "http://localhost:11434")
    ollama_host = (
        input(f"Ollama host (default: {ollama_host_default}): ").strip() or ollama_host_default
    )
    timeout_default = str(current.get("ollama_timeout_sec", "180"))
    timeout = input(f"Ollama timeout seconds (default: {timeout_default}): ").strip() or timeout_default

    openai_model_default = current.get("openai_model", "gpt-4o-mini")
    openai_model = (
        input(f"OpenAI model (default: {openai_model_default}): ").strip() or openai_model_default
    )
    key_hint = "set" if current.get("openai_api_key") else "not set"
    api_key = input(f"OpenAI API key [{key_hint}] (blank keeps existing): ").strip()
    if not api_key:
        api_key = current.get("openai_api_key", "")

    config = {
        "llm_provider": provider,
        "llm_model": model,
        "ollama_host": ollama_host,
        "ollama_timeout_sec": timeout,
        "openai_model": openai_model,
        "openai_api_key": api_key,
    }
    save_config(config)
    print(f"\nSaved config: {SECTALON_CONFIG_PATH}")
    print("Try:")
    print('  sectalon intent "check if amezon.in is suspicious"')
    print('  sectalon "https://example.com"')
    return 0


def parse_json_object_loose(text: str) -> dict | None:
    raw = text.strip()
    if "```" in raw:
        match = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", raw, re.IGNORECASE)
        if match:
            raw = match.group(1).strip()
    if not raw.startswith("{"):
        match = re.search(r"(\{[\s\S]*\})", raw)
        if match:
            raw = match.group(1).strip()
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        return None
    return None


def llm_generate_json(prompt: str, provider: str, model: str) -> dict | None:
    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key or OpenAI is None:
            return None
        try:
            client = OpenAI(api_key=api_key)
            response = client.responses.create(model=model, input=prompt, max_output_tokens=300)
            return parse_json_object_loose(response.output_text)
        except Exception:
            return None

    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    timeout_sec = int(os.getenv("OLLAMA_TIMEOUT_SEC", "180"))
    request = Request(
        f"{host}/api/generate",
        data=json.dumps(
            {"model": model, "prompt": prompt, "format": "json", "stream": False}
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_sec) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return parse_json_object_loose(str(body.get("response", "")))
    except Exception:
        return None


def run_intent_command(text: str) -> int:
    config = load_config()
    apply_config_env(config)
    provider = os.getenv("TALON_LLM_PROVIDER", "auto").lower()
    model = os.getenv("TALON_LLM_MODEL", "gemma4")
    openai_model = os.getenv("TALON_OPENAI_MODEL", "gpt-4o-mini")

    prompt = (
        "Classify this user request for a phishing-analysis CLI.\n"
        "Return strict JSON only with keys:\n"
        "- intent: one of [analyze_url, onboard, help, unknown]\n"
        "- url: string or null\n"
        "- confidence: number 0..1\n"
        "- reason: short string\n\n"
        f"User input: {text}\n"
    )

    result = None
    if provider == "auto":
        result = llm_generate_json(prompt, "ollama", model) or llm_generate_json(
            prompt, "openai", openai_model
        )
    elif provider == "openai":
        result = llm_generate_json(prompt, "openai", openai_model)
    else:
        result = llm_generate_json(prompt, "ollama", model)

    if not result:
        print("Intent: unknown")
        print("Confidence: 0.0")
        print("Reason: LLM backend unavailable or invalid response.")
        return 1

    print("=== SECTALON INTENT ===")
    print(f"Intent:      {result.get('intent', 'unknown')}")
    print(f"URL:         {result.get('url')}")
    print(f"Confidence:  {result.get('confidence')}")
    print(f"Reason:      {result.get('reason')}")
    return 0


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


def get_registrable_hint(host: str) -> str:
    parts = [p for p in host.lower().split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            delete = prev[j] + 1
            replace = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, delete, replace))
        prev = curr
    return prev[-1]


def build_verdict(input_url: str, final_url: str, page_title: str) -> Verdict:
    input_parsed = urlparse(input_url)
    parsed = urlparse(final_url)
    input_host = (input_parsed.hostname or "").lower()
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

    if input_host and host and input_host != host:
        score += 15
        reasons.append(f"Input host redirected from '{input_host}' to '{host}'.")
        input_base = get_registrable_hint(input_host)
        final_base = get_registrable_hint(host)
        edit_dist = levenshtein_distance(input_base, final_base)
        similarity = difflib.SequenceMatcher(a=input_base, b=final_base).ratio()
        if edit_dist <= 2 and similarity >= 0.7:
            score += 35
            reasons.append(
                f"Possible typosquat: '{input_base}' is very similar to '{final_base}'."
            )

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
    timeout_sec = int(os.getenv("OLLAMA_TIMEOUT_SEC", "180"))
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
        with urlopen(request, timeout=timeout_sec) as resp:
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
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = run_dir / "screenshot.png"
    dom_path = run_dir / "dom.html"
    report_path = run_dir / "report.json"

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except PlaywrightError as launch_error:
            if "Executable doesn't exist" not in str(launch_error):
                raise
            # First run (or clean machine): bootstrap Chromium automatically.
            import playwright.__main__ as playwright_cli

            original_argv = sys.argv[:]
            try:
                sys.argv = ["playwright", "install", "chromium"]
                playwright_cli.main()
            finally:
                sys.argv = original_argv
            browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        error_message = None
        error_path = run_dir / "error.txt"

        try:
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
            verdict = llm_verdict or build_verdict(url, final_url, title)
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
        except PlaywrightError as nav_error:
            error_message = str(nav_error).splitlines()[0]
            error_path.write_text(error_message + "\n", encoding="utf-8")
            verdict = Verdict(
                risk_score=60,
                risk_level="MEDIUM",
                reasons=[f"Navigation failed: {error_message}"],
                method="runtime-error",
            )
            report = {
                "input_url": url,
                "final_url": url,
                "http_status": None,
                "page_title": "UNREACHABLE",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "analysis_method": verdict.method,
                "verdict": asdict(verdict),
                "error": error_message,
                "evidence": {
                    "screenshot": None,
                    "dom_snapshot": None,
                    "error_log": str(error_path),
                },
            }
        finally:
            context.close()
            browser.close()

        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    report["report_path"] = str(report_path)
    report["run_dir"] = str(run_dir)

    run_log_entry = {
        "timestamp_utc": report["timestamp_utc"],
        "input_url": report["input_url"],
        "final_url": report["final_url"],
        "http_status": report["http_status"],
        "page_title": report["page_title"],
        "analysis_method": report["analysis_method"],
        "risk_score": report["verdict"]["risk_score"],
        "risk_level": report["verdict"]["risk_level"],
        "run_dir": report["run_dir"],
        "report_path": report["report_path"],
        "screenshot": report["evidence"]["screenshot"],
        "dom_snapshot": report["evidence"]["dom_snapshot"],
        "error": report.get("error"),
    }
    with (logs_dir / "runs.jsonl").open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(run_log_entry, ensure_ascii=True) + "\n")

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
    if len(sys.argv) > 1 and sys.argv[1] == "onboard":
        raise SystemExit(run_onboarding())
    if len(sys.argv) > 1 and sys.argv[1] == "intent":
        intent_text = " ".join(sys.argv[2:]).strip()
        if not intent_text:
            print('Usage: sectalon intent "<your request text>"')
            raise SystemExit(2)
        raise SystemExit(run_intent_command(intent_text))

    apply_config_env(load_config())
    args = parse_args()
    if os.getenv("SECTALON_NO_BANNER", "").strip().lower() not in {"1", "true", "yes"}:
        print_banner()
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
    if report.get("error"):
        print(f"Error:       {report['error']}")
        print(f"Error Log:   {report['evidence'].get('error_log')}")
    else:
        print(f"Screenshot:  {report['evidence']['screenshot']}")
        print(f"DOM:         {report['evidence']['dom_snapshot']}")


if __name__ == "__main__":
    main()
