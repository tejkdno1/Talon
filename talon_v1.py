#!/usr/bin/env python3
"""
Talon V1 (basic): URL detonation + evidence capture + heuristic verdict.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


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

    return Verdict(risk_score=score, risk_level=level, reasons=reasons)


def analyze_url(url: str, output_dir: Path, timeout_ms: int = 15000) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    screenshot_path = output_dir / f"screenshot_{ts}.png"
    dom_path = output_dir / f"dom_{ts}.html"
    report_path = output_dir / f"report_{ts}.json"

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
        dom_path.write_text(page.content(), encoding="utf-8")

        verdict = build_verdict(final_url, title)
        report = {
            "input_url": url,
            "final_url": final_url,
            "http_status": status,
            "page_title": title,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
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
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Talon V1: analyze a URL for basic phishing indicators."
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    normalized = normalize_url(args.url)
    report = analyze_url(normalized, Path(args.output_dir), timeout_ms=args.timeout_ms)

    print("=== TALON V1 REPORT ===")
    print(f"Input URL:   {report['input_url']}")
    print(f"Final URL:   {report['final_url']}")
    print(f"HTTP Status: {report['http_status']}")
    print(f"Page Title:  {report['page_title']}")
    print(
        f"Risk:        {report['verdict']['risk_level']} "
        f"({report['verdict']['risk_score']}/100)"
    )
    for reason in report["verdict"]["reasons"]:
        print(f"- {reason}")
    print(f"Report JSON: {report['report_path']}")
    print(f"Screenshot:  {report['evidence']['screenshot']}")
    print(f"DOM:         {report['evidence']['dom_snapshot']}")


if __name__ == "__main__":
    main()
