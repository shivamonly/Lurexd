from __future__ import annotations

import re
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from typing import Any, Literal
from urllib.parse import urlparse

from .config import (
    BRAND_DOMAINS,
    BRAND_NAMES,
    IP_HOST_PATTERN,
    LEET_TRANSLATION,
    LEXICAL_RULES,
    SUSPICIOUS_TOP_LEVEL_DOMAINS,
    URL_PATTERN,
    URL_SHORTENER_DOMAINS,
)
from .database import connect_database


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def root_domain(host_name: str) -> str:
    labels = [part for part in host_name.lower().strip(".").split(".") if part]
    if len(labels) < 2:
        return host_name.lower()
    return ".".join(labels[-2:])


def extract_email_domain(address: str | None) -> str:
    if not address:
        return ""
    parsed_address = parseaddr(address)[1].lower()
    if "@" not in parsed_address:
        return ""
    return parsed_address.rsplit("@", 1)[1].strip(">")


def extract_message_body(message: Any, raw_content: str) -> str:
    try:
        if message.is_multipart():
            body = message.get_body(preferencelist=("plain", "html"))
            if body:
                payload = body.get_content()
                return payload if isinstance(payload, str) else str(payload)

        payload = message.get_payload(decode=False)
        if isinstance(payload, list):
            return "\n".join(str(part.get_payload(decode=False)) for part in payload)
        return payload if isinstance(payload, str) else raw_content
    except Exception:
        return raw_content


def append_finding(
    findings: list[dict[str, Any]],
    title: str,
    detail: str,
    score: int,
    evidence: list[str],
    category: str,
) -> None:
    findings.append(
        {
            "title": title,
            "detail": detail,
            "score": score,
            "category": category,
            "severity": "high" if score >= 15 else "medium" if score >= 9 else "low",
            "evidence": (evidence or ["Detected pattern"])[:5],
        }
    )


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous_row = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current_row = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            insert_cost = current_row[right_index - 1] + 1
            delete_cost = previous_row[right_index] + 1
            replace_cost = previous_row[right_index - 1] + (left_char != right_char)
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row
    return previous_row[-1]


def normalize_url(candidate: str) -> str:
    normalized = candidate.strip().rstrip(".,);]")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", normalized, re.I):
        normalized = f"https://{normalized}"
    return normalized


def is_official_brand_host(host_name: str, brand_name: str) -> bool:
    registered_domain = root_domain(host_name)
    trusted_domains = BRAND_DOMAINS.get(brand_name, set())
    return registered_domain in trusted_domains or any(
        host_name == domain or host_name.endswith(f".{domain}") for domain in trusted_domains
    )


def scan_urls(text: str) -> tuple[list[str], list[dict[str, Any]]]:
    candidates = URL_PATTERN.findall(text)
    if not candidates and "." in text and " " not in text.strip():
        candidates = [text.strip()]

    normalized_urls: list[str] = []
    findings: list[dict[str, Any]] = []
    for candidate in dict.fromkeys(candidates):
        normalized_url = normalize_url(candidate)
        normalized_urls.append(normalized_url)

        parsed_url = urlparse(normalized_url)
        host_name = parsed_url.netloc.lower().split("@")[-1].split(":")[0].strip(".")
        registered_domain = root_domain(host_name)
        evidence = [host_name]

        if "@" in parsed_url.netloc:
            append_finding(
                findings,
                "Credential-Style Redirect Pattern",
                "URL authority contains an @ symbol, which can hide the true destination host.",
                18,
                evidence,
                "Entropy & URL Scanner",
            )
        if parsed_url.scheme == "http":
            append_finding(findings, "Plain HTTP Link", "The link does not use HTTPS transport.", 5, evidence, "Entropy & URL Scanner")
        if IP_HOST_PATTERN.match(host_name):
            append_finding(findings, "Raw IP Address Host", "Legitimate brand mail rarely routes users to bare IP addresses.", 18, evidence, "Entropy & URL Scanner")
        if registered_domain in URL_SHORTENER_DOMAINS:
            append_finding(findings, "Shortened URL", "Shorteners obscure destination context during email review.", 7, evidence, "Entropy & URL Scanner")

        top_level_domain = registered_domain.rsplit(".", 1)[-1] if "." in registered_domain else ""
        if top_level_domain in SUSPICIOUS_TOP_LEVEL_DOMAINS:
            append_finding(
                findings,
                "High-Risk Top-Level Domain",
                f"The .{top_level_domain} TLD is often abused in short-lived phishing infrastructure.",
                11,
                evidence,
                "Entropy & URL Scanner",
            )
        if len(host_name) > 55 or host_name.count(".") >= 4:
            append_finding(findings, "Overlong Domain Structure", "Deep or lengthy hostnames can be used to bury the registered domain.", 8, evidence, "Entropy & URL Scanner")
        if host_name.count("-") >= 3:
            append_finding(findings, "Hyphenated Host Pattern", "Multiple hyphens can signal brand-stuffing or campaign-generated domains.", 7, evidence, "Entropy & URL Scanner")

        host_without_tld = ".".join(host_name.split(".")[:-1])
        normalized_host = host_without_tld.translate(LEET_TRANSLATION)
        host_tokens = re.split(r"[\W_]+", normalized_host)
        for brand_name in BRAND_NAMES:
            brand_is_mentioned = brand_name in normalized_host
            brand_is_typo = any(0 < levenshtein_distance(token, brand_name) <= 2 for token in host_tokens if len(token) >= 4)
            if (brand_is_mentioned or brand_is_typo) and not is_official_brand_host(host_name, brand_name):
                append_finding(
                    findings,
                    "Look-Alike Brand Domain",
                    f"The host resembles {brand_name} but is not one of the expected registered domains.",
                    21 if brand_is_typo else 16,
                    evidence,
                    "Entropy & URL Scanner",
                )
                break

    return normalized_urls, findings


def analyze_lexical_patterns(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for title, pattern, base_score in LEXICAL_RULES:
        matches = sorted({match.group(0).strip() for match in pattern.finditer(text)})
        if matches:
            append_finding(
                findings,
                title,
                "Message language maps to common social-engineering pressure patterns.",
                base_score + min(len(matches) * 2, 6),
                matches,
                "Lexical Analysis Engine",
            )
    return findings


def analyze_email_headers(raw_content: str) -> tuple[str, str | None, list[dict[str, Any]]]:
    has_email_headers = bool(re.search(r"(?im)^(from|reply-to|return-path|authentication-results|subject):\s*", raw_content))
    parse_warning = None
    findings: list[dict[str, Any]] = []
    if not has_email_headers:
        return raw_content, "Unable to parse headers. Proceeding with text-only lexical scan.", findings

    try:
        message = Parser(policy=policy.default).parsestr(raw_content)
    except Exception:
        return raw_content, "Unable to parse headers. Proceeding with text-only lexical scan.", findings

    body_text = extract_message_body(message, raw_content)
    from_domain = extract_email_domain(message.get("From"))
    reply_to_domain = extract_email_domain(message.get("Reply-To"))
    return_path_domain = extract_email_domain(message.get("Return-Path"))
    authentication_results = " ".join(message.get_all("Authentication-Results", []))

    if reply_to_domain and from_domain and root_domain(reply_to_domain) != root_domain(from_domain):
        append_finding(
            findings,
            "Mismatched Sender Domains",
            "Reply-To routes to a different registered domain than the visible From header.",
            18,
            [f"From: {from_domain}", f"Reply-To: {reply_to_domain}"],
            "Header Validator",
        )
    if return_path_domain and from_domain and root_domain(return_path_domain) != root_domain(from_domain):
        append_finding(
            findings,
            "Return-Path Drift",
            "The bounce path differs from the visible sender domain.",
            8,
            [f"From: {from_domain}", f"Return-Path: {return_path_domain}"],
            "Header Validator",
        )

    if authentication_results:
        lowered_results = authentication_results.lower()
        if "spf=fail" in lowered_results or "spf=softfail" in lowered_results:
            append_finding(findings, "SPF Failure", "Authentication-Results reports SPF failure or soft failure.", 16, ["spf=fail"], "Header Validator")
        if "dkim=fail" in lowered_results:
            append_finding(findings, "DKIM Failure", "Authentication-Results reports DKIM failure.", 14, ["dkim=fail"], "Header Validator")
        if "dmarc=fail" in lowered_results:
            append_finding(findings, "DMARC Failure", "Authentication-Results reports DMARC failure.", 17, ["dmarc=fail"], "Header Validator")
    else:
        append_finding(
            findings,
            "Missing Authentication Results",
            "No Authentication-Results header was present for SPF, DKIM, or DMARC inspection.",
            6,
            ["Authentication-Results header not found"],
            "Header Validator",
        )

    if not from_domain:
        append_finding(findings, "Missing Sender Header", "No usable From address was found in the pasted content.", 9, ["From header missing"], "Header Validator")

    return body_text, parse_warning, findings


def risk_severity(risk_score: int) -> str:
    if risk_score >= 75:
        return "Critical"
    if risk_score >= 50:
        return "Elevated"
    if risk_score >= 25:
        return "Guarded"
    return "Low"


def save_detection_result(input_type: str, risk_score: int, findings: list[dict[str, Any]]) -> None:
    summary = ", ".join(item["title"] for item in findings[:4]) or "No major heuristic red flags found"
    with connect_database() as connection:
        connection.execute(
            "INSERT INTO detection_logs (input_type, risk_score, summary) VALUES (?, ?, ?)",
            (input_type, risk_score, summary),
        )


def analyze_threat_content(content: str, input_type: Literal["email", "url"]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    parse_warning = None
    target_text = content

    if input_type == "email":
        target_text, parse_warning, header_findings = analyze_email_headers(content)
        findings.extend(header_findings)

    findings.extend(analyze_lexical_patterns(target_text))
    detected_urls, url_findings = scan_urls(content if input_type == "email" else target_text)
    findings.extend(url_findings)

    if input_type == "url" and not detected_urls:
        append_finding(
            findings,
            "Unparseable URL",
            "The submitted value did not resolve to a URL-like host for structural inspection.",
            10,
            [content[:80]],
            "Entropy & URL Scanner",
        )

    risk_score = min(100, sum(item["score"] for item in findings))
    if not findings:
        risk_score = 4 if input_type == "url" else 6

    save_detection_result(input_type, risk_score, findings)
    return {
        "input_type": input_type,
        "risk_score": risk_score,
        "severity": risk_severity(risk_score),
        "parse_warning": parse_warning,
        "findings": findings,
        "urls": detected_urls,
        "analyzed_at": utc_timestamp(),
    }
