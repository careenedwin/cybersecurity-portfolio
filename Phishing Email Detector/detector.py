#!/usr/bin/env python3

import re
import time
import requests
from email import message_from_string
from urllib.parse import urlparse

# ── Config ────────────────────────────────
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

# ── Phishing indicators ───────────────────
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify your account", "confirm your identity",
    "suspended", "unusual activity", "click here", "act now",
    "limited time", "you have won", "congratulations",
    "update your payment", "your account will be closed",
    "dear customer", "validate your", "login attempt",
    "reset your password immediately", "wire transfer",
    "kindly provide", "bank account", "social security",
    "prize", "free gift", "you are selected", "claim now",
    "expires soon", "unauthorized access", "security alert",
    "account expires", "payment failed", "billing information"
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "mail.com", "protonmail.com",
    "icloud.com", "zoho.com"
]

COMPANY_WORDS = [
    "bank", "paypal", "amazon", "apple", "microsoft",
    "netflix", "google", "support", "security", "service",
    "account", "team", "official", "noreply", "billing",
    "alert", "notification", "verify", "admin"
]

LOOKALIKES = {
    "paypa1": "paypal", "arnazon": "amazon", "g00gle": "google",
    "micros0ft": "microsoft", "app1e": "apple", "netfl1x": "netflix",
    "faceb00k": "facebook", "твitter": "twitter", "1nstagram": "instagram",
    "dropb0x": "dropbox", "linkedln": "linkedin", "yah00": "yahoo"
}

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".pw", ".cc", ".su", ".ru", ".ws"
]

# ═══════════════════════════════════════════
# LAYER 1 — HEADER ANALYSIS
# ═══════════════════════════════════════════
def analyse_headers(msg):
    findings = []
    score = 0

    from_header  = msg.get("From", "")
    reply_to     = msg.get("Reply-To", "")
    return_path  = msg.get("Return-Path", "")

    from_match   = re.search(r'@([\w\.-]+)', from_header)
    from_domain  = from_match.group(1).lower() if from_match else ""

    # Reply-To mismatch
    if reply_to:
        rt_match = re.search(r'@([\w\.-]+)', reply_to)
        rt_domain = rt_match.group(1).lower() if rt_match else ""
        if from_domain and rt_domain and from_domain != rt_domain:
            findings.append(f"⚠  Reply-To domain ({rt_domain}) differs from From domain ({from_domain})")
            score += 2

    # Return-Path mismatch
    if return_path:
        rp_match = re.search(r'@([\w\.-]+)', return_path)
        rp_domain = rp_match.group(1).lower() if rp_match else ""
        if from_domain and rp_domain and from_domain != rp_domain:
            findings.append(f"⚠  Return-Path domain ({rp_domain}) differs from From ({from_domain})")
            score += 2

    # Free email provider pretending to be a company
    display_match = re.search(r'^(.+?)\s*<', from_header)
    display_name  = display_match.group(1).strip() if display_match else ""
    if from_domain in FREE_EMAIL_PROVIDERS and display_name:
        if any(w in display_name.lower() for w in COMPANY_WORDS):
            findings.append(f"⚠  '{display_name}' claims to be a company but uses {from_domain}")
            score += 3

    # Missing DKIM
    if not msg.get("DKIM-Signature"):
        findings.append("⚠  No DKIM signature — email authenticity cannot be verified")
        score += 1

    # Missing SPF result
    received_spf = msg.get("Received-SPF", "")
    if received_spf and "fail" in received_spf.lower():
        findings.append("⚠  SPF check failed — sender not authorised for this domain")
        score += 2

    if not findings:
        findings.append("✓  No header anomalies detected")

    return findings, score


# ═══════════════════════════════════════════
# LAYER 2 — KEYWORD ANALYSIS
# ═══════════════════════════════════════════
def analyse_keywords(text):
    findings = []
    score    = 0
    found    = []
    lower    = text.lower()

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            found.append(kw)
            score += 1

    if found:
        preview = ", ".join(f'"{k}"' for k in found[:6])
        more    = f" (+{len(found)-6} more)" if len(found) > 6 else ""
        findings.append(f"⚠  Suspicious keywords found: {preview}{more}")
    else:
        findings.append("✓  No suspicious keywords detected")

    return findings, min(score, 6)


# ═══════════════════════════════════════════
# LAYER 3 — URL PATTERN ANALYSIS
# ═══════════════════════════════════════════
def extract_urls(text):
    pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+!*\\(\\),]|(?:%[0-9a-fA-F]{2}))+'
    )
    return list(set(pattern.findall(text)))


def analyse_url_patterns(urls):
    findings = []
    score    = 0
    flagged  = []

    if not urls:
        findings.append("✓  No URLs found in email body")
        return findings, score, flagged

    findings.append(f"ℹ  Found {len(urls)} URL(s)")

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Raw IP address
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            findings.append(f"⚠  URL uses a raw IP address instead of a domain: {url[:65]}")
            score  += 3
            flagged.append(url)

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(f"⚠  Suspicious domain extension '{tld}': {domain}")
                score  += 2
                flagged.append(url)
                break

        # Excessively long URL
        if len(url) > 100:
            findings.append(f"⚠  Unusually long URL ({len(url)} chars) — may hide real destination")
            score  += 1
            flagged.append(url)

        # Typosquatting / homograph
        for fake, real in LOOKALIKES.items():
            if fake in domain:
                findings.append(f"⚠  Typosquatting detected: '{fake}' is impersonating '{real}'")
                score  += 3
                flagged.append(url)

        # URL shorteners (always redirect somewhere else)
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl",
                      "ow.ly", "buff.ly", "short.io", "rb.gy"]
        if any(s in domain for s in shorteners):
            findings.append(f"⚠  URL shortener detected ({domain}) — real destination is hidden")
            score  += 2
            flagged.append(url)

        # @ symbol in URL (tricks browser into ignoring the left part)
        if "@" in url:
            findings.append(f"⚠  '@' symbol in URL — browser ignores everything before it")
            score  += 3
            flagged.append(url)

        # Multiple subdomains (e.g. paypal.com.login.evil.com)
        parts = domain.split(".")
        if len(parts) > 4:
            findings.append(f"⚠  Excessive subdomains in URL — may disguise real domain: {domain}")
            score  += 2
            flagged.append(url)

    return findings, min(score, 8), list(set(flagged))


# ═══════════════════════════════════════════
# LAYER 4 — REDIRECT TRACING
# ═══════════════════════════════════════════
def trace_redirects(url):
    findings  = []
    score     = 0
    final_url = url

    try:
        headers  = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=8,
            stream=True
        )
        response.close()

        history   = response.history
        final_url = response.url

        if history:
            findings.append(f"⚠  URL redirects {len(history)} time(s):")
            for i, r in enumerate(history):
                findings.append(f"     hop {i+1} [{r.status_code}] → {r.url[:70]}")
            findings.append(f"     final destination: {final_url[:70]}")

            original_domain = urlparse(url).netloc.lower()
            final_domain    = urlparse(final_url).netloc.lower()

            if original_domain != final_domain:
                findings.append(f"")
                findings.append(f"⚠  DOMAIN MISMATCH — link leads to a different site!")
                findings.append(f"     displayed : {original_domain}")
                findings.append(f"     actual    : {final_domain}")
                score += 4
            else:
                findings.append(f"✓  Final domain matches original domain")

        else:
            findings.append(f"✓  No redirects — resolves directly to: {final_url[:70]}")

        # Check final URL for suspicious patterns too
        final_domain = urlparse(final_url).netloc.lower()
        for tld in SUSPICIOUS_TLDS:
            if final_domain.endswith(tld):
                findings.append(f"⚠  Final destination has suspicious TLD: {final_domain}")
                score += 2
                break

        for fake, real in LOOKALIKES.items():
            if fake in final_domain:
                findings.append(f"⚠  Final destination is typosquatting '{real}': {final_domain}")
                score += 3
                break

    except requests.exceptions.ConnectionError:
        findings.append(f"⚠  Could not connect — site may be offline or domain is fake")
        score += 1
    except requests.exceptions.Timeout:
        findings.append(f"⚠  Request timed out — suspicious (legitimate sites respond fast)")
        score += 1
    except requests.exceptions.TooManyRedirects:
        findings.append(f"⚠  Too many redirects — likely a redirect loop (very suspicious)")
        score += 3
    except Exception as e:
        findings.append(f"ℹ  Could not trace URL: {str(e)[:60]}")

    return findings, score, final_url


# ═══════════════════════════════════════════
# LAYER 5 — VIRUSTOTAL API
# ═══════════════════════════════════════════
def check_virustotal(urls):
    findings = []

    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        findings.append("ℹ  VirusTotal skipped — paste your API key into the VT_API_KEY variable")
        return findings

    if not urls:
        findings.append("ℹ  No flagged URLs to check against VirusTotal")
        return findings

    headers = {"x-apikey": VT_API_KEY}

    for url in urls[:3]:
        try:
            # Submit URL
            resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )

            if resp.status_code == 429:
                findings.append("⚠  VirusTotal rate limit reached — wait 1 minute and retry")
                break

            if resp.status_code != 200:
                findings.append(f"⚠  VirusTotal returned error {resp.status_code} for {url[:40]}")
                continue

            analysis_id = resp.json()["data"]["id"]
            time.sleep(3)

            # Fetch result
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )

            stats     = result.json()["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious= stats.get("suspicious", 0)
            total     = sum(stats.values())

            short_url = url[:50] + "..." if len(url) > 50 else url

            if malicious > 0:
                findings.append(f"🚨 MALICIOUS: {short_url}")
                findings.append(f"   {malicious}/{total} antivirus engines flagged this URL")
            elif suspicious > 0:
                findings.append(f"⚠  SUSPICIOUS: {short_url}")
                findings.append(f"   {suspicious}/{total} engines flagged as suspicious")
            else:
                findings.append(f"✓  Clean: {short_url}")
                findings.append(f"   0/{total} engines flagged this URL")

        except requests.RequestException as e:
            findings.append(f"⚠  VirusTotal request failed: {str(e)[:50]}")

    return findings


# ═══════════════════════════════════════════
# VERDICT ENGINE
# ═══════════════════════════════════════════
def get_verdict(score):
    if score == 0:
        return "✅  CLEAN",    "No phishing indicators found"
    elif score <= 3:
        return "🟡  LOW RISK", "Minor indicators — treat with caution"
    elif score <= 7:
        return "🟠  MEDIUM",   "Multiple indicators — likely phishing"
    elif score <= 12:
        return "🔴  HIGH RISK","Strong phishing indicators — do not click any links"
    else:
        return "🚨  CRITICAL", "Almost certainly phishing — delete immediately"


# ═══════════════════════════════════════════
# MAIN ANALYSER
# ═══════════════════════════════════════════
def analyse_email(raw_email):
    msg = message_from_string(raw_email)

    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    body += str(part.get_payload())
    else:
        payload = msg.get_payload(decode=True)
        body    = payload.decode(errors="ignore") if isinstance(payload, bytes) else str(msg.get_payload())

    full_text   = f"{msg.get('Subject', '')} {body}"
    total_score = 0

    # ── Header ──────────────────────────────
    print("\n" + "═"*58)
    print("  PHISHING EMAIL DETECTOR")
    print("  Cybersecurity Portfolio — Project 3")
    print("  Author: Careen | University of Dodoma")
    print("═"*58)
    print(f"\n  From      : {msg.get('From',      'N/A')}")
    print(f"  To        : {msg.get('To',        'N/A')}")
    print(f"  Subject   : {msg.get('Subject',   'N/A')}")
    print(f"  Reply-To  : {msg.get('Reply-To',  'N/A')}")
    print(f"  Return-Path: {msg.get('Return-Path','N/A')}")

    # ── Layer 1 ─────────────────────────────
    print("\n── [Layer 1] Header Analysis ───────────────────────")
    h_findings, h_score = analyse_headers(msg)
    for f in h_findings:
        print(f"  {f}")
    total_score += h_score

    # ── Layer 2 ─────────────────────────────
    print("\n── [Layer 2] Keyword Analysis ──────────────────────")
    k_findings, k_score = analyse_keywords(full_text)
    for f in k_findings:
        print(f"  {f}")
    total_score += k_score

    # ── Layer 3 ─────────────────────────────
    print("\n── [Layer 3] URL Pattern Analysis ─────────────────")
    urls = extract_urls(body)
    u_findings, u_score, flagged_urls = analyse_url_patterns(urls)
    for f in u_findings:
        print(f"  {f}")
    total_score += u_score

    # ── Layer 4 ─────────────────────────────
    print("\n── [Layer 4] Redirect Tracing ──────────────────────")
    if urls:
        all_final_urls = []
        for url in urls[:3]:
            print(f"  Tracing: {url[:60]}...")
            r_findings, r_score, final = trace_redirects(url)
            for f in r_findings:
                print(f"  {f}")
            total_score += r_score
            all_final_urls.append(final)
            print()
    else:
        print("  ℹ  No URLs to trace")

    # ── Layer 5 ─────────────────────────────
    print("\n── [Layer 5] VirusTotal Check ──────────────────────")
    vt_findings = check_virustotal(flagged_urls)
    for f in vt_findings:
        print(f"  {f}")

    # ── Verdict ──────────────────────────────
    rating, description = get_verdict(total_score)
    print("\n" + "═"*58)
    print(f"  VERDICT     : {rating}")
    print(f"  DESCRIPTION : {description}")
    print(f"  RISK SCORE  : {total_score} points")
    print("═"*58 + "\n")


# ═══════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════
def main():
    print("\n" + "═"*58)
    print("  Paste the raw email below.")
    print("  When finished, type END on a new line and press Enter.")
    print("═"*58 + "\n")

    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        except EOFError:
            break

    raw_email = "\n".join(lines)
    if raw_email.strip():
        analyse_email(raw_email)
    else:
        print("\n  No email provided. Exiting.\n")

if __name__ == "__main__":
    main()
EOF
