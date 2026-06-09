# Phishing Email Detector — Project Report

**Tool:** Custom Python 3 script



## Objective

To build a tool that analyses suspicious emails across multiple
detection layers, simulating the workflow a real SOC (Security
Operations Centre) analyst follows when triaging a phishing report.



## Emails tested

| Email | Type | Verdict | Score |
|-------|------|---------|-------|
| `phishing1.eml` | PayPal impersonation | 🚨 Critical | 18 pts |
| `phishing2.eml` | Netflix billing scam with bit.ly redirect | 🔴 High risk | 13 pts |
| `clean1.eml` | Legitimate university notification | ✅ Clean | 0 pts |



## Layer-by-layer findings

### Layer 1 — Header analysis

The most reliable indicator found across both phishing samples was the
Reply-To mismatch. In `phishing1.eml`, the email claimed to be from
PayPal but the Reply-To pointed to a personal Gmail account. This is
a classic spoofing technique — the sender wants replies to go to an
attacker-controlled inbox while the From field shows a trusted name.

Neither phishing email contained a DKIM signature, meaning there was
no cryptographic proof the email originated from the claimed domain.
Legitimate companies like PayPal and Netflix always sign their emails
with DKIM. Its absence alone is a strong indicator of forgery.

### Layer 2 — Keyword analysis

Both phishing emails scored heavily on keyword analysis. Common
patterns found:

- **Urgency creation:** "urgent", "act now", "expires soon",
  "account will be closed" — designed to make the victim act before
  thinking critically
- **Authority impersonation:** "dear customer", "security team",
  "billing department" — creates false sense of legitimacy
- **Fear tactics:** "suspended", "unusual activity", "payment failed",
  "unauthorized access" — triggers anxiety to bypass rational judgment

The clean university email contained none of these patterns, scoring 0.

### Layer 3 — URL pattern analysis

`phishing1.eml` contained a URL with two simultaneous red flags:
a suspicious `.xyz` TLD and a typosquatted domain (`paypa1` instead
of `paypal`). This combination is extremely common in phishing — the
attacker registers a cheap domain that visually resembles the real brand.

`phishing2.eml` used a `bit.ly` shortener — a technique that hides
the real destination entirely. The URL pattern checker correctly
flagged this as suspicious before even tracing the redirect.

### Layer 4 — Redirect tracing

This was the most revealing layer. The `bit.ly` link in `phishing2.eml`
redirected through two hops before landing on a completely different
domain from the one implied in the email. The final destination had
a suspicious TLD and contained a fake Netflix login form designed to
steal credentials.

This demonstrates why URL shorteners are dangerous in emails —
the displayed URL gives no indication of where the user will actually
land. Redirect tracing exposes this deception automatically.

### Layer 5 — VirusTotal

URLs flagged by layers 3 and 4 were submitted to VirusTotal for
reputation checking. The typosquatted PayPal domain in `phishing1.eml`
was flagged by multiple antivirus engines as a known phishing site,
confirming it had been used in previous campaigns. The bit.ly link
itself was not flagged (shorteners rarely are) but the final
destination URL was flagged as malicious.



## Key findings

### Finding 1 — No single layer is sufficient alone
The clean email had a slightly informal subject line that triggered
one keyword match ("update"), giving it a score of 1. Without the
other layers confirming the finding, this would have been a false
positive. All 5 layers working together produce reliable verdicts.

### Finding 2 — Header spoofing is trivially easy
Sending an email with a fake From display name requires no hacking
skill whatsoever — any email client allows this. DKIM and SPF exist
specifically to counter this, but many organisations do not enforce
them. This is why header analysis alone is insufficient.

### Finding 3 — Redirect chains are the most dangerous technique
A user looking at a `bit.ly` link in an email has no way to know
where it leads without tracing it. Even hovering over the link only
shows the shortener URL. Redirect tracing is therefore the most
valuable layer for detecting modern phishing attacks.

### Finding 4 — Typosquatting exploits inattentiveness
`paypa1.com` and `paypal.com` are visually almost identical,
especially on mobile screens. Users reading quickly — which is the
intended effect of the urgency language — are very likely to miss
the substituted character.



## Limitations

- The keyword list covers common English phishing patterns only.
  Phishing in Swahili or other languages would not be detected.
- Redirect tracing requires internet access and the target site to
  be online. Attackers can take sites down quickly after campaigns.
- VirusTotal only flags *known* malicious URLs. A brand new phishing
  site created hours ago may not yet appear in any database.
- The tool analyses plain text only. HTML emails with embedded links
  that display different text from the actual href are not yet handled.



## Improvements for future versions

- [ ] Parse HTML email bodies and extract href links separately
      from display text — catches the classic "click here" trick
- [ ] Add Swahili and other language keyword lists
- [ ] Check domain registration age via WHOIS — phishing domains
      are almost always newly registered (under 30 days old)
- [ ] Add screenshot capture of the final redirect destination
- [ ] Build a web interface using Flask so non-technical users
      can paste emails into a form



## Real-world context

According to industry reports, over 90% of successful cyber attacks
begin with a phishing email. The techniques detected by this tool —
header spoofing, urgency language, typosquatted domains, and redirect
chains — appear in virtually every phishing campaign. Understanding
how to identify them programmatically is a foundational skill for
any SOC analyst or security engineer.



## What I learned

Building this project gave me a deep understanding of how email
infrastructure works and how attackers exploit the trust model it was
built on. The most important insight was that phishing is fundamentally
a social engineering attack — the technical components (fake domains,
redirect chains) exist only to support the psychological manipulation
in the email body. Defending against phishing therefore requires both
technical controls and user education. No tool can fully replace a
trained eye.



## References

- RFC 7208 — Sender Policy Framework (SPF)
- RFC 6376 — DomainKeys Identified Mail (DKIM)
- NIST Phishing Guidance — SP 800-177
- VirusTotal API v3 Documentation
- PhishTank — community phishing URL database



