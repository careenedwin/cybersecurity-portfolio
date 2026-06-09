# Project 3 — Phishing Email Detector

A Python tool that analyses raw emails across 5 detection layers to
identify phishing attempts, fake links, and email spoofing techniques.



## What this project does

Phishing is the most common form of cyber attack. This tool simulates
what a security analyst does when examining a suspicious email —
checking headers for spoofing, scanning the body for manipulation
tactics, tracing links to their real destinations, and verifying URLs
against 90+ antivirus engines via the VirusTotal API.



## Detection layers

| Layer | Method | What it catches |
|-------|--------|-----------------|
| 1 | Header analysis | Reply-To spoofing, missing DKIM, SPF failures, free email providers impersonating companies |
| 2 | Keyword analysis | Urgency language, manipulation tactics, social engineering phrases |
| 3 | URL pattern analysis | Raw IPs, suspicious TLDs, typosquatting, URL shorteners, @ trick, excessive subdomains |
| 4 | Redirect tracing | Follows every redirect hop and exposes the real final destination |
| 5 | VirusTotal API | Checks flagged URLs against 90+ antivirus engines |



## Scoring system

Each detected indicator adds points to a risk score:

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0 | ✅ Clean | No indicators found |
| 1–3 | 🟡 Low risk | Minor indicators — treat with caution |
| 4–7 | 🟠 Medium | Multiple indicators — likely phishing |
| 8–12 | 🔴 High risk | Strong indicators — do not click links |
| 13+ | 🚨 Critical | Almost certainly phishing — delete immediately |



## How to run it

**Requirements:** Python 3, requests library

```bash
# Install dependency
pip3 install requests --break-system-packages

# Clone the repo
git clone https://github.com/YOUR_USERNAME/cybersecurity-portfolio.git
cd cybersecurity-portfolio/03-phishing-detector

# Run the detector
python3 detector.py
```

Paste a raw email when prompted. Type `END` on a new line when done.


## Getting a VirusTotal API key (free)

1. Go to [virustotal.com](https://virustotal.com) and create a free account
2. Click your profile icon → API Key
3. Copy the key and paste it into `detector.py` where it says `YOUR_VIRUSTOTAL_API_KEY_HERE`

The free tier allows 4 requests per minute and 500 per day — more than
enough for learning and testing.



## Files in this folder

| File | Description |
|------|-------------|
| `detector.py` | Main Python script — all 5 detection layers |
| `sample_emails/phishing1.eml` | Sample phishing email for testing |
| `sample_emails/phishing2.eml` | Sample phishing email with redirect |
| `sample_emails/clean1.eml` | Clean legitimate email for comparison |
| `report.md` | Full findings and what I learned |
| `screenshots/` | Terminal output screenshots |



## What I learned

- How email headers reveal spoofing attempts even when the display name looks legitimate
- How redirect chains hide malicious destinations behind innocent-looking URLs
- How typosquatting works and why it's so effective against non-technical users
- How to use the VirusTotal API to automate URL reputation checks
- How social engineering language patterns are consistent across phishing campaigns


## Tools and concepts used

- Python 3 (`re`, `email`, `urllib`, `requests`)
- Email header analysis (DKIM, SPF, Reply-To, Return-Path)
- VirusTotal Public API v3
- HTTP redirect tracing
- Regex pattern matching
- Social engineering awareness

