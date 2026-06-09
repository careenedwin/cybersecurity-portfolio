# Project 2 — Password Strength Checker

A Python tool that analyses password strength across multiple security
layers and estimates how long it would take a modern GPU to crack it.


## What this project does

Most people use weak passwords without knowing why they are weak. This tool
checks a password against 6 security layers and gives specific, actionable
feedback — not just a "weak/strong" label.


## How it works

| Layer | Check | Points |
|-------|-------|--------|
| 1 | Length (8 / 12 / 16+ characters) | 1–3 pts |
| 2 | Uppercase letters (A–Z) | 1 pt |
| 3 | Lowercase letters (a–z) | 1 pt |
| 4 | Numbers (0–9) | 1 pt |
| 5 | Special characters (!@#$%...) | 2 pts |
| 6 | Common passwords blacklist | disqualifies |

**Entropy** is also calculated using the formula:
entropy = password_length × log₂(charset_size)
Higher entropy = harder to crack. 60+ bits is considered strong.


## Crack time estimation

The tool estimates crack time assuming a modern GPU running
**1 billion guesses per second** — a realistic offline attack scenario.

| Strength | Entropy | Est. crack time |
|----------|---------|-----------------|
| 🔴 Weak | < 30 bits | Seconds to minutes |
| 🟡 Medium | 30–50 bits | Hours to days |
| 🟢 Strong | 50–70 bits | Years |
| 🟢 Very Strong | 70+ bits | Centuries+ |


## Sample output
Password : **********
Rating   : 🟢 VERY STRONG
Score    : 8/8
Entropy  : 87.6 bits
Est. crack time (GPU): 4.23e+14 years
What's good:
-✓Excellent length (16+)
-✓ Contains uppercase letters
-✓ Contains lowercase letters
-✓ Contains numbers
-✓ Contains special characters
What to fix:
(none)


## How to run it

**Requirements:** Python 3 (no extra libraries needed — uses only built-in modules)

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/cybersecurity-portfolio.git
cd cybersecurity-portfolio/02-password-checker

# Run the script
python3 password_checker.py
```

Then type any password and press Enter. Type `quit` to exit.


## Files in this folder

| File | Description |
|------|-------------|
| `password_checker.py` | Main Python script |
| `sample_passwords.txt` | Test inputs used during development |
| `report.md` | Findings, what I learned, security insights |
| `screenshots/` | Terminal output screenshots |



## What I learned

- How password entropy is calculated mathematically
- Why length matters more than complexity alone
- How fast modern GPUs can crack passwords (1 billion/sec)
- Why common passwords are dangerous even if they look complex
- How to use Python `re` (regex) and `math` modules for security logic


## Tools & concepts used

- Python 3
- Regular expressions (`re` module)
- Entropy calculation (`math.log2`)
- Password security principles (NIST guidelines)


