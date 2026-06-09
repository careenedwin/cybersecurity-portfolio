#!/usr/bin/env python3

import re
import math

# ── Common passwords list ──────────────────
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "iloveyou",
    "sunshine", "princess", "welcome", "shadow", "superman",
    "dragon", "master", "hello", "freedom", "whatever",
    "football", "baseball", "soccer", "hockey", "killer",
    "trustno1", "batman", "access", "login", "passw0rd"
]

# ── Scoring engine ─────────────────────────
def check_password(password):
    score = 0
    feedback = []
    passed = []

    # 1. Length check
    length = len(password)
    if length < 8:
        feedback.append("✗ Too short — use at least 8 characters")
    elif length < 12:
        score += 1
        passed.append("✓ Acceptable length (8+)")
    elif length < 16:
        score += 2
        passed.append("✓ Good length (12+)")
    else:
        score += 3
        passed.append("✓ Excellent length (16+)")

    # 2. Uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
        passed.append("✓ Contains uppercase letters")
    else:
        feedback.append("✗ Add uppercase letters (A-Z)")

    # 3. Lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
        passed.append("✓ Contains lowercase letters")
    else:
        feedback.append("✗ Add lowercase letters (a-z)")

    # 4. Numbers
    if re.search(r'[0-9]', password):
        score += 1
        passed.append("✓ Contains numbers")
    else:
        feedback.append("✗ Add numbers (0-9)")

    # 5. Special characters
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        score += 2
        passed.append("✓ Contains special characters")
    else:
        feedback.append("✗ Add special characters (!@#$%^&*...)")

    # 6. Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("✗ This is one of the most common passwords — change it immediately")

    # 7. Repeated characters penalty
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("✗ Avoid repeating characters (e.g. aaa, 111)")

    # ── Entropy calculation ──────────────────
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32

    entropy = length * math.log2(charset) if charset > 0 else 0

    # ── Crack time estimate ──────────────────
    guesses_per_second = 1_000_000_000  # 1 billion/sec (modern GPU)
    combinations = charset ** length if charset > 0 else 1
    seconds = combinations / guesses_per_second

    if seconds < 60:
        crack_time = f"{seconds:.1f} seconds"
    elif seconds < 3600:
        crack_time = f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        crack_time = f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        crack_time = f"{seconds/86400:.1f} days"
    elif seconds < 3153600000:
        crack_time = f"{seconds/31536000:.1f} years"
    else:
        crack_time = f"{seconds/31536000:.2e} years"

    # ── Final rating ─────────────────────────
    score = max(0, score)
    if score <= 2:
        rating = "WEAK"
        color = "🔴"
    elif score <= 4:
        rating = "MEDIUM"
        color = "🟡"
    elif score <= 6:
        rating = "STRONG"
        color = "🟢"
    else:
        rating = "VERY STRONG"
        color = "🟢"

    return {
        "rating": rating,
        "color": color,
        "score": score,
        "entropy": round(entropy, 2),
        "crack_time": crack_time,
        "passed": passed,
        "feedback": feedback
    }

# ── Display result ─────────────────────────
def display_result(password, result):
    print("\n" + "="*50)
    print(f"  Password : {'*' * len(password)}")
    print(f"  Rating   : {result['color']} {result['rating']}")
    print(f"  Score    : {result['score']}/8")
    print(f"  Entropy  : {result['entropy']} bits")
    print(f"  Est. crack time (GPU): {result['crack_time']}")
    print("="*50)

    if result['passed']:
        print("\n  What's good:")
        for p in result['passed']:
            print(f"    {p}")

    if result['feedback']:
        print("\n  What to fix:")
        for f in result['feedback']:
            print(f"    {f}")

    print()

# ── Main loop ─────────────────────────────
def main():
    print("\n" + "="*50)
    print("   PASSWORD STRENGTH CHECKER")
    print("="*50)
    print("\nType 'quit' to exit\n")

    while True:
        password = input("Enter a password to check: ")
        if password.lower() == 'quit':
            print("\nExiting. Stay secure!\n")
            break
        if not password:
            print("Please enter a password.\n")
            continue
        result = check_password(password)
        display_result(password, result)

if __name__ == "__main__":
    main()
