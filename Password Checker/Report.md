# Password Strength Checker — Project Report

**Date:**2026-06-08
**Tool:**Custom Python 3 script


## Objective

To build a password analysis tool that evaluates password strength using
multiple security layers, calculates entropy, and estimates crack time
based on a realistic GPU attack speed of 1 billion guesses per second.



## Test results

The following passwords were tested to validate the tool across all
strength levels:

| Password | Score | Rating | Entropy | Est. crack time |
|----------|-------|--------|---------|-----------------|
| `password` | 0/8 | 🔴 WEAK | 0 bits | Instant (blacklisted) |
| `123456` | 0/8 | 🔴 WEAK | 0 bits | Instant (blacklisted) |
| `hello123` | 2/8 | 🔴 WEAK | 37.6 bits | ~3 minutes |
| `Hello123` | 4/8 | 🟡 MEDIUM | 47.6 bits | ~4 days |
| `Hello@123` | 6/8 | 🟢 STRONG | 59.4 bits | ~1,300 years |
| `C@reen#Dodoma2024!` | 8/8 | 🟢 VERY STRONG | 118.0 bits | 4.2e+14 years |



## Key findings

### Finding 1 — Length is the biggest factor
The single most impactful factor in password strength is length.
`Hello@123` (9 chars) scores STRONG while `C@reen#Dodoma2024!`
(18 chars) scores VERY STRONG. Doubling the length raises crack time
from 1,300 years to hundreds of trillions of years — because strength
grows exponentially with each added character.

### Finding 2 — Common passwords bypass all other rules
`password` and `123456` score 0 regardless of how they might otherwise
score on the complexity checks. This reflects real-world attacks:
credential stuffing and dictionary attacks try common passwords first,
before attempting brute force. A password can appear to have decent
length and still be instantly cracked if it is in a known list.

### Finding 3 — Special characters add disproportionate value
Adding one special character expands the charset from 62 possible
characters (a-z, A-Z, 0-9) to 94. This alone increases the number
of possible combinations by 51% per character position — a significant
jump in crack time for minimal typing effort.

### Finding 4 — Medium passwords offer false security
`Hello123` scores MEDIUM with an estimated crack time of ~4 days.
This sounds safe but is not — a dedicated attacker with a GPU cluster
or a cloud-rented cracking rig could crack it in hours. Anything below
STRONG should be considered unacceptable for real accounts.



## Entropy analysis

Entropy measures unpredictability in bits. It is calculated as:
entropy = length × log₂(charset_size)
| Charset used | Size | Example |
|--------------|------|---------|
| Lowercase only | 26 | `hello` |
| Lower + Upper | 52 | `Hello` |
| Lower + Upper + Numbers | 62 | `Hello1` |
| All printable | 94 | `Hello1!` |

The NIST Digital Identity Guidelines (SP 800-63B) recommend a minimum
of 8 characters but strongly encourage longer passphrases. Entropy
above 60 bits is generally considered resistant to offline attacks.



## Real-world context

In 2024 the RockYou2024 dataset was leaked — containing nearly
10 billion real-world passwords from previous breaches. Any password
in that list can be cracked instantly via lookup, regardless of
complexity. This is why the common password blacklist in this tool
matters as much as the complexity scoring.

Attack types this tool helps defend against:

| Attack type | How this tool helps |
|-------------|---------------------|
| Dictionary attack | Common password blacklist |
| Brute force | Entropy score + crack time estimate |
| Credential stuffing | Blacklist + uniqueness encouragement |
| Rule-based attack | Complexity layer checks |

## Limitations of this tool

- The common passwords list contains only 30 entries. A production
  tool would use the full RockYou list (14 million+ entries).
- Crack time assumes a single GPU at 1B guesses/sec. A rented cloud
  cluster can do 100B+/sec, reducing all estimates by 100x.
- The tool does not check if the password contains the user's name,
  email, or username — a common weakness not caught by entropy alone.
- No check for keyboard patterns (qwerty, asdfgh) beyond the
  common password list.



## Improvements for future versions

- [ ] Load full RockYou wordlist from file for blacklist checking
- [ ] Detect keyboard walk patterns (qwerty, 12345, etc.)
- [ ] Add username/email field to check for personal info in password
- [ ] Build a simple web interface using Flask
- [ ] Add a password generator that creates strong passwords


## What I learned

Building this tool taught me that password security is more mathematical
than most people realise. Entropy gives a precise, quantifiable measure
of how unpredictable a password is — and the crack time estimates make
that abstract number concrete and meaningful. The most surprising finding
was how dramatically length affects security compared to complexity:
a 16-character lowercase-only password (`correcthorsebatterystaple`)
has higher entropy than an 8-character password with all character
types (`P@ssw0rd`). This aligns with the XKCD 936 principle —
long passphrases beat short complex passwords every time.



## References

- NIST SP 800-63B Digital Identity Guidelines
- XKCD #936 — Password Strength (https://xkcd.com/936/)
- RockYou2024 breach analysis
- Have I Been Pwned — https://haveibeenpwned.com

