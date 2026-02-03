# hashguard-os

A Python-based password strength analyzer that checks your passwords against common patterns, leaked databases, and calculates entropy to give you a real security score.

## Features

- **Entropy Analysis** — Calculates password randomness in bits
- **Pattern Detection** — Catches weak patterns like `qwerty`, `123456`, repeated chars, dates
- **Dictionary Attack Check** — Compares against 10,000+ common passwords
- **Breach Detection** — Queries HaveIBeenPwned API to check if your password has been leaked
- **Smart Scoring** — Combines all factors into a clear 0-100 strength score
- **Actionable Feedback** — Tells you exactly what's wrong and how to fix it

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/hashguard-os.git
cd hashguard-os

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage
python main.py

# Check a specific password
python main.py --password "your_password_here"

# Verbose output with all details
python main.py --verbose
```

## How Scoring Works

| Score | Rating | Meaning |
|-------|--------|---------|
| 0-20 | 💀 Critical | Instantly crackable |
| 21-40 | 🔴 Weak | Minutes to crack |
| 41-60 | 🟠 Fair | Could be stronger |
| 61-80 | 🟢 Strong | Good for most uses |
| 81-100 | 🛡️ Excellent | Very secure |

## Privacy

Your passwords never leave your machine in plain text. The breach check uses k-anonymity — only the first 5 characters of the SHA-1 hash are sent to the API, so your actual password stays private.

## License

MIT

## Author

Built by [ospw](https://github.com/ospw)
