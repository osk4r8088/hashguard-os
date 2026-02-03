# hashguard-os

Password strength analyzer that checks against common patterns, leaked databases, and calculates entropy.

## Features

- Entropy calculation (password randomness in bits)
- Pattern detection (keyboard walks, repeated chars, dates, l33t speak)
- Dictionary check against 10.000+ common passwords
- Breach detection via HaveIBeenPwned API
- 0-100 strength score with detailed feedback

## Installation
```bash
git clone https://github.com/osk4r8088/hashguard-os.git
cd hashguard-os
pip install -r requirements.txt
```

## Usage
```bash
# Interactive mode
python main.py

# Direct check
python main.py -p "your_password"

# Verbose output
python main.py -p "your_password" --verbose

# Skip breach check (offline)
python main.py -p "your_password" --offline
```

## Scoring

| Score | Rating | Meaning |
|-------|--------|---------|
| 0-20 | Critical | Instantly crackable |
| 21-40 | Weak | Crackable in minutes |
| 41-60 | Fair | Could be stronger |
| 61-80 | Strong | Good for most uses |
| 81-100 | Excellent | Very secure |

## Privacy

Passwords never leave your machine in plain text. Breach checks use k-anonymity — only the first 5 characters of the SHA-1 hash are sent to the API.

## License

MIT
