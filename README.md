# hashguard-os

Password strength analyzer that checks against common patterns, leaked databases, and calculates entropy. (Some shit in here is completely vibe coded since I got stuck so hard I couldnt think of alternatives, feel free to fork and improve it)

## Features

- Entropy calculation (password randomness in bits)
- Pattern detection (keyboard walks, repeated chars, dates, l33t speak)) [kinda broken]
- Dictionary check against 10k+ common passwords
- Breach detection via HaveIBeenPwned API [more work needed]
- 0-100 strength score with detailed feedback [more work needed]
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

Passwords never leave your machine in plain text. Breach checks use k-anonymity, meaning... only the first 5 characters of the SHA-1 hash are sent to the API.

## License

MIT (= Do whatever you want with it, just credit me when republishing or making additions)






