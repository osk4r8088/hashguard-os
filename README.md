# hashguard-os

hashguard-os/
├── analyzer/
│   ├── entropy.py      # Calculates password randomness in bits
│   ├── patterns.py     # Detects keyboard walks, repeated chars, dates, l33t
│   ├── dictionary.py   # Checks against common passwords list
│   ├── breach_check.py # Queries HaveIBeenPwned API (k-anonymity)
│   └── scorer.py       # Combines everything into final score
├── data/
│   └── common_passwords.txt
├── main.py             # CLI with rich terminal output
├── requirements.txt
└── README.md
