"""
patterns.py - Detect common weak patterns in passwords

This is where we catch all the lazy password habits:
- Keyboard walks (qwerty, asdf, 12345)
- Repeated characters (aaaaaa, 111111)
- Sequential patterns (abcdef, 987654)
- Common substitutions (p@ssw0rd, l33t)
- Date patterns (19990101, 2024)
- Common words with numbers (password123)

Even if a password has good entropy on paper, these patterns
make it way easier to crack because attackers check them first.
"""

import re
from typing import List, Dict


# Common keyboard walks people use
# super common ones, attackers always check these first
KEYBOARD_WALKS = [
    # Horizontal rows
    "qwerty", "qwertyuiop", "asdf", "asdfgh", "asdfghjkl", 
    "zxcv", "zxcvbn", "zxcvbnm",
    # Reversed
    "ytrewq", "fdsa", "vcxz",
    # Number row
    "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "09876", "098765", "0987654321",
    # Diagonal patterns
    "qazwsx", "1qaz2wsx", "zaq12wsx",
    # Common combos
    "qweasd", "qweasdzxc",
]

# Common l33t speak substitutions
LEET_MAP = {
    '@': 'a',
    '4': 'a',
    '8': 'b',
    '3': 'e',
    '6': 'g',
    '1': 'i',
    '!': 'i',
    '0': 'o',
    '5': 's',
    '$': 's',
    '7': 't',
    '+': 't',
    '2': 'z',
}


def detect_patterns(password: str) -> Dict:
    """
    Run all pattern checks on the password.
    
    Returns a dict with:
    - patterns_found: list of pattern names detected
    - details: specific info about each pattern
    - penalty: how much to reduce the score (0-50)
    """
    
    patterns_found = []
    details = []
    penalty = 0
    
    # Check for keyboard walks
    walk_result = check_keyboard_walks(password)
    if walk_result:
        patterns_found.append("keyboard_walk")
        details.append(f"Keyboard walk detected: '{walk_result}'")
        penalty += 20
    
    # Check for repeated characters
    repeat_result = check_repeated_chars(password)
    if repeat_result:
        patterns_found.append("repeated_chars")
        details.append(f"Repeated characters: '{repeat_result}'")
        penalty += 15
    
    # Check for sequential characters (abc, 123)
    seq_result = check_sequential(password)
    if seq_result:
        patterns_found.append("sequential")
        details.append(f"Sequential pattern: '{seq_result}'")
        penalty += 15
    
    # Check for date patterns
    date_result = check_date_patterns(password)
    if date_result:
        patterns_found.append("date_pattern")
        details.append(f"Date pattern detected: '{date_result}'")
        penalty += 10
    
    # Check for l33t speak (reveals)
    leet_result = check_leetspeak(password)
    if leet_result:
        patterns_found.append("leetspeak")
        details.append(f"L33t speak for: '{leet_result}'")
        penalty += 10
    
    # Check for common suffixes (123, !, 2024)
    suffix_result = check_common_suffixes(password)
    if suffix_result:
        patterns_found.append("common_suffix")
        details.append(f"Common suffix: '{suffix_result}'")
        penalty += 5
    
    # Cap penalty at 50 so patterns alone dont destroy the score
    penalty = min(penalty, 50)
    
    return {
        "patterns_found": patterns_found,
        "details": details,
        "penalty": penalty,
        "has_patterns": len(patterns_found) > 0
    }


def check_keyboard_walks(password: str) -> str | None:
    """
    Check if the password contains keyboard walk patterns.
    
    I'm checking both the password itself and a lowercase version
    because people might type QWERTY or Qwerty.
    """
    
    lower_pass = password.lower()
    
    for walk in KEYBOARD_WALKS:
        if walk in lower_pass:
            return walk
    
    return None


def check_repeated_chars(password: str) -> str | None:
    """
    Check for repeated characters like 'aaaaaa' or '111111'.
    
    Using regex to find any character repeated 3+ times in a row.
    3 is the threshold because 'aaa' is already a bad sign.
    """
    
    # This regex finds any character followed by itself 2+ more times
    # The (.)\1{2,} means: capture any char, then match it 2+ more times
    match = re.search(r'(.)\1{2,}', password)
    
    if match:
        return match.group(0)
    
    return None


def check_sequential(password: str) -> str | None:
    """
    Check for sequential characters like 'abcdef' or '987654'.
    
    Looking for runs of 4+ characters that go up or down in ASCII order.
    """
    
    if len(password) < 4:
        return None
    
    # Check for ascending sequences
    for i in range(len(password) - 3):
        chunk = password[i:i+4]
        if is_sequential(chunk, ascending=True):
            # Try to extend the match
            end = i + 4
            while end < len(password) and ord(password[end]) == ord(password[end-1]) + 1:
                end += 1
            return password[i:end]
    
    # Check for descending sequences
    for i in range(len(password) - 3):
        chunk = password[i:i+4]
        if is_sequential(chunk, ascending=False):
            end = i + 4
            while end < len(password) and ord(password[end]) == ord(password[end-1]) - 1:
                end += 1
            return password[i:end]
    
    return None


def is_sequential(s: str, ascending: bool = True) -> bool:
    """
    Helper to check if a string is sequential ASCII.
    
    ascending=True: checks for abc, 123
    ascending=False: checks for cba, 321
    """
    
    if len(s) < 2:
        return False
    
    step = 1 if ascending else -1
    
    for i in range(len(s) - 1):
        if ord(s[i+1]) - ord(s[i]) != step:
            return False
    
    return True


def check_date_patterns(password: str) -> str | None:
    """
    Check for date patterns in the password.
    
    People love using birthdays, anniversaries, years, etc.
    Common formats: YYYY, MMDD, YYYYMMDD, DD/MM/YYYY, etc.
    """
    
    # 4-digit years (1950-2030 range)
    year_match = re.search(r'(19[5-9]\d|20[0-3]\d)', password)
    if year_match:
        return year_match.group(0)
    
    # MMDDYYYY or DDMMYYYY
    full_date = re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}', password)
    if full_date:
        return full_date.group(0)
    
    # YYYYMMDD
    iso_date = re.search(r'(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', password)
    if iso_date:
        return iso_date.group(0)
    
    # MM/DD or DD/MM patterns
    short_date = re.search(r'(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])', password)
    if short_date:
        return short_date.group(0)
    
    return None


def check_leetspeak(password: str) -> str | None:
    """
    Convert l33t speak back to normal text.
    
    If the converted text is a common word, that's a red flag.
    For example: p@ssw0rd -> password
    """
    
    # Convert the password using leet map
    converted = ""
    for char in password.lower():
        converted += LEET_MAP.get(char, char)
    
    # If conversion changed something and result is mostly letters,
    # it might be a word in disguise
    if converted != password.lower():
        # Check if it's alphabetic (allowing for some numbers that didn't convert)
        alpha_only = ''.join(c for c in converted if c.isalpha())
        if len(alpha_only) >= 4 and len(alpha_only) >= len(password) * 0.6:
            return converted
    
    return None


def check_common_suffixes(password: str) -> str | None:
    """
    Check for common lazy suffixes people add.
    
    Things like: 123, 1234, !, !!, 2024, 2023, etc.
    Adding these barely improves security.
    """
    
    common_suffixes = [
        # Numbers
        '123', '1234', '12345', '123456',
        '1', '12', '69', '420', '007',
        # Years
        '2020', '2021', '2022', '2023', '2024', '2025',
        # Symbols
        '!', '!!', '!!!', '!@#', '!@#$',
        # Common endings
        '01', '1!', '123!',
    ]
    
    lower_pass = password.lower()
    
    for suffix in common_suffixes:
        if lower_pass.endswith(suffix):
            return suffix
    
    return None
