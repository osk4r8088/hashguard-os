"""
dictionary.py - Check password against common password lists

This checks if your password (or something similar to it) appears
in lists of commonly used passwords. Attackers always try these first
before brute forcing, so being on a common list = instant crack.

We check:
1. Exact match against common passwords
2. Case-insensitive match
3. Password with common suffixes stripped
4. L33t speak decoded version
"""

import os
from typing import Dict, List


# Top 100 most common passwords hardcoded as a fallback
# These are from various breach analyses
# Having these hardcoded means we can always check the worst offenders
TOP_COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "welcome", "shadow", "ashley", "football",
    "jesus", "michael", "ninja", "mustang", "password1",
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password1",
    "password123", "batman", "login", "admin", "princess",
    "starwars", "hello", "charlie", "donald", "qwerty123",
    "password1", "1q2w3e4r", "zxcvbnm", "121212", "flower",
    "hottie", "loveme", "zaq1zaq1", "hunter", "test",
    "0987654321", "1qaz2wsx", "gandalf", "hello123", "cheese",
    "tigger", "internet", "pepper", "killer", "winter",
    "soccer", "access", "hockey", "thunder", "fuck",
    "pussy", "asshole", "buster", "joshua", "thomas",
    "summer", "whatever", "orange", "hunter2", "robert",
    "nicole", "sexy", "secret", "merlin", "cookie",
]


def load_password_list(filepath: str = None) -> set:
    """
    Load the common passwords list from file.
    
    Falls back to hardcoded list if file doesn't exist.
    Using a set for O(1) lookup speed.
    """
    
    passwords = set(TOP_COMMON_PASSWORDS)
    
    # Try to load extended list from file
    if filepath is None:
        # Default path relative to this file's location
        current_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(current_dir, "..", "data", "common_passwords.txt")
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Strip whitespace and skip empty lines/comments
                pwd = line.strip()
                if pwd and not pwd.startswith('#'):
                    passwords.add(pwd.lower())
    except FileNotFoundError:
        # That's fine, we'll use the hardcoded list
        pass
    except Exception as e:
        # Log but don't crash
        print(f"Warning: Could not load password list: {e}")
    
    return passwords


# Load passwords once when module is imported
# This way we don't re-read the file on every check
COMMON_PASSWORDS = load_password_list()


def check_dictionary(password: str) -> Dict:
    """
    Check if the password appears in common password lists.
    
    Returns info about matches found and severity.
    """
    
    results = {
        "is_common": False,
        "match_type": None,
        "matched_password": None,
        "penalty": 0,
        "details": []
    }
    
    # Check 1: Exact match (case insensitive)
    if password.lower() in COMMON_PASSWORDS:
        results["is_common"] = True
        results["match_type"] = "exact"
        results["matched_password"] = password.lower()
        results["penalty"] = 50  # Massive penalty for exact match
        results["details"].append(f"'{password}' is in the top common passwords list")
        return results
    
    # Check 2: Strip common suffixes and check again
    stripped = strip_common_suffixes(password.lower())
    if stripped != password.lower() and stripped in COMMON_PASSWORDS:
        results["is_common"] = True
        results["match_type"] = "stripped"
        results["matched_password"] = stripped
        results["penalty"] = 40  # Still bad
        results["details"].append(f"Base word '{stripped}' is common (you just added numbers/symbols)")
        return results
    
    # Check 3: Check if it's a simple variation of a common password
    # Like Password, PASSWORD, PaSsWoRd
    variation = check_case_variations(password)
    if variation:
        results["is_common"] = True
        results["match_type"] = "variation"
        results["matched_password"] = variation
        results["penalty"] = 45
        results["details"].append(f"'{variation}' is common (case changes don't help)")
        return results
    
    # Check 4: Decode l33t speak and check
    decoded = decode_leetspeak(password.lower())
    if decoded != password.lower() and decoded in COMMON_PASSWORDS:
        results["is_common"] = True
        results["match_type"] = "leetspeak"
        results["matched_password"] = decoded
        results["penalty"] = 40
        results["details"].append(f"Decodes to common password '{decoded}' (l33t speak doesn't help)")
        return results
    
    return results


def strip_common_suffixes(password: str) -> str:
    """
    Remove common lazy suffixes from passwords.
    
    People do password123, password!, password2024 all the time.
    """
    
    suffixes = [
        '123456', '12345', '1234', '123', '12', '1',
        '2024', '2023', '2022', '2021', '2020',
        '!!!', '!!', '!', '@', '#', '!@#', '!@#$',
        '69', '420', '007', '01', '00',
    ]
    
    result = password
    
    # Keep stripping until nothing changes
    # This handles cases like password123!
    changed = True
    while changed:
        changed = False
        for suffix in suffixes:
            if result.endswith(suffix) and len(result) > len(suffix):
                result = result[:-len(suffix)]
                changed = True
                break
    
    return result


def check_case_variations(password: str) -> str | None:
    """
    Check if any case variation of the password is common.
    
    Covers: lowercase, UPPERCASE, Capitalized, aLtErNaTiNg
    """
    
    variations = [
        password.lower(),
        password.upper(),
        password.capitalize(),
        password.swapcase(),
    ]
    
    for var in variations:
        if var.lower() in COMMON_PASSWORDS:
            return var.lower()
    
    return None


def decode_leetspeak(password: str) -> str:
    """
    Convert l33t speak back to regular text.
    
    Same mapping as in patterns.py but used here for dictionary lookup.
    """
    
    leet_map = {
        '@': 'a', '4': 'a',
        '8': 'b',
        '3': 'e',
        '6': 'g',
        '1': 'i', '!': 'i',
        '0': 'o',
        '5': 's', '$': 's',
        '7': 't', '+': 't',
        '2': 'z',
    }
    
    result = ""
    for char in password:
        result += leet_map.get(char, char)
    
    return result


def get_similar_common_passwords(password: str, max_results: int = 5) -> List[str]:
    """
    Find common passwords that are similar to the input.
    
    This is useful for feedback - showing the user what attackers
    would try that's close to their password.
    
    Using simple edit distance / substring matching.
    """
    
    similar = []
    lower_pass = password.lower()
    
    for common in list(COMMON_PASSWORDS)[:1000]:  # Check first 1000 only for speed
        # Check if common password is a substring
        if common in lower_pass or lower_pass in common:
            similar.append(common)
        # Check if they share a long prefix
        elif len(common) >= 4 and common[:4] == lower_pass[:4]:
            similar.append(common)
        
        if len(similar) >= max_results:
            break
    
    return similar
