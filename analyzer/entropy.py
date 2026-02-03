"""
entropy.py - Password entropy calculator

Entropy measures how random/unpredictable a password is.
Higher entropy = harder to crack through brute force.

The formula is: entropy = length * log2(pool_size)
- length: how many characters in the password
- pool_size: how many possible characters could be in each position

For example:
- Only lowercase (26 chars): "password" = 8 * log2(26) = ~37 bits
- Mixed case + numbers (62 chars): "Password1" = 9 * log2(62) = ~53 bits
- Full ASCII (95 chars): "P@ssw0rd!" = 9 * log2(95) = ~59 bits

Generally:
- < 28 bits: very weak (instantly crackable)
- 28-35 bits: weak (crackable in minutes)  
- 36-59 bits: reasonable (hours to days)
- 60-127 bits: strong (years to crack)
- 128+ bits: overkill (heat death of universe)
"""

import math
import string


def calculate_entropy(password: str) -> dict:
    """
    Calculate the entropy of a password in bits.
    
    I'm checking which character sets are used (lowercase, uppercase, digits, symbols)
    and then calculating how many bits of entropy that gives us.
    
    Returns a dict with the entropy value and breakdown of what was detected.
    """
    
    if not password:
        return {
            "entropy_bits": 0,
            "pool_size": 0,
            "length": 0,
            "character_sets": [],
            "rating": "none"
        }
    
    # I'll track which character sets are present in the password
    # Each set adds to the "pool" of possible characters an attacker would need to guess
    pool_size = 0
    character_sets = []
    
    # Check for lowercase letters (a-z = 26 characters)
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
        character_sets.append("lowercase")
    
    # Check for uppercase letters (A-Z = 26 characters)
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
        character_sets.append("uppercase")
    
    # Check for digits (0-9 = 10 characters)
    if any(c in string.digits for c in password):
        pool_size += 10
        character_sets.append("digits")
    
    # Check for common symbols/punctuation (32 characters on standard keyboard)
    # This includes stuff like !@#$%^&*()_+-=[]{}|;':",.<>?/`~
    symbols = string.punctuation
    if any(c in symbols for c in password):
        pool_size += 32
        character_sets.append("symbols")
    
    # Check for spaces (some passwords use spaces)
    if " " in password:
        pool_size += 1
        character_sets.append("spaces")
    
    # Check for extended ASCII or unicode (anything not in the above)
    # This catches stuff like émojis, accented characters, etc.
    standard_chars = string.ascii_letters + string.digits + string.punctuation + " "
    if any(c not in standard_chars for c in password):
        pool_size += 100  # rough estimate for extended characters
        character_sets.append("extended")
    
    # Now calculate entropy using the formula: length * log2(pool_size)
    # log2 tells us how many bits we need to represent the pool
    length = len(password)
    
    if pool_size > 0:
        entropy_bits = length * math.log2(pool_size)
    else:
        entropy_bits = 0
    
    # Give a human-readable rating based on entropy
    # These thresholds are based on how long it would take to brute force
    rating = get_entropy_rating(entropy_bits)
    
    return {
        "entropy_bits": round(entropy_bits, 2),
        "pool_size": pool_size,
        "length": length,
        "character_sets": character_sets,
        "rating": rating
    }


def get_entropy_rating(entropy_bits: float) -> str:
    """
    Convert entropy bits into a human-readable rating.
    
    I based these thresholds on real-world cracking speeds.
    A modern GPU can do ~10 billion hashes/second for MD5.
    """
    
    if entropy_bits < 28:
        return "critical"  # Crackable in seconds
    elif entropy_bits < 36:
        return "weak"      # Crackable in minutes to hours
    elif entropy_bits < 60:
        return "fair"      # Crackable in days to months
    elif entropy_bits < 80:
        return "strong"    # Would take years
    else:
        return "excellent" # Practically uncrackable


def get_crack_time_estimate(entropy_bits: float) -> str:
    """
    Estimate how long it would take to crack this password.
    
    Assuming 10 billion guesses per second (modern GPU cluster).
    This is a rough estimate - actual time depends on the hashing algorithm,
    whether the attacker uses wordlists, rules, etc.
    """
    
    if entropy_bits <= 0:
        return "instant"
    
    # 2^entropy_bits = total possible combinations
    # Divide by guesses per second to get time in seconds
    # On average, you find it halfway through (divide by 2)
    guesses_per_second = 10_000_000_000  # 10 billion
    total_combinations = 2 ** entropy_bits
    seconds_to_crack = (total_combinations / 2) / guesses_per_second
    
    # Convert seconds to human readable time
    if seconds_to_crack < 1:
        return "instant"
    elif seconds_to_crack < 60:
        return f"{int(seconds_to_crack)} seconds"
    elif seconds_to_crack < 3600:
        return f"{int(seconds_to_crack / 60)} minutes"
    elif seconds_to_crack < 86400:
        return f"{int(seconds_to_crack / 3600)} hours"
    elif seconds_to_crack < 31536000:
        return f"{int(seconds_to_crack / 86400)} days"
    elif seconds_to_crack < 31536000 * 1000:
        return f"{int(seconds_to_crack / 31536000)} years"
    elif seconds_to_crack < 31536000 * 1000000:
        return f"{int(seconds_to_crack / 31536000 / 1000)} thousand years"
    elif seconds_to_crack < 31536000 * 1000000000:
        return f"{int(seconds_to_crack / 31536000 / 1000000)} million years"
    else:
        return "heat death of universe"
