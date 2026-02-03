"""
breach_check.py - Check if password has been leaked in data breaches

This uses the HaveIBeenPwned (HIBP) API to check if your password
has appeared in known data breaches. Their database has billions
of leaked passwords from major breaches.

IMPORTANT: We use k-anonymity to protect your password!
- We hash your password with SHA-1
- We only send the first 5 characters of the hash to the API
- The API returns all hashes that start with those 5 chars
- We check locally if our full hash is in that list
- Result: HIBP never sees your actual password or full hash

If your password is in a breach, attackers have it in their wordlists
and will crack it instantly.
"""

import hashlib
import requests
from typing import Dict, Optional


# HaveIBeenPwned API endpoint for password checking
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

# Timeout for API requests (seconds)
REQUEST_TIMEOUT = 10


def check_breach(password: str) -> Dict:
    """
    Check if the password has been exposed in known data breaches.
    
    Uses the HIBP Pwned Passwords API with k-anonymity.
    Returns breach status and count of times it was seen.
    """
    
    result = {
        "is_breached": False,
        "breach_count": 0,
        "checked": False,  # False if API call failed
        "error": None,
        "penalty": 0,
        "details": []
    }
    
    try:
        # Step 1: Hash the password with SHA-1
        # HIBP uses SHA-1 because that's what most breached databases used
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Step 2: Split the hash into prefix (5 chars) and suffix (rest)
        # We only send the prefix to the API for privacy
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Step 3: Query the API with just the prefix
        response = requests.get(
            f"{HIBP_API_URL}{prefix}",
            timeout=REQUEST_TIMEOUT,
            headers={
                # Be a good citizen - identify ourselves
                "User-Agent": "hashguard-os-password-checker"
            }
        )
        
        # Check if request was successful
        if response.status_code != 200:
            result["error"] = f"API returned status {response.status_code}"
            return result
        
        result["checked"] = True
        
        # Step 4: Parse the response and look for our hash suffix
        # Response format is: HASH_SUFFIX:COUNT\r\n for each match
        # Example: 1E4C9B93F3F0682250B6CF8331B7EE68:3645804
        for line in response.text.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':')
                
                # Check if this suffix matches our password's hash
                if hash_suffix == suffix:
                    result["is_breached"] = True
                    result["breach_count"] = int(count)
                    
                    # Calculate penalty based on how many times it was seen
                    # More breaches = more likely attackers have it
                    if result["breach_count"] > 1000000:
                        result["penalty"] = 50  # Super common in breaches
                        result["details"].append(
                            f"Password found in {result['breach_count']:,} data breaches! "
                            "This is extremely compromised."
                        )
                    elif result["breach_count"] > 10000:
                        result["penalty"] = 40
                        result["details"].append(
                            f"Password found in {result['breach_count']:,} data breaches. "
                            "Attackers definitely have this in their lists."
                        )
                    elif result["breach_count"] > 100:
                        result["penalty"] = 30
                        result["details"].append(
                            f"Password found in {result['breach_count']:,} data breaches. "
                            "Consider changing it."
                        )
                    else:
                        result["penalty"] = 20
                        result["details"].append(
                            f"Password found in {result['breach_count']} data breaches. "
                            "It's been leaked before."
                        )
                    
                    break
        
        # If we got here without finding a match, the password is clean
        if not result["is_breached"]:
            result["details"].append("Password not found in known data breaches ✓")
        
    except requests.exceptions.Timeout:
        result["error"] = "API request timed out"
        result["details"].append("Could not check breaches - request timed out")
        
    except requests.exceptions.ConnectionError:
        result["error"] = "Could not connect to HIBP API"
        result["details"].append("Could not check breaches - no internet connection?")
        
    except Exception as e:
        result["error"] = str(e)
        result["details"].append(f"Could not check breaches - {e}")
    
    return result


def get_breach_severity(count: int) -> str:
    """
    Get a human-readable severity rating based on breach count.
    """
    
    if count == 0:
        return "clean"
    elif count < 100:
        return "low"
    elif count < 10000:
        return "medium"
    elif count < 1000000:
        return "high"
    else:
        return "critical"


def explain_k_anonymity() -> str:
    """
    Returns an explanation of how we protect privacy during breach checks.
    
    Useful for showing users why it's safe to check their passwords.
    """
    
    return """
    How we protect your password during breach checking:
    
    1. Your password is hashed with SHA-1 locally on your machine
    2. Only the first 5 characters of the hash are sent to the API
    3. The API returns all breached passwords that start with those 5 chars
    4. We check locally if your full hash matches any in the list
    
    Result: The HaveIBeenPwned service never sees your actual password
    or even your complete hash. Your password stays private.
    
    Example:
    - Your password: "secret123"
    - SHA-1 hash: "F7C3BC1D808E04732ADF679965CCC34CA7AE3441"
    - Sent to API: "F7C3B" (just the first 5 chars)
    - API returns: ~500 hashes starting with F7C3B
    - We check locally: Is our full hash in that list?
    """
