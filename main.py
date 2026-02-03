#!/usr/bin/env python3
"""
hashguard-os - Password Strength Analyzer
Single-file version with all modules included

Usage:
    python main.py                     # Interactive mode
    python main.py -p "mypassword"     # Direct password input
    python main.py --verbose           # Show detailed breakdown
    python main.py --offline           # Skip breach check
"""

import math
import string
import hashlib
import re
import os
import requests
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
from getpass import getpass
from typing import Optional, Dict, List


# ============================================================================
# ENTROPY MODULE
# Measures how random/unpredictable a password is
# Higher entropy = harder to crack through brute force
# ============================================================================

def calculate_entropy(password: str) -> dict:
    """
    Calculate the entropy of a password in bits.
    
    I'm checking which character sets are used (lowercase, uppercase, digits, symbols)
    and then calculating how many bits of entropy that gives us.
    """
    
    if not password:
        return {
            "entropy_bits": 0,
            "pool_size": 0,
            "length": 0,
            "character_sets": [],
            "rating": "none"
        }
    
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
    
    # Check for symbols
    symbols = string.punctuation
    if any(c in symbols for c in password):
        pool_size += 32
        character_sets.append("symbols")
    
    # Check for spaces
    if " " in password:
        pool_size += 1
        character_sets.append("spaces")
    
    # Check for extended ASCII or unicode
    standard_chars = string.ascii_letters + string.digits + string.punctuation + " "
    if any(c not in standard_chars for c in password):
        pool_size += 100
        character_sets.append("extended")
    
    # Calculate entropy: length * log2(pool_size)
    length = len(password)
    
    if pool_size > 0:
        entropy_bits = length * math.log2(pool_size)
    else:
        entropy_bits = 0
    
    rating = get_entropy_rating(entropy_bits)
    
    return {
        "entropy_bits": round(entropy_bits, 2),
        "pool_size": pool_size,
        "length": length,
        "character_sets": character_sets,
        "rating": rating
    }


def get_entropy_rating(entropy_bits: float) -> str:
    """Convert entropy bits into a human-readable rating."""
    
    if entropy_bits < 28:
        return "critical"
    elif entropy_bits < 36:
        return "weak"
    elif entropy_bits < 60:
        return "fair"
    elif entropy_bits < 80:
        return "strong"
    else:
        return "excellent"


def get_crack_time_estimate(entropy_bits: float) -> str:
    """Estimate how long it would take to crack this password."""
    
    if entropy_bits <= 0:
        return "instant"
    
    guesses_per_second = 10_000_000_000  # 10 billion
    total_combinations = 2 ** entropy_bits
    seconds_to_crack = (total_combinations / 2) / guesses_per_second
    
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


# ============================================================================
# PATTERNS MODULE
# Detects common weak patterns in passwords
# ============================================================================

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdf", "asdfgh", "asdfghjkl",
    "zxcv", "zxcvbn", "zxcvbnm",
    "ytrewq", "fdsa", "vcxz",
    "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "09876", "098765", "0987654321",
    "qazwsx", "1qaz2wsx", "zaq12wsx",
    "qweasd", "qweasdzxc",
]

LEET_MAP = {
    '@': 'a', '4': 'a', '8': 'b', '3': 'e', '6': 'g',
    '1': 'i', '!': 'i', '0': 'o', '5': 's', '$': 's',
    '7': 't', '+': 't', '2': 'z',
}


def detect_patterns(password: str) -> Dict:
    """Run all pattern checks on the password."""
    
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
    
    # Check for sequential characters
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
    
    # Check for l33t speak
    leet_result = check_leetspeak(password)
    if leet_result:
        patterns_found.append("leetspeak")
        details.append(f"L33t speak for: '{leet_result}'")
        penalty += 10
    
    # Check for common suffixes
    suffix_result = check_common_suffixes(password)
    if suffix_result:
        patterns_found.append("common_suffix")
        details.append(f"Common suffix: '{suffix_result}'")
        penalty += 5
    
    penalty = min(penalty, 50)
    
    return {
        "patterns_found": patterns_found,
        "details": details,
        "penalty": penalty,
        "has_patterns": len(patterns_found) > 0
    }


def check_keyboard_walks(password: str) -> str | None:
    lower_pass = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in lower_pass:
            return walk
    return None


def check_repeated_chars(password: str) -> str | None:
    match = re.search(r'(.)\1{2,}', password)
    if match:
        return match.group(0)
    return None


def check_sequential(password: str) -> str | None:
    if len(password) < 4:
        return None
    
    for i in range(len(password) - 3):
        chunk = password[i:i+4]
        if is_sequential(chunk, ascending=True):
            end = i + 4
            while end < len(password) and ord(password[end]) == ord(password[end-1]) + 1:
                end += 1
            return password[i:end]
    
    for i in range(len(password) - 3):
        chunk = password[i:i+4]
        if is_sequential(chunk, ascending=False):
            end = i + 4
            while end < len(password) and ord(password[end]) == ord(password[end-1]) - 1:
                end += 1
            return password[i:end]
    
    return None


def is_sequential(s: str, ascending: bool = True) -> bool:
    if len(s) < 2:
        return False
    step = 1 if ascending else -1
    for i in range(len(s) - 1):
        if ord(s[i+1]) - ord(s[i]) != step:
            return False
    return True


def check_date_patterns(password: str) -> str | None:
    year_match = re.search(r'(19[5-9]\d|20[0-3]\d)', password)
    if year_match:
        return year_match.group(0)
    
    full_date = re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}', password)
    if full_date:
        return full_date.group(0)
    
    iso_date = re.search(r'(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', password)
    if iso_date:
        return iso_date.group(0)
    
    return None


def check_leetspeak(password: str) -> str | None:
    converted = ""
    for char in password.lower():
        converted += LEET_MAP.get(char, char)
    
    if converted != password.lower():
        alpha_only = ''.join(c for c in converted if c.isalpha())
        if len(alpha_only) >= 4 and len(alpha_only) >= len(password) * 0.6:
            return converted
    return None


def check_common_suffixes(password: str) -> str | None:
    common_suffixes = [
        '123', '1234', '12345', '123456',
        '1', '12', '69', '420', '007',
        '2020', '2021', '2022', '2023', '2024', '2025',
        '!', '!!', '!!!', '!@#', '!@#$',
        '01', '1!', '123!',
    ]
    
    lower_pass = password.lower()
    for suffix in common_suffixes:
        if lower_pass.endswith(suffix):
            return suffix
    return None


# ============================================================================
# DICTIONARY MODULE
# Check password against common password lists
# ============================================================================

TOP_COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "welcome", "shadow", "ashley", "football",
    "jesus", "michael", "ninja", "mustang", "password1",
    "abc123", "monkey", "letmein", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey",
    "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123",
    "batman", "login", "admin", "princess", "starwars",
    "hello", "charlie", "donald", "qwerty123", "1q2w3e4r",
    "zxcvbnm", "121212", "flower", "hottie", "loveme",
    "zaq1zaq1", "hunter", "test", "cheese", "tigger",
    "internet", "pepper", "killer", "winter", "soccer",
    "access", "hockey", "thunder", "whatever", "orange",
    "hunter2", "robert", "nicole", "sexy", "secret",
    "merlin", "cookie", "fuckyou", "jordan", "liverpool",
]

COMMON_PASSWORDS = set(TOP_COMMON_PASSWORDS)


def check_dictionary(password: str) -> Dict:
    """Check if the password appears in common password lists."""
    
    results = {
        "is_common": False,
        "match_type": None,
        "matched_password": None,
        "penalty": 0,
        "details": []
    }
    
    # Check exact match
    if password.lower() in COMMON_PASSWORDS:
        results["is_common"] = True
        results["match_type"] = "exact"
        results["matched_password"] = password.lower()
        results["penalty"] = 50
        results["details"].append(f"'{password}' is in the top common passwords list")
        return results
    
    # Check stripped version
    stripped = strip_common_suffixes(password.lower())
    if stripped != password.lower() and stripped in COMMON_PASSWORDS:
        results["is_common"] = True
        results["match_type"] = "stripped"
        results["matched_password"] = stripped
        results["penalty"] = 40
        results["details"].append(f"Base word '{stripped}' is common")
        return results
    
    # Check l33t decoded
    decoded = decode_leetspeak_dict(password.lower())
    if decoded != password.lower() and decoded in COMMON_PASSWORDS:
        results["is_common"] = True
        results["match_type"] = "leetspeak"
        results["matched_password"] = decoded
        results["penalty"] = 40
        results["details"].append(f"Decodes to common password '{decoded}'")
        return results
    
    return results


def strip_common_suffixes(password: str) -> str:
    suffixes = [
        '123456', '12345', '1234', '123', '12', '1',
        '2024', '2023', '2022', '2021', '2020',
        '!!!', '!!', '!', '@', '#', '!@#', '!@#$',
        '69', '420', '007', '01', '00',
    ]
    
    result = password
    changed = True
    while changed:
        changed = False
        for suffix in suffixes:
            if result.endswith(suffix) and len(result) > len(suffix):
                result = result[:-len(suffix)]
                changed = True
                break
    return result


def decode_leetspeak_dict(password: str) -> str:
    result = ""
    for char in password:
        result += LEET_MAP.get(char, char)
    return result


# ============================================================================
# BREACH CHECK MODULE
# Uses HaveIBeenPwned API with k-anonymity
# ============================================================================

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
REQUEST_TIMEOUT = 10


def check_breach(password: str) -> Dict:
    """Check if the password has been exposed in known data breaches."""
    
    result = {
        "is_breached": False,
        "breach_count": 0,
        "checked": False,
        "error": None,
        "penalty": 0,
        "details": []
    }
    
    try:
        # Hash password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Split into prefix and suffix for k-anonymity
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Query API
        response = requests.get(
            f"{HIBP_API_URL}{prefix}",
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "hashguard-os-password-checker"}
        )
        
        if response.status_code != 200:
            result["error"] = f"API returned status {response.status_code}"
            return result
        
        result["checked"] = True
        
        # Look for our hash suffix in the response
        for line in response.text.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    result["is_breached"] = True
                    result["breach_count"] = int(count)
                    
                    # Format number with dots instead of commas (e.g., 2.254.650)
                    breach_count_str = f"{result['breach_count']:,}".replace(",", ".")
                    
                    if result["breach_count"] > 1000000:
                        result["penalty"] = 50
                        result["details"].append(
                            f"Password found in {breach_count_str} data breaches!"
                        )
                    elif result["breach_count"] > 10000:
                        result["penalty"] = 40
                        result["details"].append(
                            f"Password found in {breach_count_str} data breaches."
                        )
                    elif result["breach_count"] > 100:
                        result["penalty"] = 30
                        result["details"].append(
                            f"Password found in {breach_count_str} data breaches."
                        )
                    else:
                        result["penalty"] = 20
                        result["details"].append(
                            f"Password found in {result['breach_count']} data breaches."
                        )
                    break
        
        if not result["is_breached"]:
            result["details"].append("Password not found in known data breaches.")
        
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


# ============================================================================
# SCORER MODULE
# Combines all analysis into a final score
# ============================================================================

def analyze_password(password: str, skip_breach_check: bool = False) -> Dict:
    """Run full analysis on a password."""
    
    entropy_result = calculate_entropy(password)
    pattern_result = detect_patterns(password)
    dictionary_result = check_dictionary(password)
    
    if skip_breach_check:
        breach_result = {
            "is_breached": False,
            "breach_count": 0,
            "checked": False,
            "error": "Skipped",
            "penalty": 0,
            "details": ["Breach check skipped (offline mode)"]
        }
    else:
        breach_result = check_breach(password)
    
    score_result = calculate_score(
        entropy_result,
        pattern_result,
        dictionary_result,
        breach_result
    )
    
    feedback = generate_feedback(
        password,
        entropy_result,
        pattern_result,
        dictionary_result,
        breach_result,
        score_result
    )
    
    return {
        "password_length": len(password),
        "score": score_result["final_score"],
        "rating": score_result["rating"],
        "crack_time": get_crack_time_estimate(entropy_result["entropy_bits"]),
        "entropy": entropy_result,
        "patterns": pattern_result,
        "dictionary": dictionary_result,
        "breach": breach_result,
        "feedback": feedback,
        "score_breakdown": score_result["breakdown"],
    }


def calculate_score(entropy: Dict, patterns: Dict, dictionary: Dict, breach: Dict) -> Dict:
    """Calculate the final 0-100 score."""
    
    breakdown = []
    
    # Base score from entropy
    entropy_bits = entropy["entropy_bits"]
    base_score = min(100, (entropy_bits / 80) * 100)
    breakdown.append(f"Base score from entropy: {base_score:.0f}/100 ({entropy_bits:.1f} bits)")
    
    # Apply penalties
    total_penalty = 0
    
    if patterns["penalty"] > 0:
        total_penalty += patterns["penalty"]
        breakdown.append(f"Pattern penalty: -{patterns['penalty']}")
    
    if dictionary["penalty"] > 0:
        total_penalty += dictionary["penalty"]
        breakdown.append(f"Dictionary penalty: -{dictionary['penalty']}")
    
    if breach["penalty"] > 0:
        total_penalty += breach["penalty"]
        breakdown.append(f"Breach penalty: -{breach['penalty']}")
    
    final_score = max(0, base_score - total_penalty)
    
    # Hard caps for critical issues
    if breach["is_breached"] and breach["breach_count"] > 1000:
        final_score = min(final_score, 15)
        breakdown.append("Hard cap: heavily breached password")
    
    if dictionary["is_common"] and dictionary["match_type"] == "exact":
        final_score = min(final_score, 10)
        breakdown.append("Hard cap: exact match in common passwords")
    
    if entropy.get("length", 0) < 6:
        final_score = min(final_score, 20)
        breakdown.append("Hard cap: password too short")
    
    final_score = round(final_score)
    
    return {
        "final_score": final_score,
        "rating": get_rating(final_score),
        "base_score": round(base_score),
        "total_penalty": total_penalty,
        "breakdown": breakdown
    }


def get_rating(score: int) -> str:
    if score <= 20:
        return "critical"
    elif score <= 40:
        return "weak"
    elif score <= 60:
        return "fair"
    elif score <= 80:
        return "strong"
    else:
        return "excellent"


def get_rating_symbol(rating: str) -> str:
    symbols = {
        "critical": "[X]",
        "weak": "[-]",
        "fair": "[~]",
        "strong": "[+]",
        "excellent": "[!]"
    }
    return symbols.get(rating, "[?]")


def generate_feedback(password: str, entropy: Dict, patterns: Dict, 
                      dictionary: Dict, breach: Dict, score: Dict) -> List[str]:
    """Generate specific, actionable feedback."""
    
    feedback = []
    
    if breach["is_breached"]:
        breach_count_str = f"{breach['breach_count']:,}".replace(",", ".")
        feedback.append(
            f"[!] CRITICAL: This password was found in {breach_count_str} data breaches!"
        )
    
    if dictionary["is_common"]:
        feedback.append("[!] This is a commonly used password.")
    
    length = len(password)
    if length < 8:
        feedback.append(f"[LENGTH] Too short ({length} chars). Use at least 12 characters.")
    elif length < 12:
        feedback.append(f"[LENGTH] Length is okay ({length} chars) but 12+ is better.")
    elif length >= 16:
        feedback.append(f"[LENGTH] Good length ({length} chars).")
    
    char_sets = entropy.get("character_sets", [])
    missing = []
    if "lowercase" not in char_sets:
        missing.append("lowercase letters")
    if "uppercase" not in char_sets:
        missing.append("uppercase letters")
    if "digits" not in char_sets:
        missing.append("numbers")
    if "symbols" not in char_sets:
        missing.append("symbols (!@#$%)")
    
    if missing:
        feedback.append(f"[CHARSET] Add {', '.join(missing)} to increase strength.")
    elif len(char_sets) >= 4:
        feedback.append("[CHARSET] Good character variety.")
    
    if patterns["has_patterns"]:
        for detail in patterns["details"]:
            feedback.append(f"[PATTERN] {detail}")
    
    if score["final_score"] >= 80:
        feedback.append("[OK] This is a strong password!")
    elif score["final_score"] >= 60:
        feedback.append("[OK] This password is decent but could be stronger.")
    
    crack_time = get_crack_time_estimate(entropy["entropy_bits"])
    if "instant" not in crack_time.lower() and "second" not in crack_time.lower():
        feedback.append(f"[TIME] Brute-force estimate: {crack_time}")
    else:
        feedback.append(f"[TIME] Could be cracked in {crack_time}!")
    
    return feedback


# ============================================================================
# CLI INTERFACE
# ============================================================================

app = typer.Typer(
    name="hashguard-os",
    help="Password strength analyzer",
    add_completion=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def callback(
    ctx: typer.Context,
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password to analyze"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show detailed analysis"
    ),
    offline: bool = typer.Option(
        False, "--offline", "-o",
        help="Skip breach check"
    ),
) -> None:
    """Password strength analyzer."""
    
    # If a subcommand is being invoked, don't run the default behavior
    if ctx.invoked_subcommand is not None:
        return
    
    # If no password provided via argument, prompt for it
    if password is None:
        console.print("[bold]hashguard-os[/bold] - Password Strength Analyzer")
        console.print()
        password = getpass("Enter password to analyze: ")
    
    if not password:
        console.print("[red]Error: No password provided[/red]")
        raise typer.Exit(1)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyzing password...", total=None)
        results = analyze_password(password, skip_breach_check=offline)
    
    display_results(results, verbose=verbose)


def get_score_color(score: int) -> str:
    if score <= 20:
        return "red"
    elif score <= 40:
        return "orange1"
    elif score <= 60:
        return "yellow"
    elif score <= 80:
        return "green"
    else:
        return "bright_green"


def display_results(results: dict, verbose: bool = False) -> None:
    """Display the analysis results."""
    
    score = results["score"]
    rating = results["rating"]
    symbol = get_rating_symbol(rating)
    color = get_score_color(score)
    
    score_display = f"[bold {color}]{score}/100[/bold {color}]"
    rating_display = f"[bold {color}]{rating.upper()}[/bold {color}]"
    
    console.print()
    console.print(Panel(
        f"{symbol} Score: {score_display}  |  Rating: {rating_display}  |  Brute-force estimate: {results['crack_time']}",
        title="[bold]hashguard-os Analysis[/bold]",
        border_style=color,
    ))
    
    console.print()
    console.print("[bold]Feedback:[/bold]")
    for item in results["feedback"]:
        console.print(f"  {item}")
    
    if verbose:
        console.print()
        
        entropy_table = Table(title="Entropy Analysis", box=box.ROUNDED)
        entropy_table.add_column("Metric", style="cyan")
        entropy_table.add_column("Value", style="white")
        
        entropy = results["entropy"]
        entropy_table.add_row("Entropy bits", f"{entropy['entropy_bits']:.2f}")
        entropy_table.add_row("Character pool size", str(entropy['pool_size']))
        entropy_table.add_row("Password length", str(entropy['length']))
        entropy_table.add_row("Character sets used", ", ".join(entropy['character_sets']) or "none")
        
        console.print(entropy_table)
        console.print()
        
        if results["patterns"]["has_patterns"]:
            patterns_table = Table(title="Patterns Detected", box=box.ROUNDED)
            patterns_table.add_column("Pattern Type", style="yellow")
            patterns_table.add_column("Details", style="white")
            
            for i, pattern in enumerate(results["patterns"]["patterns_found"]):
                detail = results["patterns"]["details"][i] if i < len(results["patterns"]["details"]) else ""
                patterns_table.add_row(pattern, detail)
            
            console.print(patterns_table)
            console.print()
        
        breakdown_table = Table(title="Score Breakdown", box=box.ROUNDED)
        breakdown_table.add_column("Component", style="cyan")
        
        for line in results["score_breakdown"]:
            breakdown_table.add_row(line)
        
        console.print(breakdown_table)


@app.command()
def explain():
    """Explain how hashguard-os works."""
    
    console.print(Panel(
        """
[bold]How hashguard-os Works[/bold]

[cyan]1. Entropy Calculation[/cyan]
   Measures password randomness in bits. Higher = better.

[cyan]2. Pattern Detection[/cyan]
   Catches keyboard walks, repeated chars, dates, l33t speak.

[cyan]3. Dictionary Check[/cyan]
   Compares against common passwords list.

[cyan]4. Breach Check (HaveIBeenPwned API)[/cyan]
   Uses k-anonymity - your password stays private!

[bold]Scoring[/bold]
   0-20: [X] Critical | 21-40: [-] Weak | 41-60: [~] Fair
   61-80: [+] Strong | 81-100: [!] Excellent
        """,
        title="[bold]hashguard-os[/bold]",
        border_style="cyan",
    ))


if __name__ == "__main__":
    app()
