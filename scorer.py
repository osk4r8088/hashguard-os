"""
scorer.py - Combine all analysis into a final security score

This is where everything comes together. We take results from:
- Entropy calculation
- Pattern detection
- Dictionary check
- Breach check

And combine them into a single 0-100 score with clear feedback.

Scoring Philosophy:
- Start with entropy as the base (0-100 scaled from bits)
- Apply penalties for patterns, common passwords, and breaches
- Never let a breached or common password score above 20
- Provide specific, actionable feedback
"""

from typing import Dict, List
from .entropy import calculate_entropy, get_crack_time_estimate
from .patterns import detect_patterns
from .dictionary import check_dictionary
from .breach_check import check_breach


def analyze_password(password: str, skip_breach_check: bool = False) -> Dict:
    """
    Run full analysis on a password and return comprehensive results.
    
    This is the main entry point for the analyzer.
    Set skip_breach_check=True to skip the API call (offline mode).
    """
    
    # Run all the individual checks
    entropy_result = calculate_entropy(password)
    pattern_result = detect_patterns(password)
    dictionary_result = check_dictionary(password)
    
    # Breach check is optional (requires internet)
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
    
    # Calculate the final score
    score_result = calculate_score(
        entropy_result,
        pattern_result,
        dictionary_result,
        breach_result
    )
    
    # Generate feedback
    feedback = generate_feedback(
        password,
        entropy_result,
        pattern_result,
        dictionary_result,
        breach_result,
        score_result
    )
    
    # Compile everything into the final result
    return {
        "password_length": len(password),
        "score": score_result["final_score"],
        "rating": score_result["rating"],
        "crack_time": get_crack_time_estimate(entropy_result["entropy_bits"]),
        
        # Detailed breakdowns
        "entropy": entropy_result,
        "patterns": pattern_result,
        "dictionary": dictionary_result,
        "breach": breach_result,
        
        # Human-readable output
        "feedback": feedback,
        "score_breakdown": score_result["breakdown"],
    }


def calculate_score(
    entropy: Dict,
    patterns: Dict,
    dictionary: Dict,
    breach: Dict
) -> Dict:
    """
    Calculate the final 0-100 score from all the analysis results.
    
    Scoring method:
    1. Base score from entropy (scaled to 0-100)
    2. Subtract penalties from patterns, dictionary, breach
    3. Hard caps for critical issues
    """
    
    breakdown = []
    
    # Step 1: Calculate base score from entropy
    # 80 bits of entropy = 100 points (extremely strong)
    # Scale linearly below that
    entropy_bits = entropy["entropy_bits"]
    base_score = min(100, (entropy_bits / 80) * 100)
    breakdown.append(f"Base score from entropy: {base_score:.0f}/100 ({entropy_bits:.1f} bits)")
    
    # Step 2: Apply penalties
    total_penalty = 0
    
    # Pattern penalty
    if patterns["penalty"] > 0:
        total_penalty += patterns["penalty"]
        breakdown.append(f"Pattern penalty: -{patterns['penalty']} (found: {', '.join(patterns['patterns_found'])})")
    
    # Dictionary penalty
    if dictionary["penalty"] > 0:
        total_penalty += dictionary["penalty"]
        breakdown.append(f"Dictionary penalty: -{dictionary['penalty']} ({dictionary['match_type']} match)")
    
    # Breach penalty
    if breach["penalty"] > 0:
        total_penalty += breach["penalty"]
        breakdown.append(f"Breach penalty: -{breach['penalty']} (found {breach['breach_count']:,} times)")
    
    # Step 3: Calculate final score
    final_score = max(0, base_score - total_penalty)
    
    # Step 4: Apply hard caps for critical issues
    # A breached password should never score well, no matter the entropy
    if breach["is_breached"] and breach["breach_count"] > 1000:
        final_score = min(final_score, 15)
        breakdown.append("Hard cap applied: heavily breached password")
    
    # A common password should never score well
    if dictionary["is_common"] and dictionary["match_type"] == "exact":
        final_score = min(final_score, 10)
        breakdown.append("Hard cap applied: exact match in common passwords")
    
    # Very short passwords are always weak
    if entropy.get("length", 0) < 6:
        final_score = min(final_score, 20)
        breakdown.append("Hard cap applied: password too short")
    
    final_score = round(final_score)
    
    return {
        "final_score": final_score,
        "rating": get_rating(final_score),
        "base_score": round(base_score),
        "total_penalty": total_penalty,
        "breakdown": breakdown
    }


def get_rating(score: int) -> str:
    """
    Convert numeric score to a rating label.
    """
    
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


def get_rating_emoji(rating: str) -> str:
    """
    Get an emoji for the rating (for terminal output).
    """
    
    emojis = {
        "critical": "💀",
        "weak": "🔴",
        "fair": "🟠",
        "strong": "🟢",
        "excellent": "🛡️"
    }
    return emojis.get(rating, "❓")


def generate_feedback(
    password: str,
    entropy: Dict,
    patterns: Dict,
    dictionary: Dict,
    breach: Dict,
    score: Dict
) -> List[str]:
    """
    Generate specific, actionable feedback based on the analysis.
    
    We want to tell users exactly what's wrong and how to fix it.
    """
    
    feedback = []
    
    # Critical issues first
    if breach["is_breached"]:
        feedback.append(
            f"⚠️  CRITICAL: This password was found in {breach['breach_count']:,} data breaches. "
            "Change it immediately!"
        )
    
    if dictionary["is_common"]:
        feedback.append(
            f"⚠️  This is a commonly used password. Attackers try these first."
        )
    
    # Length feedback
    length = len(password)
    if length < 8:
        feedback.append(f"📏 Too short ({length} chars). Use at least 12 characters.")
    elif length < 12:
        feedback.append(f"📏 Length is okay ({length} chars) but 12+ is better.")
    elif length >= 16:
        feedback.append(f"📏 Good length ({length} chars).")
    
    # Character set feedback
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
        feedback.append(f"🔤 Add {', '.join(missing)} to increase strength.")
    elif len(char_sets) >= 4:
        feedback.append("🔤 Good character variety.")
    
    # Pattern feedback
    if patterns["has_patterns"]:
        for detail in patterns["details"]:
            feedback.append(f"🔍 {detail}")
    
    # Positive feedback for good passwords
    if score["final_score"] >= 80:
        feedback.append("✅ This is a strong password!")
    elif score["final_score"] >= 60:
        feedback.append("👍 This password is decent but could be stronger.")
    
    # Crack time context
    crack_time = get_crack_time_estimate(entropy["entropy_bits"])
    if "instant" not in crack_time.lower() and "second" not in crack_time.lower():
        feedback.append(f"⏱️  Estimated crack time: {crack_time}")
    else:
        feedback.append(f"⏱️  Could be cracked in {crack_time}!")
    
    return feedback
