#!/usr/bin/env python3
"""
main.py - hashguard-os CLI entry point

This is the main script you run to analyze passwords.
Uses typer for CLI argument handling and rich for pretty output.

Usage:
    python main.py                     # Interactive mode (prompts for password)
    python main.py -p "mypassword"     # Direct password input
    python main.py --verbose           # Show detailed breakdown
    python main.py --offline           # Skip breach check (no internet needed)
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from getpass import getpass
from typing import Optional

from analyzer import analyze_password
from analyzer.scorer import get_rating_emoji

# Initialize typer app and rich console
app = typer.Typer(
    name="hashguard-os",
    help="🔐 Password strength analyzer - check your passwords against patterns, dictionaries, and breach databases",
    add_completion=False,
)
console = Console()


def get_score_color(score: int) -> str:
    """
    Get a color for the score display based on value.
    
    Rich uses color names or hex codes for styling.
    """
    
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
    """
    Display the analysis results in a nice formatted way.
    
    Uses rich panels and tables for clean terminal output.
    """
    
    score = results["score"]
    rating = results["rating"]
    emoji = get_rating_emoji(rating)
    color = get_score_color(score)
    
    # Main score panel
    score_display = f"[bold {color}]{score}/100[/bold {color}]"
    rating_display = f"[bold {color}]{rating.upper()}[/bold {color}]"
    
    console.print()
    console.print(Panel(
        f"{emoji} Score: {score_display}  •  Rating: {rating_display}  •  Crack time: {results['crack_time']}",
        title="[bold]hashguard-os Analysis[/bold]",
        border_style=color,
    ))
    
    # Feedback section
    console.print()
    console.print("[bold]Feedback:[/bold]")
    for item in results["feedback"]:
        console.print(f"  {item}")
    
    # Verbose mode shows the detailed breakdown
    if verbose:
        console.print()
        
        # Entropy details table
        entropy_table = Table(title="Entropy Analysis", box=box.ROUNDED)
        entropy_table.add_column("Metric", style="cyan")
        entropy_table.add_column("Value", style="white")
        
        entropy = results["entropy"]
        entropy_table.add_row("Entropy bits", f"{entropy['entropy_bits']:.2f}")
        entropy_table.add_row("Character pool size", str(entropy['pool_size']))
        entropy_table.add_row("Password length", str(entropy['length']))
        entropy_table.add_row("Character sets used", ", ".join(entropy['character_sets']) or "none")
        entropy_table.add_row("Entropy rating", entropy['rating'])
        
        console.print(entropy_table)
        console.print()
        
        # Patterns detected
        if results["patterns"]["has_patterns"]:
            patterns_table = Table(title="Patterns Detected", box=box.ROUNDED)
            patterns_table.add_column("Pattern Type", style="yellow")
            patterns_table.add_column("Details", style="white")
            
            for i, pattern in enumerate(results["patterns"]["patterns_found"]):
                detail = results["patterns"]["details"][i] if i < len(results["patterns"]["details"]) else ""
                patterns_table.add_row(pattern, detail)
            
            console.print(patterns_table)
            console.print()
        
        # Score breakdown
        breakdown_table = Table(title="Score Breakdown", box=box.ROUNDED)
        breakdown_table.add_column("Component", style="cyan")
        
        for line in results["score_breakdown"]:
            breakdown_table.add_row(line)
        
        console.print(breakdown_table)
        console.print()
        
        # Breach check details
        breach = results["breach"]
        if breach["checked"]:
            breach_status = "[red]FOUND IN BREACHES[/red]" if breach["is_breached"] else "[green]Not found in breaches[/green]"
            console.print(f"[bold]Breach Check:[/bold] {breach_status}")
            if breach["is_breached"]:
                console.print(f"  Times seen in breaches: [red]{breach['breach_count']:,}[/red]")
        elif breach["error"]:
            console.print(f"[bold]Breach Check:[/bold] [yellow]Could not check - {breach['error']}[/yellow]")


@app.command()
def main(
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password to analyze (will prompt securely if not provided)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show detailed analysis breakdown"
    ),
    offline: bool = typer.Option(
        False, "--offline", "-o",
        help="Skip breach check (no internet required)"
    ),
) -> None:
    """
    🔐 Analyze password strength against patterns, dictionaries, and breaches.
    """
    
    # Get password if not provided via argument
    if password is None:
        console.print("[bold]hashguard-os[/bold] - Password Strength Analyzer")
        console.print()
        # Using getpass for secure input (hides what you type)
        password = getpass("Enter password to analyze: ")
    
    # Validate we got something
    if not password:
        console.print("[red]Error: No password provided[/red]")
        raise typer.Exit(1)
    
    # Show a spinner while we analyze (especially for the breach check API call)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,  # Disappears when done
    ) as progress:
        task = progress.add_task("Analyzing password...", total=None)
        
        # Run the analysis
        results = analyze_password(password, skip_breach_check=offline)
    
    # Display the results
    display_results(results, verbose=verbose)


@app.command()
def explain():
    """
    Explain how hashguard-os analyzes passwords and protects your privacy.
    """
    
    console.print(Panel(
        """
[bold]How hashguard-os Works[/bold]

[cyan]1. Entropy Calculation[/cyan]
   Measures password randomness in bits. Higher = better.
   A password using lowercase + uppercase + numbers + symbols
   has a larger character pool, making it harder to guess.

[cyan]2. Pattern Detection[/cyan]
   Catches lazy patterns that make passwords easy to crack:
   • Keyboard walks (qwerty, asdf, 12345)
   • Repeated characters (aaaaaa)
   • Sequential characters (abcdef)
   • Date patterns (19901225)
   • L33t speak (p@ssw0rd)

[cyan]3. Dictionary Check[/cyan]
   Compares against thousands of commonly used passwords.
   If your password is on the list, attackers try it first.

[cyan]4. Breach Check (HaveIBeenPwned API)[/cyan]
   Checks if your password has appeared in known data breaches.
   Uses k-anonymity - only first 5 chars of hash are sent.
   [green]Your actual password never leaves your machine![/green]

[bold]Scoring[/bold]
   • 0-20: 💀 Critical - instantly crackable
   • 21-40: 🔴 Weak - crackable in minutes
   • 41-60: 🟠 Fair - could be stronger
   • 61-80: 🟢 Strong - good for most uses
   • 81-100: 🛡️ Excellent - very secure
        """,
        title="[bold]hashguard-os - How It Works[/bold]",
        border_style="cyan",
    ))


if __name__ == "__main__":
    app()
