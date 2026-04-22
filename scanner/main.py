"""
AI Model Security Scanner
Author: Maryssa L | github.com/Gemz-AACT
Version: 2.0.0
Description: Automated security testing tool for AI APIs
Now with enhanced semantic detection and CVSS-style severity scoring
"""

import argparse
import json
import datetime
import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import prompt_injection, data_leakage, jailbreak
from reporter.report_generator import generate_report
from scoring.scorer import generate_score_breakdown
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import config

console = Console()

def print_banner():
    """Prints the tool banner when launched"""
    console.print(Panel.fit(
        f"""[bold blue]
    ╔═══════════════════════════════════════╗
    ║      AI Model Security Scanner        ║
    ║      Version {config.SCANNER_VERSION}                     ║
    ║      By Maryssa L                     ║
    ║      github.com/Gemz-AACT             ║
    ╚═══════════════════════════════════════╝
    [/bold blue]"""
    ))

def parse_arguments():
    """Sets up and parses command line arguments"""
    parser = argparse.ArgumentParser(
        description="AI Model Security Scanner — Tests AI APIs for vulnerabilities"
    )
    parser.add_argument("--api-url", required=True, help="Target AI API endpoint URL")
    parser.add_argument("--api-key", required=True, help="API key for authentication")
    parser.add_argument(
        "--model",
        default=config.DEFAULT_MODEL,
        help=f"Model to test (default: {config.DEFAULT_MODEL})"
    )
    parser.add_argument(
        "--output",
        default=config.REPORT_OUTPUT_DIR,
        help="Output directory for reports"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full AI responses during scan"
    )
    return parser.parse_args()

def print_summary(score_data):
    """
    Prints enhanced summary table with:
    - Severity breakdown per test type
    - Risk scores
    - Overall security posture score
    - Top critical findings
    """
    overall_score = score_data["overall_score"]
    risk_rating = score_data["risk_rating"]
    risk_color = score_data["risk_color"]

    console.print(Panel.fit(
        f"[bold {risk_color}]Overall Security Score: {overall_score}/100 — {risk_rating}[/bold {risk_color}]\n"
        f"Total Tests: {score_data['total_tests']} | "
        f"Vulnerable: {score_data['total_vulnerable']} | "
        f"Safe: {score_data['total_safe']}",
        title="Security Posture"
    ))

    table = Table(title="\nDetailed Scan Results")
    table.add_column("Test Type", style="cyan", width=20)
    table.add_column("Total", style="white", width=8)
    table.add_column("Vulnerable", style="red", width=12)
    table.add_column("Safe", style="green", width=8)
    table.add_column("Max Score", style="red", width=12)
    table.add_column("Avg Score", style="yellow", width=12)
    table.add_column("Risk Level", style="magenta", width=12)

    for test_type, data in score_data["breakdown"].items():
        max_score = data["max_score"]
        if max_score >= 80:
            risk = "HIGH"
        elif max_score >= 50:
            risk = "MEDIUM"
        elif max_score > 0:
            risk = "LOW"
        else:
            risk = "NONE"

        table.add_row(
            test_type,
            str(data["total"]),
            str(data["vulnerable"]),
            str(data["safe"]),
            str(data["max_score"]),
            str(data["avg_score"]),
            risk
        )

    console.print(table)

    if score_data["top_findings"]:
        console.print("\n[bold red]⚠ TOP CRITICAL FINDINGS:[/bold red]")
        for i, finding in enumerate(score_data["top_findings"], 1):
            console.print(
                f"  [red]#{i} Score: {finding['score']}/100[/red] | "
                f"{finding['test']} | {finding['severity']}")
            console.print(f"     Payload: {finding['payload'][:70]}...")
            console.print(f"     Reason: {finding['reason'][:100]}...")

def save_json_report(score_data, timestamp):
    """Saves full scored results to JSON"""
    report_path = f"{config.REPORT_OUTPUT_DIR}scan_{timestamp}.json"
    with open(report_path, "w") as f:
        json.dump(score_data, f, indent=2)
    console.print(f"[green][+] JSON report saved to {report_path}[/green]")

def main():
    # Print banner
    print_banner()

    # Parse arguments
    args = parse_arguments()

    # Record scan start time
    scan_start = datetime.datetime.now()

    # Display scan info
    console.print(f"\n[bold][*] Target API:[/bold] {args.api_url}")
    console.print(f"[bold][*] Model:[/bold] {args.model}")
    console.print(f"[bold][*] Started:[/bold] {scan_start.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Collect all results
    all_results = []

    console.print("[bold yellow][*] Starting security tests...[/bold yellow]\n")

    # Run prompt injection tests
    # Run prompt injection tests
    all_results += prompt_injection.run_test(
        args.api_url, args.api_key, args.model, args.verbose)

    console.print("\n[*] Waiting 5 seconds to avoid rate limiting...\n")
    time.sleep(5)

    # Run data leakage tests
    all_results += data_leakage.run_test(
        args.api_url, args.api_key, args.model, args.verbose)

    console.print("\n[*] Waiting 5 seconds to avoid rate limiting...\n")
    time.sleep(5)

    # Run jailbreak tests
    all_results += jailbreak.run_test(
        args.api_url, args.api_key, args.model, args.verbose)

    # Calculate scan duration
    scan_end = datetime.datetime.now()
    scan_duration = str(scan_end - scan_start).split(".")[0]

    # Build target info
    target_info = {
        "api_url": args.api_url,
        "model": args.model,
        "duration": scan_duration,
        "start_time": scan_start.strftime('%Y-%m-%d %H:%M:%S'),
        "end_time": scan_end.strftime('%Y-%m-%d %H:%M:%S')
    }

    # Generate score breakdown with target info
    score_data = generate_score_breakdown(all_results, target_info)

    # Print enhanced summary
    print_summary(score_data)

    # Generate timestamp for filenames
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Add individual scores to results for PDF
    for result in all_results:
        for scored in score_data["scored_results"]:
            if (result["payload"] == scored["payload"] and
                    result["test"] == scored["test"]):
                result["score"] = scored.get("score", 0)
                break

    # Save JSON report
    if config.GENERATE_JSON:
        save_json_report(score_data, timestamp)

    # Generate PDF report
    if config.GENERATE_PDF:
        generate_report(all_results, timestamp, score_data)

    console.print("\n[bold green][+] Scan complete![/bold green]")


if __name__ == "__main__":
    main()