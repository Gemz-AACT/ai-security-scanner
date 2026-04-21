"""
AI Model Security Scanner
Author: Maryssa L | github.com/Gemz-AACT
Version: 1.0.0
Description: Automated security testing tool for AI APIs
"""

import argparse
import json
import datetime
import sys
import os

# Add parent directory to path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our test modules
from tests import prompt_injection, data_leakage, jailbreak
from reporter.report_generator import generate_report
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import config

# Initialize Rich console for beautiful CLI output
console = Console()

def print_banner():
    """Prints the tool banner when launched"""
    console.print(Panel.fit(
        f"""[bold blue]
    ╔═══════════════════════════════════════╗
    ║      AI Model Security Scanner        ║
    ║      Version {config.SCANNER_VERSION}                    ║
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
    parser.add_argument(
        "--api-url",
        required=True,
        help="Target AI API endpoint URL"
    )
    parser.add_argument(
        "--api-key",
        required=True,
        help="API key for authentication"
    )
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
    return parser.parse_args()

def print_summary(results):
    """Prints a formatted summary table of all scan results"""
    table = Table(title="\nScan Results Summary")
    table.add_column("Test Type", style="cyan", width=20)
    table.add_column("Total Tests", style="white", width=15)
    table.add_column("Vulnerable", style="red", width=15)
    table.add_column("Safe", style="green", width=15)
    table.add_column("Risk Level", style="yellow", width=15)

    for test_type in ["Prompt Injection", "Data Leakage", "Jailbreak"]:
        # Filter results for this test type
        tests = [r for r in results if r["test"] == test_type]
        vulns = [r for r in tests if r["vulnerable"]]
        
        # Calculate risk level based on vulnerabilities found
        vuln_count = len(vulns)
        if vuln_count == 0:
            risk = "LOW"
        elif vuln_count <= 2:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        table.add_row(
            test_type,
            str(len(tests)),
            str(vuln_count),
            str(len(tests) - vuln_count),
            risk
        )

    console.print(table)

def save_json_report(results, timestamp):
    """Saves raw scan results to a JSON file for further analysis"""
    report_path = f"{config.REPORT_OUTPUT_DIR}scan_{timestamp}.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"[green][+] JSON report saved to {report_path}[/green]")

def main():
    # Print banner
    print_banner()

    # Parse command line arguments
    args = parse_arguments()

    # Display scan info
    console.print(f"\n[bold][*] Target API:[/bold] {args.api_url}")
    console.print(f"[bold][*] Model:[/bold] {args.model}")
    console.print(f"[bold][*] Started:[/bold] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Run all tests and collect results
    all_results = []

    console.print("[bold yellow][*] Starting security tests...[/bold yellow]\n")

    # Run prompt injection tests
    all_results += prompt_injection.run_test(
        args.api_url, args.api_key, args.model)

    # Run data leakage tests
    all_results += data_leakage.run_test(
        args.api_url, args.api_key, args.model)

    # Run jailbreak tests
    all_results += jailbreak.run_test(
        args.api_url, args.api_key, args.model)

    # Print summary table
    print_summary(all_results)

    # Generate timestamp for report filenames
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save JSON report
    if config.GENERATE_JSON:
        save_json_report(all_results, timestamp)

    # Generate PDF report
    if config.GENERATE_PDF:
        generate_report(all_results, timestamp)

    console.print("\n[bold green][+] Scan complete![/bold green]")

if __name__ == "__main__":
    main()