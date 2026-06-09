"""
AI Model Security Scanner
Author: Maryssa L | github.com/Gemz-AACT
Version: 3.0.0
Description: Automated security testing tool for AI APIs
Now with 8 test categories, multi-provider support, and custom payload loading
"""

import argparse
import json
import datetime
import sys
import os
import time
import glob
import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import (
    prompt_injection,
    data_leakage,
    jailbreak,
    system_prompt_extraction,
    indirect_prompt_injection,
    model_dos,
    insecure_output_handling,
    training_data_extraction,
)
from providers import get_provider
from reporter.report_generator import generate_report
from scoring.scorer import generate_score_breakdown
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import config

console = Console()

ALL_TESTS = [
    ("prompt-injection",         "Prompt Injection",          prompt_injection),
    ("data-leakage",             "Data Leakage",              data_leakage),
    ("jailbreak",                "Jailbreak",                 jailbreak),
    ("system-prompt-extraction", "System Prompt Extraction",  system_prompt_extraction),
    ("indirect-injection",       "Indirect Prompt Injection", indirect_prompt_injection),
    ("model-dos",                "Model DoS",                 model_dos),
    ("insecure-output",          "Insecure Output Handling",  insecure_output_handling),
    ("training-extraction",      "Training Data Extraction",  training_data_extraction),
]

TEST_KEYS = [t[0] for t in ALL_TESTS]


def print_banner():
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
    parser = argparse.ArgumentParser(
        description="AI Model Security Scanner — Tests AI APIs for vulnerabilities",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--api-url",  required=True,  help="Target AI API endpoint URL")
    parser.add_argument("--api-key",  required=True,  help="API key for authentication")
    parser.add_argument("--model",    default=config.DEFAULT_MODEL,
                        help=f"Model name to test (default: {config.DEFAULT_MODEL})")
    parser.add_argument(
        "--provider",
        default="openai",
        choices=["openai", "anthropic", "gemini", "ollama"],
        help="API provider (default: openai)"
    )
    parser.add_argument(
        "--tests",
        default="all",
        help="Comma-separated tests to run or 'all' (default: all)\nAvailable: " + ", ".join(TEST_KEYS)
    )
    parser.add_argument(
        "--payloads-dir",
        default=None,
        help="Path to directory of custom payload .json files"
    )
    parser.add_argument("--output",  default=config.REPORT_OUTPUT_DIR,
                        help="Output directory for reports")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full AI responses during scan")
    return parser.parse_args()


def load_custom_payloads(payloads_dir, test_key):
    if not payloads_dir:
        return None
    if not os.path.isdir(payloads_dir):
        console.print(f"[yellow][!] --payloads-dir '{payloads_dir}' not found — using built-in payloads[/yellow]")
        return None

    pattern = os.path.join(payloads_dir, f"*{test_key}*.json")
    matches = glob.glob(pattern)
    if not matches:
        return None

    if len(matches) > 1:
        console.print(f"  [yellow][!] Multiple files match '{test_key}' — using: {matches[0]}[/yellow]")
    filepath = matches[0]

    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"  [red][!] Invalid JSON in {filepath}: {e} — using built-in payloads[/red]")
        return None
    except OSError as e:
        console.print(f"  [red][!] Cannot read {filepath}: {e} — using built-in payloads[/red]")
        return None

    if not isinstance(data, dict) or "payloads" not in data:
        console.print(f"  [red][!] {filepath} must have a top-level 'payloads' key[/red]")
        return None

    raw   = data["payloads"]
    valid = [p for p in raw if isinstance(p, str) and p.strip()]

    if not valid:
        console.print(f"  [yellow][!] No valid payloads in {filepath} — using built-in payloads[/yellow]")
        return None

    console.print(f"  [cyan][+] Loaded {len(valid)} custom payload(s) from {os.path.basename(filepath)}[/cyan]")
    return valid


def resolve_tests(tests_arg):
    if tests_arg.strip().lower() == "all":
        return ALL_TESTS
    requested = [t.strip().lower() for t in tests_arg.split(",")]
    key_map   = {t[0]: t for t in ALL_TESTS}
    selected  = []
    for key in requested:
        if key in key_map:
            selected.append(key_map[key])
        else:
            console.print(f"[yellow][!] Unknown test '{key}' — skipping[/yellow]")
    return selected


def print_summary(score_data):
    overall_score = score_data["overall_score"]
    risk_rating   = score_data["risk_rating"]
    risk_color    = score_data["risk_color"]

    console.print(Panel.fit(
        f"[bold {risk_color}]Overall Security Score: {overall_score}/100 — {risk_rating}[/bold {risk_color}]\n"
        f"Total Tests: {score_data['total_tests']} | "
        f"Vulnerable: {score_data['total_vulnerable']} | "
        f"Safe: {score_data['total_safe']}",
        title="Security Posture"
    ))

    table = Table(title="\nDetailed Scan Results")
    table.add_column("Test Type",  style="cyan",    width=26)
    table.add_column("Total",      style="white",   width=8)
    table.add_column("Vulnerable", style="red",     width=12)
    table.add_column("Safe",       style="green",   width=8)
    table.add_column("Max Score",  style="red",     width=12)
    table.add_column("Avg Score",  style="yellow",  width=12)
    table.add_column("Risk Level", style="magenta", width=12)

    for test_type, data in score_data["breakdown"].items():
        max_score = data["max_score"]
        risk = "HIGH" if max_score >= 80 else "MEDIUM" if max_score >= 50 else "LOW" if max_score > 0 else "NONE"
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
            console.print(f"     Reason:  {finding['reason'][:100]}...")


def save_json_report(score_data, timestamp):
    report_path = f"{config.REPORT_OUTPUT_DIR}scan_{timestamp}.json"
    with open(report_path, "w") as f:
        json.dump(score_data, f, indent=2)
    console.print(f"[green][+] JSON report saved to {report_path}[/green]")


def main():
    print_banner()
    args = parse_arguments()
    scan_start = datetime.datetime.now()

    console.print(f"\n[bold][*] Target API:[/bold]  {args.api_url}")
    console.print(f"[bold][*] Model:[/bold]       {args.model}")
    console.print(f"[bold][*] Provider:[/bold]    {args.provider}")
    if args.payloads_dir:
        console.print(f"[bold][*] Payloads dir:[/bold] {args.payloads_dir}")
    console.print(f"[bold][*] Started:[/bold]     {scan_start.strftime('%Y-%m-%d %H:%M:%S')}\n")

    selected_tests = resolve_tests(args.tests)
    if not selected_tests:
        console.print("[red][!] No valid tests selected. Exiting.[/red]")
        sys.exit(1)

    try:
        provider = get_provider(args.provider, args.api_url, args.api_key, args.model)
        console.print(f"[green][+] Provider ready: {args.provider.upper()}[/green]\n")
    except ValueError as e:
        console.print(f"[red][!] Provider error: {e}[/red]")
        sys.exit(1)

    console.print(f"[bold yellow][*] Running {len(selected_tests)} test module(s)...[/bold yellow]\n")

    all_results = []

    for i, (test_key, test_label, test_module) in enumerate(selected_tests):
        custom = load_custom_payloads(args.payloads_dir, test_key)
        results = test_module.run_test(
            provider=provider,
            api_url=args.api_url,
            api_key=args.api_key,
            model=args.model,
            verbose=args.verbose,
            custom_payloads=custom
        )
        all_results += results
        if i < len(selected_tests) - 1:
            console.print("\n[*] Waiting 5 seconds to avoid rate limiting...\n")
            time.sleep(5)

    scan_end      = datetime.datetime.now()
    scan_duration = str(scan_end - scan_start).split(".")[0]

    target_info = {
        "api_url":    args.api_url,
        "model":      args.model,
        "provider":   args.provider,
        "duration":   scan_duration,
        "start_time": scan_start.strftime('%Y-%m-%d %H:%M:%S'),
        "end_time":   scan_end.strftime('%Y-%m-%d %H:%M:%S'),
        "tests_run":  [t[1] for t in selected_tests],
    }

    score_data = generate_score_breakdown(all_results, target_info)
    print_summary(score_data)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    for result in all_results:
        for scored in score_data["scored_results"]:
            if (result["payload"] == scored["payload"] and
                    result["test"] == scored["test"]):
                result["score"]      = scored.get("score", 0)
                result["owasp_id"]   = scored.get("owasp_id", "N/A")
                result["owasp_name"] = scored.get("owasp_name", "N/A")
                result["owasp_url"]  = scored.get("owasp_url", "")
                break

    if config.GENERATE_JSON:
        save_json_report(score_data, timestamp)

    if config.GENERATE_PDF:
        generate_report(all_results, timestamp, score_data)

    # Organize output into subfolders
    report_dir = config.REPORT_OUTPUT_DIR if config.REPORT_OUTPUT_DIR.endswith("/") else config.REPORT_OUTPUT_DIR + "/"
    os.makedirs(f"{report_dir}pdf", exist_ok=True)
    os.makedirs(f"{report_dir}json", exist_ok=True)
    os.makedirs(f"{report_dir}hackerone", exist_ok=True)
    os.makedirs(f"{report_dir}bugcrowd", exist_ok=True)

    # Move PDF and JSON into subfolders
    pdf_src  = f"{report_dir}AI_Security_Report_{timestamp}.pdf"
    json_src = f"{report_dir}scan_{timestamp}.json"

    if os.path.exists(pdf_src):
        shutil.move(pdf_src,  f"{report_dir}pdf/AI_Security_Report_{timestamp}.pdf")
        console.print(f"[green][+] PDF report saved to reports/pdf/[/green]")

    if os.path.exists(json_src):
        shutil.move(json_src, f"{report_dir}json/scan_{timestamp}.json")
        console.print(f"[green][+] JSON report saved to reports/json/[/green]")

    # Auto-generate bug bounty reports
    json_final = f"{report_dir}json/scan_{timestamp}.json"
    if os.path.exists(json_final):
        console.print("\n[bold yellow][*] Generating bug bounty reports...[/bold yellow]")
        try:
            from reporter.bug_bounty_report import load_scan_results, generate_hackerone_report, generate_bugcrowd_report
            import datetime as dt

            bb_data     = load_scan_results(json_final)
            bb_results  = bb_data.get("scored_results", bb_data) if isinstance(bb_data, dict) else bb_data
            bb_findings = sorted(
                [r for r in bb_results if r.get("vulnerable") and r.get("score", 0) >= 50],
                key=lambda x: x.get("score", 0), reverse=True
            )

            target_url  = target_info.get("api_url", "N/A")

            if bb_findings:
                h1_path = f"{report_dir}hackerone/hackerone_report_{timestamp}.txt"
                bc_path = f"{report_dir}bugcrowd/bugcrowd_report_{timestamp}.txt"

                with open(h1_path, "w") as f:
                    f.write(f"HACKERONE BUG BOUNTY REPORTS\nGenerated: {timestamp}\nTarget: {target_url}\nTotal Findings: {len(bb_findings)}\n" + "="*80 + "\n\n")
                    for i, finding in enumerate(bb_findings, 1):
                        f.write(generate_hackerone_report(finding, "Target Program", target_url, i))

                with open(bc_path, "w") as f:
                    f.write(f"BUGCROWD BUG BOUNTY REPORTS\nGenerated: {timestamp}\nTarget: {target_url}\nTotal Findings: {len(bb_findings)}\n" + "="*80 + "\n\n")
                    for i, finding in enumerate(bb_findings, 1):
                        f.write(generate_bugcrowd_report(finding, "Target Program", target_url, i))

                console.print(f"[green][+] HackerOne report saved to reports/hackerone/[/green]")
                console.print(f"[green][+] Bugcrowd report saved to reports/bugcrowd/[/green]")
                console.print(f"[cyan][*] {len(bb_findings)} findings exported — review before submitting[/cyan]")
            else:
                console.print("[yellow][*] No findings above score threshold for bug bounty reports[/yellow]")
        except Exception as e:
            console.print(f"[yellow][!] Bug bounty report generation failed: {e}[/yellow]")

    console.print("\n[bold green][+] Scan complete![/bold green]")


if __name__ == "__main__":
    main()
