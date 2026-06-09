"""
Auto Bug Bounty Report Generator
Generates ready-to-submit reports for HackerOne and Bugcrowd
from AI Security Scanner findings.

Usage:
  python scanner/reporter/bug_bounty_report.py \
    --json reports/scan_TIMESTAMP.json \
    --platform hackerone \
    --program "Target Program Name" \
    --target-url https://api.target.com
"""

import json
import argparse
import datetime
import os


SEVERITY_MAP = {
    "HIGH":   {"h1": "high",     "bc": "P2", "cvss": "8.5"},
    "MEDIUM": {"h1": "medium",   "bc": "P3", "cvss": "5.5"},
    "LOW":    {"h1": "low",      "bc": "P4", "cvss": "3.5"},
    "NONE":   {"h1": "none",     "bc": "P5", "cvss": "0.0"},
}

OWASP_REMEDIATION = {
    "LLM01": """- Implement strict separation between system instructions and user input
- Use allowlists to validate and sanitize all inputs before passing to the model
- Apply a layered defense: input validation + output filtering + rate limiting
- Never trust user-supplied content as instructions""",

    "LLM02": """- Enforce data minimization — only include data the model needs
- Apply output filtering to detect and redact PII before responses reach users
- Restrict the model's access to sensitive data sources
- Implement system prompt confidentiality controls""",

    "LLM05": """- Treat all model outputs as untrusted user input
- Apply context-aware output encoding (HTML encode for web, parameterize for SQL)
- Never pass raw model output directly to interpreters, browsers, or shells
- Implement a content security policy (CSP) to limit XSS impact""",

    "LLM07": """- Mark system prompts as confidential and instruct the model not to reveal them
- Use a system prompt that explicitly refuses to repeat its own instructions
- Implement output filtering to detect system prompt content in responses
- Rotate system prompts regularly""",

    "LLM10": """- Implement token limits and request quotas per user/session
- Add timeouts to all AI API calls
- Monitor for abnormally large requests or responses
- Apply rate limiting at the API gateway level""",

    "LLM01 / LLM06": """- Implement strict input validation and output filtering
- Limit the model's ability to take autonomous actions
- Apply principle of least privilege to all model capabilities
- Monitor for unexpected behavior changes in model responses""",
}


def load_scan_results(json_path):
    with open(json_path) as f:
        return json.load(f)


def get_remediation(owasp_id):
    return OWASP_REMEDIATION.get(owasp_id, "- Review OWASP LLM Top 10 guidance for this vulnerability type\n- Consult your security team for remediation steps")


def generate_hackerone_report(finding, program_name, target_url, index):
    severity = finding.get("severity", "MEDIUM")
    owasp_id = finding.get("owasp_id", "N/A")
    owasp_name = finding.get("owasp_name", "N/A")
    test_type = finding.get("test", "AI Security Test")
    payload = finding.get("payload", "N/A")
    response = finding.get("response", "N/A")[:500]
    reason = finding.get("reason", "N/A")
    score = finding.get("score", 0)
    confidence = finding.get("confidence", 0)
    cvss = SEVERITY_MAP.get(severity, {}).get("cvss", "5.0")
    h1_severity = SEVERITY_MAP.get(severity, {}).get("h1", "medium")
    remediation = get_remediation(owasp_id)

    report = f"""
================================================================================
HACKERONE REPORT #{index} — {test_type.upper()}
================================================================================

## Title
{test_type} Vulnerability in AI API — {owasp_id}: {owasp_name}

## Severity
{h1_severity.upper()} (CVSS {cvss}) | Scanner Score: {score}/100 | Confidence: {confidence}%

## Program
{program_name}

## Target
{target_url}

## Vulnerability Type
AI/ML Security — {owasp_name} ({owasp_id})
OWASP LLM Top 10 (2025): {owasp_id} — {owasp_name}
Reference: https://genai.owasp.org/llm-top-10/

## Summary
The target AI API was found to be vulnerable to {test_type}. During automated
security testing, the model responded in a way that indicates a security weakness
mapped to {owasp_id} ({owasp_name}) in the OWASP LLM Top 10 (2025).

Scanner confidence: {confidence}% | Risk score: {score}/100

## Steps to Reproduce

1. Send the following payload to the AI API endpoint:

   Endpoint: {target_url}
   Method: POST
   Headers: Authorization: Bearer [API_KEY], Content-Type: application/json

   Request body:
   {{
     "model": "[MODEL_NAME]",
     "messages": [
       {{"role": "user", "content": "{payload[:200]}"}}
     ]
   }}

2. Observe the model response:

   "{response}..."

3. The response demonstrates {test_type} because:
   {reason}

## Impact
An attacker who can reproduce this vulnerability could:
- Bypass AI safety controls and extract sensitive information
- Manipulate the AI model's behavior for malicious purposes
- Use this as a stepping stone for further attacks against the application
- Violate user trust and privacy expectations

This finding maps to {owasp_id} ({owasp_name}) in the OWASP LLM Top 10 (2025),
indicating a well-documented and recognized AI security risk.

## Remediation
{remediation}

## Supporting Evidence
- Test Type: {test_type}
- OWASP ID: {owasp_id}
- OWASP Name: {owasp_name}
- Scanner Score: {score}/100
- Confidence Level: {confidence}%
- Detection Method: Dual-layer (rule-based + semantic AI analysis)
- Scanner: AI Model Security Scanner v3.0.0 (github.com/Gemz-AACT/ai-security-scanner)

================================================================================
"""
    return report


def generate_bugcrowd_report(finding, program_name, target_url, index):
    severity = finding.get("severity", "MEDIUM")
    owasp_id = finding.get("owasp_id", "N/A")
    owasp_name = finding.get("owasp_name", "N/A")
    test_type = finding.get("test", "AI Security Test")
    payload = finding.get("payload", "N/A")
    response = finding.get("response", "N/A")[:500]
    reason = finding.get("reason", "N/A")
    score = finding.get("score", 0)
    confidence = finding.get("confidence", 0)
    bc_priority = SEVERITY_MAP.get(severity, {}).get("bc", "P3")
    remediation = get_remediation(owasp_id)

    report = f"""
================================================================================
BUGCROWD REPORT #{index} — {test_type.upper()}
================================================================================

Title: {test_type} — {owasp_id}: {owasp_name}
Priority: {bc_priority}
Target: {target_url}
Program: {program_name}

---

## Description

The AI API at {target_url} is vulnerable to {test_type}, mapped to
{owasp_id} ({owasp_name}) in the OWASP LLM Top 10 (2025).

Risk Score: {score}/100 | Confidence: {confidence}%

## Proof of Concept

Payload sent:
{payload[:300]}

Response received:
{response}...

Detection reason:
{reason}

## Impact

This vulnerability allows an attacker to exploit weaknesses in the AI model's
input handling and response generation. Specifically:
- The model responded in a way that indicates {owasp_name}
- This could be used to extract sensitive data, bypass safety controls,
  or manipulate model behavior

## Remediation
{remediation}

## References
- OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
- {owasp_id}: https://genai.owasp.org/llmrisk/
- Scanner: github.com/Gemz-AACT/ai-security-scanner

================================================================================
"""
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Generate bug bounty reports from AI Security Scanner results"
    )
    parser.add_argument("--json",        required=True,  help="Path to scan JSON output file")
    parser.add_argument("--platform",    default="both", choices=["hackerone", "bugcrowd", "both"],
                        help="Target platform (default: both)")
    parser.add_argument("--program",     default="Target Program", help="Bug bounty program name")
    parser.add_argument("--target-url",  default="https://api.target.com", help="Target API URL")
    parser.add_argument("--min-score",   default=50, type=int,
                        help="Minimum score to include in report (default: 50)")
    parser.add_argument("--output-dir",  default="reports/", help="Output directory for reports")
    args = parser.parse_args()

    print(f"\n[*] Loading scan results from {args.json}...")
    data = load_scan_results(args.json)

    # Handle both raw results list and score_data dict
    if isinstance(data, list):
        results = data
    elif "scored_results" in data:
        results = data["scored_results"]
    else:
        results = data.get("results", [])

    # Filter to vulnerable findings above min score
    findings = [
        r for r in results
        if r.get("vulnerable") and r.get("score", 0) >= args.min_score
    ]

    # Sort by score descending
    findings = sorted(findings, key=lambda x: x.get("score", 0), reverse=True)

    print(f"[*] Found {len(findings)} findings above score threshold ({args.min_score})")

    if not findings:
        print("[!] No findings meet the minimum score threshold. Try lowering --min-score")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Create organized folder structure
    h1_dir = os.path.join(args.output_dir, "hackerone")
    bc_dir = os.path.join(args.output_dir, "bugcrowd")
    os.makedirs(h1_dir, exist_ok=True)
    os.makedirs(bc_dir, exist_ok=True)

    if args.platform in ["hackerone", "both"]:
        h1_path = os.path.join(h1_dir, f"hackerone_report_{timestamp}.txt")
        with open(h1_path, "w") as f:
            f.write(f"HACKERONE BUG BOUNTY REPORTS\n")
            f.write(f"Generated: {timestamp}\n")
            f.write(f"Program: {args.program}\n")
            f.write(f"Target: {args.target_url}\n")
            f.write(f"Total Findings: {len(findings)}\n")
            f.write("="*80 + "\n\n")
            for i, finding in enumerate(findings, 1):
                f.write(generate_hackerone_report(finding, args.program, args.target_url, i))
        print(f"[+] HackerOne report saved to {h1_path}")

    if args.platform in ["bugcrowd", "both"]:
        bc_path = os.path.join(bc_dir, f"bugcrowd_report_{timestamp}.txt")
        with open(bc_path, "w") as f:
            f.write(f"BUGCROWD BUG BOUNTY REPORTS\n")
            f.write(f"Generated: {timestamp}\n")
            f.write(f"Program: {args.program}\n")
            f.write(f"Target: {args.target_url}\n")
            f.write(f"Total Findings: {len(findings)}\n")
            f.write("="*80 + "\n\n")
            for i, finding in enumerate(findings, 1):
                f.write(generate_bugcrowd_report(finding, args.program, args.target_url, i))
        print(f"[+] Bugcrowd report saved to {bc_path}")

    print(f"\n[+] Done! {len(findings)} findings exported.")
    print(f"[!] Remember: Review and customize each report before submitting.")
    print(f"[!] Add your own testing notes and screenshots for stronger reports.")


if __name__ == "__main__":
    main()
