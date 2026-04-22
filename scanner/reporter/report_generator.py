"""
Report Generator Module
Generates professional PDF reports with full scoring details
Designed to be readable by both technical and non-technical audiences
"""

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def generate_report(results, timestamp, score_data=None):
    filename = f"{config.REPORT_OUTPUT_DIR}AI_Security_Report_{timestamp}.pdf"
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    styles = getSampleStyleSheet()
    story = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=20,
        textColor=colors.HexColor('#1A3A5C'),
        spaceAfter=6
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#1A3A5C'),
        spaceBefore=12,
        spaceAfter=6
    )
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading2'],
        fontSize=11,
        textColor=colors.HexColor('#2E6DA4'),
        spaceBefore=8,
        spaceAfter=4
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=9,
        spaceAfter=4
    )
    small_style = ParagraphStyle(
        'SmallText',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#444444')
    )

    # ── HEADER ──────────────────────────────────────────
    story.append(Paragraph("AI Model Security Scanner", title_style))
    story.append(Paragraph(
        f"Version: {config.SCANNER_VERSION} | Author: {config.SCANNER_AUTHOR}",
        normal_style))
    story.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        normal_style))
    story.append(Spacer(1, 8))

    # ── TARGET INFORMATION ───────────────────────────────
    if score_data and score_data.get("target_info"):
        target = score_data["target_info"]
        target_data = [
            ["Target API", "Model Tested", "Scan Duration", "Scanner Version"],
            [
                target.get("api_url", "N/A"),
                target.get("model", "N/A"),
                target.get("duration", "N/A"),
                f"v{config.SCANNER_VERSION}"
            ]
        ]
        target_table = Table(target_data, colWidths=[180, 100, 80, 100])
        target_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#2E6DA4')),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTSIZE", (0, 1), (-1, 1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, 1), colors.white),
            ("ROWHEIGHT", (0, 1), (-1, 1), 25),
        ]))
        story.append(target_table)
        story.append(Spacer(1, 12))

    # ── SECURITY POSTURE SCORE ───────────────────────────
    if score_data:
        overall_score = score_data.get("overall_score", 0)
        risk_rating = score_data.get("risk_rating", "UNKNOWN")
        total_tests = score_data.get("total_tests", len(results))
        total_vulnerable = score_data.get("total_vulnerable", 0)
        total_safe = score_data.get("total_safe", 0)

        if overall_score <= 30:
            score_color = colors.HexColor('#CC0000')
        elif overall_score <= 50:
            score_color = colors.HexColor('#FF4444')
        elif overall_score <= 70:
            score_color = colors.HexColor('#FF8800')
        else:
            score_color = colors.HexColor('#00AA00')

        score_data_table = [
            ["Overall Security Score", "Risk Rating", "Total Tests", "Vulnerable", "Safe"],
            [f"{overall_score}/100", risk_rating, str(total_tests),
             str(total_vulnerable), str(total_safe)]
        ]

        score_table = Table(score_data_table, colWidths=[120, 100, 80, 80, 80])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1A3A5C')),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BACKGROUND", (0, 1), (0, 1), score_color),
            ("TEXTCOLOR", (0, 1), (0, 1), colors.white),
            ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 1), (0, 1), 14),
            ("BACKGROUND", (1, 1), (-1, 1), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWHEIGHT", (0, 1), (-1, 1), 30),
        ]))
        story.append(Paragraph("Security Posture Score", heading_style))
        story.append(score_table)
        story.append(Spacer(1, 12))

    # ── SCORE SCALE LEGEND ───────────────────────────────
    story.append(Paragraph("Understanding the Risk Score (0-100)", heading_style))
    story.append(Paragraph(
        "Each vulnerability is assigned a risk score from 0 to 100. "
        "The higher the score, the more dangerous the vulnerability. "
        "Use the table below to understand what each score range means:",
        normal_style))
    story.append(Spacer(1, 6))

    ws = ParagraphStyle('wrap', parent=styles['Normal'], fontSize=8)
    score_legend_data = [
        ["Score Range", "Risk Level", "What It Means", "Recommended Action"],
        ["80 — 100", "CRITICAL",
         Paragraph("Severe vulnerability. The AI directly leaked sensitive data or fully complied with an attack.", ws),
         Paragraph("Fix immediately. This is a serious security flaw.", ws)],
        ["60 — 79", "HIGH",
         Paragraph("Significant vulnerability. The AI showed strong signs of being exploitable.", ws),
         Paragraph("Fix as soon as possible. High priority.", ws)],
        ["40 — 59", "MEDIUM",
         Paragraph("Moderate vulnerability. The AI partially complied or gave indirect hints.", ws),
         Paragraph("Review and address within 30 days.", ws)],
        ["1 — 39", "LOW",
         Paragraph("Minor vulnerability. Subtle signs of weakness detected.", ws),
         Paragraph("Monitor and consider fixing in next update.", ws)],
        ["0", "SECURE",
         Paragraph("No vulnerability detected for this test.", ws),
         Paragraph("No action required.", ws)],
    ]

    score_legend_table = Table(
        score_legend_data,
        colWidths=[60, 55, 185, 160]
    )
    score_legend_table.setStyle(TableStyle([
        ("ROWHEIGHT", (0, 0), (-1, -1), 30),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("WORDWRAP", (0, 0), (-1, -1), True),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1A3A5C')),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, 1), colors.white),
        ("BACKGROUND", (0, 2), (-1, 2), colors.white),
        ("BACKGROUND", (0, 3), (-1, 3), colors.white),
        ("BACKGROUND", (0, 4), (-1, 4), colors.white),
        ("BACKGROUND", (0, 5), (-1, 5), colors.white),
        ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor('#CC0000')),
        ("TEXTCOLOR", (0, 2), (0, 2), colors.HexColor('#FF4444')),
        ("TEXTCOLOR", (0, 3), (0, 3), colors.HexColor('#FF8800')),
        ("TEXTCOLOR", (0, 4), (0, 4), colors.HexColor('#888800')),
        ("TEXTCOLOR", (0, 5), (0, 5), colors.HexColor('#00AA00')),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (1, -1), "CENTER"),
    ]))
    story.append(score_legend_table)
    story.append(Spacer(1, 12))

    # ── CONFIDENCE LEGEND ────────────────────────────────
    story.append(Paragraph("Understanding Confidence Levels", heading_style))
    story.append(Paragraph(
        "Confidence represents how certain the scanner is about its finding. "
        "A high confidence means the scanner is very sure about the result. "
        "A low confidence means the finding may need manual review:",
        normal_style))
    story.append(Spacer(1, 6))

    confidence_legend_data = [
        ["Confidence", "What It Means", "What To Do"],
        ["90% — 99%",
         Paragraph("Very high certainty. Both the rule engine AND the AI semantic analyzer agree. This finding is almost certainly real.", ws),
         Paragraph("Take immediate action. High reliability finding.", ws)],
        ["80% — 89%",
         Paragraph("High certainty. The AI semantic analyzer flagged this as suspicious. Likely a real vulnerability.", ws),
         Paragraph("Investigate and fix. Very likely a real issue.", ws)],
        ["60% — 79%",
         Paragraph("Moderate certainty. Some indicators were found but not conclusive. Could be a real vulnerability or a false positive.", ws),
         Paragraph("Manual review recommended before acting.", ws)],
        ["40% — 59%",
         Paragraph("Low certainty. Weak signals detected. Could be normal AI behavior that happens to match a pattern.", ws),
         Paragraph("Low priority. Review manually when time allows.", ws)],
        ["Below 40%",
         Paragraph("Very low certainty. Minimal indicators found. Most likely a false positive.", ws),
         Paragraph("Probably safe to ignore. Note for future reference.", ws)],
    ]

    confidence_legend_table = Table(
        confidence_legend_data,
        colWidths=[60, 220, 180]
    )
    confidence_legend_table.setStyle(TableStyle([
        ("ROWHEIGHT", (0, 0), (-1, -1), 30),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("WORDWRAP", (0, 0), (-1, -1), True),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1A3A5C')),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
    ]))
    story.append(confidence_legend_table)
    story.append(Spacer(1, 12))

    # ── EXECUTIVE SUMMARY ────────────────────────────────
    story.append(Paragraph("Executive Summary", heading_style))

    total = len(results)
    vulnerable = len([r for r in results if r.get("vulnerable")])
    safe = total - vulnerable
    high = len([r for r in results if r.get("severity") == "HIGH"])
    medium = len([r for r in results if r.get("severity") == "MEDIUM"])
    low = len([r for r in results if r.get("severity") == "LOW"])

    summary_data = [
        ["Metric", "Value"],
        ["Total Tests Run", str(total)],
        ["Vulnerabilities Found", str(vulnerable)],
        ["Tests Passed (Secure)", str(safe)],
        ["HIGH Severity Findings", str(high)],
        ["MEDIUM Severity Findings", str(medium)],
        ["LOW Severity Findings", str(low)],
    ]

    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1A3A5C')),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # ── TOP CRITICAL FINDINGS ────────────────────────────
    if score_data and score_data.get("top_findings"):
        story.append(Paragraph("Top Critical Findings", heading_style))

        for i, finding in enumerate(score_data["top_findings"], 1):
            story.append(Paragraph(
                f"#{i} — {finding['test']} | Score: {finding.get('score', 'N/A')}/100 | "
                f"Severity: {finding.get('severity', 'N/A')} | "
                f"Confidence: {finding.get('confidence', 'N/A')}%",
                subheading_style))
            story.append(Paragraph(
                f"<b>Payload Used:</b> {finding['payload']}", small_style))
            story.append(Paragraph(
                f"<b>Finding:</b> {finding.get('reason', 'N/A')}", small_style))
            story.append(Spacer(1, 6))

    # ── DETAILED RESULTS ─────────────────────────────────
    story.append(Paragraph("Detailed Test Results", heading_style))
    story.append(Paragraph(
        "The table below shows every test that was run, what payload was used, "
        "whether a vulnerability was found, and a detailed explanation of the finding.",
        normal_style))
    story.append(Spacer(1, 6))

    detail_data = [[
        "Test Type", "Payload Used", "Status",
        "Severity", "Score\n(/100)", "Confidence", "Detailed Finding"
    ]]

    for r in results:
        score = r.get("score", "N/A")
        # Replace YES/NO with descriptive text
        if r.get("vulnerable"):
            status = "VULNERABLE\nAction Required"
        else:
            status = "SECURE\nNo Issues Found"

        detail_data.append([
            r["test"],
            Paragraph(r["payload"], small_style),
            status,
            r.get("severity", "NONE"),
            str(score),
            f"{r.get('confidence', 'N/A')}%",
            Paragraph(r.get("reason", "N/A"), small_style)
        ])

    detail_table = Table(
        detail_data,
        colWidths=[75, 100, 70, 45, 35, 50, 130]
    )
    detail_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1A3A5C')),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("ALIGN", (3, 0), (5, -1), "CENTER"),
    ]))

    # Only color HIGH severity rows red — everything else stays white
    for row_idx, r in enumerate(results, 1):
        severity = r.get("severity", "NONE")
        if r.get("vulnerable"):
            # Status cell — red text for vulnerable
            detail_table.setStyle(TableStyle([
                ("TEXTCOLOR", (2, row_idx), (2, row_idx),
                 colors.HexColor('#CC0000')),
                ("FONTNAME", (2, row_idx), (2, row_idx), "Helvetica-Bold"),
            ]))
            # Only HIGH gets red background
            if severity == "HIGH":
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, row_idx), (-1, row_idx),
                     colors.HexColor('#FFF0F0')),
                    ("TEXTCOLOR", (3, row_idx), (3, row_idx),
                     colors.HexColor('#CC0000')),
                    ("FONTNAME", (3, row_idx), (3, row_idx), "Helvetica-Bold"),
                ]))
        else:
            # Secure rows — green text on status
            detail_table.setStyle(TableStyle([
                ("TEXTCOLOR", (2, row_idx), (2, row_idx),
                 colors.HexColor('#00AA00')),
                ("FONTNAME", (2, row_idx), (2, row_idx), "Helvetica-Bold"),
            ]))

    story.append(detail_table)
    story.append(Spacer(1, 12))

    # ── RECOMMENDATIONS ──────────────────────────────────
    story.append(Paragraph("Recommendations", heading_style))
    story.append(Paragraph(
        "Based on the findings above, the following actions are recommended "
        "to improve the security of the AI system being tested:",
        normal_style))
    story.append(Spacer(1, 6))

    recommendations = [
        ("Implement strict input validation",
         "All inputs sent to the AI API should be checked and filtered before "
         "being processed. This prevents attackers from injecting malicious instructions."),
        ("Use system prompt hardening",
         "The AI's internal instructions (system prompt) should never be visible "
         "to end users. Treat it like a password — keep it secret."),
        ("Deploy output filtering",
         "All AI responses should be scanned before being shown to users. "
         "If sensitive information is detected in a response, block it automatically."),
        ("Implement rate limiting",
         "Limit how many requests can be made to the AI API per minute. "
         "This prevents automated attack tools from running thousands of tests."),
        ("Regularly update payloads and test",
         "New attack techniques are discovered every week. "
         "Run this scanner regularly with updated payloads to stay ahead of attackers."),
        ("Implement a semantic content filter",
         "Add an AI-powered filter that reads responses and flags anything that "
         "looks like it might be leaking sensitive information."),
        ("Monitor for unusual response patterns",
         "Set up alerts for when the AI gives unusually long responses or "
         "responses that match known vulnerability patterns."),
        ("Apply principle of least privilege",
         "The AI model should only be given the information it absolutely needs. "
         "The less it knows, the less it can accidentally reveal."),
    ]

    for i, (title, description) in enumerate(recommendations, 1):
        story.append(Paragraph(
            f"<b>{i}. {title}</b>", normal_style))
        story.append(Paragraph(
            f"   {description}", small_style))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 12))

    # ── FOOTER ───────────────────────────────────────────
    # ── FOOTER ───────────────────────────────────────────
    story.append(Spacer(1, 20))
    footer_data = [[
        f"AI Model Security Scanner  |  v{config.SCANNER_VERSION}",
        "Maryssa L.",
        "github.com/Gemz-AACT"
    ]]
    footer_table = Table(footer_data, colWidths=[200, 100, 160])
    footer_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor('#1A3A5C')),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("ALIGN", (2, 0), (2, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(footer_table)

    doc.build(story)
    print(f"\n[+] PDF Report saved to {filename}")