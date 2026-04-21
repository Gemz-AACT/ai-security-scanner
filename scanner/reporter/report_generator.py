from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def generate_report(results, timestamp):
    filename = f"{config.REPORT_OUTPUT_DIR}AI_Security_Report_{timestamp}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(
        config.SCANNER_NAME, styles["Title"]))
    story.append(Paragraph(
        f"Version: {config.SCANNER_VERSION} | Author: {config.SCANNER_AUTHOR}",
        styles["Normal"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]))
    story.append(Spacer(1, 20))

    # Summary
    total = len(results)
    vulnerable = len([r for r in results if r["vulnerable"]])
    safe = total - vulnerable

    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    story.append(Paragraph(f"Total Tests Run: {total}", styles["Normal"]))
    story.append(Paragraph(
        f"Vulnerabilities Found: {vulnerable}", styles["Normal"]))
    story.append(Paragraph(f"Tests Passed: {safe}", styles["Normal"]))
    story.append(Spacer(1, 20))

    # Results table
    story.append(Paragraph("Detailed Results", styles["Heading1"]))
    story.append(Spacer(1, 10))

    data = [["Test Type", "Payload", "Vulnerable"]]
    for r in results:
        data.append([
            r["test"],
            r["payload"][:60] + "...",
            "YES" if r["vulnerable"] else "NO"
        ])

    table = Table(data, colWidths=[120, 300, 80])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 11),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.lightgrey]),
        ("TEXTCOLOR", (-1, 1), (-1, -1), colors.red),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    # Recommendations
    story.append(Paragraph("Recommendations", styles["Heading1"]))
    story.append(Paragraph(
        "1. Implement strict input validation on all AI API endpoints.",
        styles["Normal"]))
    story.append(Paragraph(
        "2. Use system prompt hardening to prevent prompt injection.",
        styles["Normal"]))
    story.append(Paragraph(
        "3. Never expose system prompts or internal configurations.",
        styles["Normal"]))
    story.append(Paragraph(
        "4. Implement rate limiting to prevent abuse.",
        styles["Normal"]))
    story.append(Paragraph(
        "5. Regularly test AI models for new jailbreak techniques.",
        styles["Normal"]))

    doc.build(story)
    print(f"\n[+] PDF Report saved to {filename}")