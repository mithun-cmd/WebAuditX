from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import Paragraph
from datetime import datetime
import os

# ✅ IMPORTANT: ESCAPE HTML
from xml.sax.saxutils import escape


def generate_report(target, score, level, vulnerabilities, safe_checks, recs):

    os.makedirs("reports", exist_ok=True)

    clean_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    file_path = f"reports/{clean_target}.pdf"

    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()

    # -------------------------------
    # 🎨 STYLES
    # -------------------------------
    title_style = ParagraphStyle(
        name="TitleStyle",
        fontSize=22,
        leading=26,
        alignment=1,
        spaceAfter=20
    )

    section_style = ParagraphStyle(
        name="SectionStyle",
        fontSize=14,
        leading=18,
        spaceAfter=12,
        textColor=colors.darkblue
    )

    normal = styles["Normal"]

    content = []

    # -------------------------------
    # 🚀 TITLE
    # -------------------------------
    content.append(Paragraph("WebAuditX Security Assessment Report", title_style))

    # -------------------------------
    # 🎯 SAFE DATA (VERY IMPORTANT)
    # -------------------------------
    safe_target = escape(str(target))
    safe_level = escape(str(level))

    # -------------------------------
    # 🎯 RISK COLOR
    # -------------------------------
    risk_color = {
        "Critical": colors.red,
        "High": colors.orange,
        "Medium": colors.gold,
        "Low": colors.green,
        "Safe": colors.darkgreen
    }.get(level, colors.grey)

    # -------------------------------
    # 📊 INFO TABLE
    # -------------------------------
    info_table = Table([
        ["Target", safe_target],
        ["Scan Date", datetime.now().strftime('%d-%m-%Y %H:%M')],
        ["Security Score", f"{score}/10"],
        ["Risk Level", safe_level]
    ], colWidths=[130, 330])

    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

        ("BACKGROUND", (0, 3), (-1, 3), risk_color),
        ("TEXTCOLOR", (0, 3), (-1, 3), colors.white),
    ]))

    content.append(info_table)

    content.append(Spacer(1, 10))
    content.append(Paragraph(
        "Note: Higher score indicates better security posture.",
        styles["Italic"]
    ))

    content.append(Spacer(1, 20))

    # -------------------------------
    # 🧠 EXECUTIVE SUMMARY
    # -------------------------------
    content.append(Paragraph("Executive Summary", section_style))

    summary_map = {
        "Critical": "The target system is critically vulnerable and requires immediate remediation.",
        "High": "The system contains high-risk vulnerabilities that could lead to compromise.",
        "Medium": "The system has moderate vulnerabilities that should be addressed soon.",
        "Low": "The system has minor issues and follows most security best practices.",
        "Safe": "The system appears secure with minimal risk exposure."
    }

    content.append(Paragraph(summary_map.get(level, "Unknown risk level."), normal))
    content.append(Spacer(1, 20))

    # -------------------------------
    # 📊 FINDINGS SUMMARY
    # -------------------------------
    high = len([v for v in vulnerabilities if v["severity"] == "High"])
    medium = len([v for v in vulnerabilities if v["severity"] == "Medium"])
    low = len([v for v in vulnerabilities if v["severity"] == "Low"])

    content.append(Paragraph("Findings Summary", section_style))

    summary_table = Table([
        ["Severity", "Count"],
        ["High", high],
        ["Medium", medium],
        ["Low", low]
    ], colWidths=[120, 100])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

        ("BACKGROUND", (0, 1), (0, 1), colors.red),
        ("BACKGROUND", (0, 2), (0, 2), colors.orange),
        ("BACKGROUND", (0, 3), (0, 3), colors.green),
        ("TEXTCOLOR", (0, 1), (0, 3), colors.white),
    ]))

    content.append(summary_table)
    content.append(Spacer(1, 20))

    # -------------------------------
    # 🔴 VULNERABILITIES
    # -------------------------------
    content.append(Paragraph("Detailed Findings", section_style))

    if vulnerabilities:
        table_data = [["Type", "Severity", "Description"]]

        for v in vulnerabilities:
            table_data.append([
                Paragraph(escape(str(v["type"])), normal),
                Paragraph(escape(str(v["severity"])), normal),
                Paragraph(escape(str(v["description"])).replace("\n", "<br/>"), normal)
            ])

        table = Table(table_data, colWidths=[130, 80, 250])

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (1, 1), (1, -1), "CENTER"),
        ]))

        content.append(table)
    else:
        content.append(Paragraph("No vulnerabilities found.", normal))

    content.append(Spacer(1, 20))

    # -------------------------------
    # ✅ SAFE CHECKS
    # -------------------------------
    content.append(Paragraph("Passed Security Checks", section_style))

    for check in safe_checks:
        content.append(Paragraph(f"• {escape(str(check))}", normal))

    content.append(Spacer(1, 20))

    # -------------------------------
    # 🛠 RECOMMENDATIONS
    # -------------------------------
    content.append(Paragraph("Recommendations", section_style))

    for rec in recs:
        content.append(Paragraph(f"- {escape(str(rec))}", normal))

    content.append(Spacer(1, 30))

    # -------------------------------
    # 📌 FOOTER
    # -------------------------------
    content.append(Paragraph(
        "Generated by WebAuditX • Automated Security Scanner",
        styles["Italic"]
    ))

    # ✅ FINAL BUILD
    doc.build(content)

    return file_path