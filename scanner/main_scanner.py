from scanner.header_analyzer import analyze_headers
from scanner.port_scanner import scan_ports, get_service
from scanner.sqli_scanner import scan_sqli
from scanner.xss_scanner import scan_xss
from scanner.risk_engine import calculate_risk
from utils.report_generator import generate_report
from scanner.dir_bruteforce import dir_bruteforce
from scanner.utils.progress_tracker import update_progress, complete_scan, add_log

import traceback  # 🔥 IMPORTANT


def scan_target(url, scan_id=None):
    vulnerabilities = []
    safe_checks = []

    # -------------------------------
    # 🔥 LOGGER FUNCTION
    # -------------------------------
    def logger(msg):
        if scan_id:
            add_log(scan_id, msg)
        else:
            print(msg)

    try:
        # -------------------------------
        # 1. Header Analysis
        # -------------------------------
        if scan_id:
            update_progress(scan_id, 10, "running", "Analyzing headers...")

        logger("[+] Analyzing headers...")

        header_issues = analyze_headers(url) or []

        if header_issues:
            logger(f"[!] {len(header_issues)} header issues found")

            for issue in header_issues:
                vulnerabilities.append({
                    "type": "Header Issue",
                    "severity": "Medium",
                    "description": issue,
                    "url": url
                })
        else:
            logger("[+] Headers are secure")
            safe_checks.append("All important security headers are present")

        # -------------------------------
        # 2. Port Scan
        # -------------------------------
        if scan_id:
            update_progress(scan_id, 25, "running", "Scanning ports...")

        logger("[+] Starting port scan...")

        open_ports = scan_ports(url, logger=logger, mode="fast") or []

        if open_ports:
            logger(f"[!] Open ports found: {open_ports}")

            for port in open_ports:
                service = get_service(port)

                vulnerabilities.append({
                    "type": "Open Port",
                    "severity": "Low",
                    "description": f"Port {port} ({service}) is open",
                    "url": url
                })
        else:
            logger("[+] No risky ports found")
            safe_checks.append("No unnecessary open ports detected")

        # -------------------------------
        # 3. SQL Injection
        # -------------------------------
        if scan_id:
            update_progress(scan_id, 45, "running", "Testing SQL Injection...")

        logger("[+] Testing SQL Injection...")

        sqli_result = scan_sqli(url, logger)

        if sqli_result.get("vulnerable"):
            logger("[!] SQL Injection detected")

            payload = sqli_result.get("payload", "N/A")
            test_url = sqli_result.get("test_url", "N/A")
            evidence = sqli_result.get("evidence", "Unknown")

            vulnerabilities.append({
                "type": "SQL Injection",
                "severity": "High",
                "description": (
                    f"SQL Injection detected!\n\n"
                    f"Payload Used:\n{payload}\n\n"
                    f"Test URL:\n{test_url}\n\n"
                    f"Evidence:\nDatabase error keyword detected: {evidence}\n\n"
                    f"Impact:\nAttacker may extract or manipulate database data."
                ),
                "url": url
            })

            sqli_found = True
        else:
            logger("[+] No SQL Injection detected")
            safe_checks.append("No SQL Injection detected")
            sqli_found = False

        # -------------------------------
        # 4. XSS
        # -------------------------------
        if scan_id:
            update_progress(scan_id, 65, "running", "Testing XSS...")

        logger("[+] Testing XSS...")

        xss_found = scan_xss(url, logger)

        if xss_found:
            logger("[!] XSS vulnerability detected")

            vulnerabilities.append({
                "type": "XSS",
                "severity": "High",
                "description": "XSS vulnerability detected",
                "url": url
            })
        else:
            logger("[+] No XSS detected")
            safe_checks.append("No XSS detected")

        # -------------------------------
        # 5. Directory Bruteforce
        # -------------------------------
        if scan_id:
            update_progress(scan_id, 80, "running", "Bruteforcing directories...")

        logger("[+] Starting directory brute force...")

        found_dirs = dir_bruteforce(url, logger=logger, threads=20) or []

        if found_dirs:
            logger(f"[!] {len(found_dirs)} directories/files discovered")

            for d in found_dirs:
                # Handle BOTH cases (dict OR string)
                if isinstance(d, dict):
                    desc = f"{d.get('url')} → HTTP {d.get('status')} | {d.get('size')} bytes"
                else:
                    desc = f"{d} → Accessible endpoint found"

                vulnerabilities.append({
                    "type": "Directory Exposure",
                    "severity": "Low",
                    "description": desc,
                    "url": url
                })
        else:
            logger("[+] No sensitive directories found")
            safe_checks.append("No sensitive directories exposed")

        # -------------------------------
        # DEBUG LOG
        # -------------------------------
        print("\n===== DEBUG DATA =====")
        print("Open Ports:", open_ports)
        print("Header Issues:", header_issues)
        print("Dirs:", found_dirs)
        print("SQLi:", sqli_found)
        print("XSS:", xss_found)
        print("=====================\n")

        # -------------------------------
        # 6. Risk Calculation
        # -------------------------------
        if scan_id:
            update_progress(scan_id, 90, "running", "Calculating risk...")

        logger("[+] Calculating risk score...")

        risk_score, risk_level = calculate_risk(
            open_ports=open_ports,
            sqli=bool(sqli_found),
            xss=bool(xss_found),
            found_dirs=found_dirs,
            header_issues=header_issues
        )

        # 🔥 Convert to SECURITY SCORE
        security_score = round(max(1.5, 10 - risk_score), 1)

        logger(f"[+] Risk Score: {risk_score}/10 ({risk_level})")
        logger(f"[+] Security Score: {security_score}/10")

        # -------------------------------
        # 7. Recommendations
        # -------------------------------
        recommendations = []

        if header_issues:
            recommendations.append("Add security headers (CSP, X-Frame-Options, HSTS)")

        if open_ports:
            recommendations.append("Close unused ports or apply firewall rules")

        if sqli_found:
            recommendations.append("Use parameterized queries / ORM")

        if xss_found:
            recommendations.append("Sanitize and encode user inputs")

        if found_dirs:
            recommendations.append("Restrict access to sensitive directories")

        recommendations = list(set(recommendations))

        # -------------------------------
        # 8. Generate PDF
        # -------------------------------
        if scan_id:
            update_progress(scan_id, 95, "running", "Generating report...")

        logger("[+] Generating PDF report...")

        try:
            report_path = generate_report(
                url,
                security_score,
                risk_level,
                vulnerabilities,
                safe_checks,
                recommendations
            )
        except Exception as e:
            traceback.print_exc()  # 🔥 KEY FIX
            logger(f"[!] Report generation failed: {e}")
            report_path = None

        # -------------------------------
        # 9. Final Result
        # -------------------------------
        result = {
            "score": security_score,
            "risk": risk_level,
            "vulnerabilities": vulnerabilities,
            "safe_checks": safe_checks,
            "recommendations": recommendations,
            "report": report_path
        }

        logger("[✓] Scan completed successfully")

        if scan_id:
            complete_scan(scan_id, result)

        return result

    # -------------------------------
    # ❌ GLOBAL FAILURE HANDLER
    # -------------------------------
    except Exception as e:
        traceback.print_exc()

        logger(f"[❌] Scan crashed: {e}")

        if scan_id:
            complete_scan(scan_id, {
                "score": 0,
                "risk": "Error",
                "vulnerabilities": [],
                "safe_checks": ["Scan failed due to internal error"],
                "recommendations": [],
                "report": None
            })

        return None