def calculate_risk(open_ports, sqli, xss, found_dirs, header_issues):
    score = 0.0

    # -------------------------------
    # 🔴 CRITICAL VULNERABILITIES
    # -------------------------------
    if sqli:
        score += 7.5   # SQL Injection = very high impact

    if xss:
        score += 5.5   # XSS = moderate-high impact

    # -------------------------------
    # 🟠 DANGEROUS PORT EXPOSURE
    # -------------------------------
    dangerous_ports = [6379, 3306, 21, 22]  # Redis, MySQL, FTP, SSH

    for port in open_ports:
        if port in dangerous_ports:
            score += 1.5   # high risk if exposed

    # Normal ports (low impact)
    score += min(len(open_ports) * 0.3, 1.5)

    # -------------------------------
    # 🟡 HEADER MISCONFIGURATIONS
    # -------------------------------
    header_score = min(len(header_issues) * 0.4, 2.5)
    score += header_score

    # -------------------------------
    # 🟢 DIRECTORY EXPOSURE
    # -------------------------------
    dir_score = 0

    for d in found_dirs:
        d_str = str(d).lower()

        if "config" in d_str or "admin" in d_str:
            dir_score += 1.5   # sensitive
        else:
            dir_score += 0.5   # normal

    score += min(dir_score, 2)

    # -------------------------------
    # ⚖️ FINAL NORMALIZATION
    # -------------------------------
    score = min(score, 10)

    # -------------------------------
    # 🎯 RISK LEVEL CLASSIFICATION
    # -------------------------------
    if score >= 8:
        level = "Critical"
    elif score >= 6:
        level = "High"
    elif score >= 4:
        level = "Medium"
    elif score >= 2:
        level = "Low"
    else:
        level = "Safe"

    return round(score, 1), level