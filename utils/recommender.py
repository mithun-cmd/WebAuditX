def get_recommendations(header_issues, sqli, xss, found_dirs, open_ports):
    recommendations = []

    # Header fixes
    for issue in header_issues:
        if "Content-Security-Policy" in issue:
            recommendations.append("Add Content-Security-Policy header to prevent XSS attacks.")
        elif "X-Frame-Options" in issue:
            recommendations.append("Add X-Frame-Options to prevent clickjacking.")
        elif "X-Content-Type-Options" in issue:
            recommendations.append("Add X-Content-Type-Options to prevent MIME sniffing.")
        elif "HSTS" in issue:
            recommendations.append("Enable Strict-Transport-Security (HSTS) for HTTPS enforcement.")

    # SQLi
    if sqli:
        recommendations.append("Use parameterized queries / prepared statements to prevent SQL Injection.")

    # XSS
    if xss:
        recommendations.append("Sanitize user inputs and use output encoding to prevent XSS.")

    # Directory exposure
    if found_dirs:
        recommendations.append("Restrict access to sensitive directories (admin, backup, etc.).")

    # Open ports
    if len(open_ports) > 2:
        recommendations.append("Close unnecessary open ports or use firewall rules.")

    return recommendations