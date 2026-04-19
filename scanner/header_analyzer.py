import requests
from urllib.parse import urlparse


def analyze_headers(url):
    issues = []

    try:
        response = requests.get(url, timeout=8)
        headers = {k.lower(): v for k, v in response.headers.items()}

    except requests.exceptions.RequestException:
        return ["Could not connect to target (Timeout / Blocked / Invalid URL)"]

    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    # -------------------------------
    # 1. Content Security Policy (CSP)
    # -------------------------------
    if "content-security-policy" not in headers:
        issues.append("Missing Content-Security-Policy")
    else:
        csp = headers["content-security-policy"]
        if "*" in csp:
            issues.append("Weak CSP: Wildcard (*) detected")

    # -------------------------------
    # 2. X-Frame-Options
    # -------------------------------
    if "x-frame-options" not in headers:
        issues.append("Missing X-Frame-Options")
    else:
        xfo = headers["x-frame-options"].lower()
        if xfo not in ["deny", "sameorigin"]:
            issues.append("Weak X-Frame-Options configuration")

    # -------------------------------
    # 3. X-Content-Type-Options
    # -------------------------------
    if "x-content-type-options" not in headers:
        issues.append("Missing X-Content-Type-Options")
    else:
        if headers["x-content-type-options"].lower() != "nosniff":
            issues.append("Improper X-Content-Type-Options (should be 'nosniff')")

    # -------------------------------
    # 4. HSTS (Strict-Transport-Security)
    # -------------------------------
    if is_https:
        if "strict-transport-security" not in headers:
            issues.append("Missing HSTS")
        else:
            hsts = headers["strict-transport-security"]

            if "max-age" not in hsts:
                issues.append("Weak HSTS: Missing max-age")

            if "includeSubDomains" not in hsts:
                issues.append("HSTS missing includeSubDomains")

    else:
        # Smart behavior
        issues.append("HSTS not applicable (HTTP site)")

    # -------------------------------
    # 5. X-XSS-Protection (legacy but informative)
    # -------------------------------
    if "x-xss-protection" in headers:
        if headers["x-xss-protection"] == "0":
            issues.append("X-XSS-Protection disabled")

    # -------------------------------
    # 6. Server Information Disclosure
    # -------------------------------
    if "server" in headers:
        issues.append(f"Server reveals technology: {headers['server']}")

    if "x-powered-by" in headers:
        issues.append(f"X-Powered-By reveals technology: {headers['x-powered-by']}")

    return issues