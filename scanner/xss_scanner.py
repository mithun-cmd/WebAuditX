import requests

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]


def scan_xss(url, logger=None):
    if logger:
        logger("[+] Testing for XSS...")
    else:
        print("\n[+] Testing for XSS...\n")

    for payload in XSS_PAYLOADS:
        test_url = f"{url}?q={payload}"

        try:
            response = requests.get(test_url, timeout=5)

            if payload in response.text:
                msg = f"[!] XSS detected with payload: {payload}"

                if logger:
                    logger(msg)
                else:
                    print(msg)

                return True

        except Exception:
            continue

    if logger:
        logger("[+] No XSS detected")
    else:
        print("[+] No XSS detected")

    return False