import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

# -------------------------------
# WORDLIST (Optimized)
# -------------------------------
COMMON_DIRS = [
    "admin", "admin/login", "login", "dashboard", "panel",
    "backup", "backups", "old", "temp", "private",
    "api", "v1", "v2",
    "uploads", "files", "images",
    "test", "dev", "staging",
    ".git", ".env",
    "phpmyadmin", "adminer",
    "wp-admin", "wp-content",
    "config", "settings"
]

# -------------------------------
# FILE EXTENSIONS
# -------------------------------
EXTENSIONS = ["", ".php", ".html", ".bak", ".zip", ".old"]

# -------------------------------
# REQUEST HEADERS (avoid blocking)
# -------------------------------
HEADERS = {
    "User-Agent": "WebAuditX-Scanner/1.0",
    "Accept": "*/*",
    "Connection": "close"
}


# -------------------------------
# CHECK SINGLE PATH
# -------------------------------
def check_path(base_url, path, timeout=3):
    url = urljoin(base_url + "/", path)

    try:
        res = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=False)

        content_length = len(res.content)

        # Smart filtering
        if res.status_code in [200, 301, 302, 403] and content_length > 50:
            return {
                "url": url,
                "status": res.status_code,
                "size": content_length
            }

    except requests.RequestException:
        return None

    return None


# -------------------------------
# MAIN BRUTEFORCE
# -------------------------------
def dir_bruteforce(base_url, logger=None, threads=20):

    if logger:
        logger("[+] Starting directory brute force...")

    found = []

    # Generate paths (dir + extensions)
    paths = []
    for d in COMMON_DIRS:
        for ext in EXTENSIONS:
            paths.append(d + ext)

    # Remove duplicates
    paths = list(set(paths))

    if logger:
        logger(f"[+] Total paths to scan: {len(paths)}")

    # Threaded execution
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: check_path(base_url, p), paths)

    for res in results:
        if res:
            found.append(res["url"])

            if logger:
                logger(f"[!] Found: {res['url']} (Status: {res['status']}, Size: {res['size']})")

    if logger:
        if found:
            logger(f"[+] Found {len(found)} potential directories/files")
        else:
            logger("[+] No sensitive directories found")

    return found