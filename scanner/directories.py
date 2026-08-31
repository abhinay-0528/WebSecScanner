"""
scanner/directories.py

Lightweight Directory Discovery Module.

Checks for the existence of a small, built-in list of commonly used
directory/path names using simple GET requests. This is intentionally
a SMALL wordlist (not a full brute-force dirbuster-style wordlist) to
keep the scan fast and low-impact on the target server.
"""

from urllib.parse import urljoin

from scanner import safe_get

WORDLIST = [
    "admin", "administrator", "dashboard", "backup", "backups", "uploads",
    "test", "staging", "dev", "api", "login", "old", "tmp", "private",
    "config", "logs", "data", "assets", "scripts", "console",
]

# path -> risk level for when found
DEFAULT_RISK = "Low"
HIGH_RISK_PATHS = {"admin", "administrator", "config", "backup", "backups", "console"}


def discover(target_url):
    findings = []
    base = target_url if target_url.endswith("/") else target_url + "/"

    for path in WORDLIST:
        full_url = urljoin(base, path + "/")
        response = safe_get(full_url, allow_redirects=False)

        if response is None:
            continue

        if response.status_code in (200, 201, 301, 302, 401, 403):
            risk = "Medium" if path in HIGH_RISK_PATHS else DEFAULT_RISK
            status_note = {
                401: "requires authentication (path exists)",
                403: "forbidden (path exists but access denied)",
                301: "redirects (path likely exists)",
                302: "redirects (path likely exists)",
            }.get(response.status_code, "publicly accessible")

            findings.append({
                "vulnerability": f"Discoverable Path: /{path}/",
                "severity": risk,
                "url": full_url,
                "description": f"The path '/{path}/' exists on the server and is {status_note}.",
                "evidence": f"HTTP {response.status_code}",
                "recommendation": "Ensure sensitive/administrative paths are not predictably named, "
                                   "are properly access-controlled, and are not indexed by search engines.",
                "category": "Directory Discovery",
            })

    if not findings:
        findings.append({
            "vulnerability": "No Additional Directories Discovered",
            "severity": "Informational",
            "url": target_url,
            "description": f"Tested {len(WORDLIST)} common path names; none were found to exist.",
            "evidence": "N/A",
            "recommendation": "N/A",
            "category": "Directory Discovery",
        })

    return findings
