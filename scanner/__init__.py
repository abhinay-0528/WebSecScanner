"""
scanner package

Each module in this package implements ONE detection technique
(security headers, SSL/TLS, sensitive files, forms, reflected XSS,
SQL injection error detection, open redirects, directory discovery).

Design principles followed across every module:
  * READ-ONLY / NON-DESTRUCTIVE: modules only send GET/HEAD/benign
    requests. No exploitation, brute forcing of credentials, or
    denial-of-service style requests are performed.
  * All test payloads are harmless markers used purely to detect
    reflection or error signatures, never to actually exploit a flaw.
  * Every module returns a list of plain dict "findings" so app.py
    can persist them uniformly via database.db.add_finding().
"""

import requests

# A single shared timeout/user-agent policy for every outbound request
# made by any scanner module.
DEFAULT_TIMEOUT = 8
USER_AGENT = "WebAppSecurityScanner/1.0 (+educational-portfolio-project; non-destructive scanner)"

HEADERS = {"User-Agent": USER_AGENT}


def safe_get(url, allow_redirects=True, timeout=DEFAULT_TIMEOUT, **kwargs):
    """Wrapper around requests.get that never raises - returns None on failure."""
    try:
        return requests.get(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=kwargs.pop("verify", True),
            **kwargs,
        )
    except requests.exceptions.RequestException:
        return None


def safe_head(url, allow_redirects=True, timeout=DEFAULT_TIMEOUT):
    try:
        return requests.head(
            url, headers=HEADERS, timeout=timeout, allow_redirects=allow_redirects
        )
    except requests.exceptions.RequestException:
        return None
