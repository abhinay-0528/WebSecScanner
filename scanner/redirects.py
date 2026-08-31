"""
scanner/redirects.py

Open Redirect Detection Module.

Looks at discovered URLs for query parameters commonly used to hold a
redirect target (e.g. 'next', 'url', 'redirect', 'return'). For each
candidate, substitutes an external, harmless test domain and checks
whether the server issues a redirect (3xx + Location header) pointing
to that external domain - which would indicate an open redirect
vulnerability usable for phishing.
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner import safe_get

REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_uri", "redirect_url", "next", "url", "return",
    "return_url", "returnurl", "continue", "dest", "destination", "target", "out", "view",
}

# Neutral, non-malicious test domain used purely to observe redirect BEHAVIOR
TEST_EXTERNAL_DOMAIN = "https://example.com/oredirect-test"

MAX_URLS_TO_TEST = 20


def scan(urls):
    findings = []
    tested = 0

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        candidate_params = [p for p in params if p.lower() in REDIRECT_PARAM_NAMES]

        if not candidate_params or tested >= MAX_URLS_TO_TEST:
            continue

        for param_name in candidate_params:
            new_params = {
                k: (TEST_EXTERNAL_DOMAIN if k == param_name else v[0]) for k, v in params.items()
            }
            test_query = urlencode(new_params)
            test_url = urlunparse(parsed._replace(query=test_query))

            response = safe_get(test_url, allow_redirects=False)
            tested += 1
            if response is None:
                continue

            location = response.headers.get("Location", "")
            if response.status_code in (301, 302, 303, 307, 308) and TEST_EXTERNAL_DOMAIN in location:
                findings.append({
                    "vulnerability": "Open Redirect",
                    "severity": "Medium",
                    "url": test_url,
                    "description": f"The parameter '{param_name}' controls a redirect destination, and "
                                    f"the application redirected to an attacker-supplied external URL "
                                    f"without validation.",
                    "evidence": f"HTTP {response.status_code}, Location: {location}",
                    "recommendation": "Validate redirect targets against an allow-list of internal paths, "
                                       "or avoid user-controlled redirect destinations entirely.",
                    "category": "Open Redirect",
                })

    if not findings and tested > 0:
        findings.append({
            "vulnerability": "No Open Redirect Indicators Found",
            "severity": "Informational",
            "url": "",
            "description": f"Tested {tested} redirect-like parameter(s); none redirected to the "
                            f"external test domain.",
            "evidence": "N/A",
            "recommendation": "N/A",
            "category": "Open Redirect",
        })

    return findings
