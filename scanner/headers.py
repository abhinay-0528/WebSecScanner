"""
scanner/headers.py

Security Headers Scanner.

Checks a single response from the target for the presence of
recommended HTTP security headers, and produces a finding (with risk
explanation and remediation guidance) for every header that is
missing or misconfigured.
"""

from scanner import safe_get

# header_name -> (severity_if_missing, risk_explanation, remediation_guidance)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "Without a CSP, the browser has no restriction on which scripts/resources can execute, "
        "increasing the impact of any XSS vulnerability.",
        "Define a Content-Security-Policy header that whitelists trusted script/style/image sources.",
    ),
    "X-Frame-Options": (
        "Medium",
        "The site can be embedded in an <iframe> on another site, enabling clickjacking attacks.",
        "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or use CSP frame-ancestors).",
    ),
    "X-Content-Type-Options": (
        "Low",
        "Browsers may MIME-sniff responses, which can lead to content being interpreted in "
        "unintended, potentially unsafe ways.",
        "Set 'X-Content-Type-Options: nosniff' on all responses.",
    ),
    "Referrer-Policy": (
        "Low",
        "Full referrer URLs (which may contain sensitive path/query data) can leak to third parties "
        "when users click outbound links.",
        "Set a restrictive Referrer-Policy, e.g. 'strict-origin-when-cross-origin' or 'no-referrer'.",
    ),
    "Permissions-Policy": (
        "Low",
        "Without this header, browser features (camera, microphone, geolocation, etc.) are not "
        "explicitly restricted for embedded/third-party content.",
        "Set a Permissions-Policy header restricting powerful browser features to trusted origins only.",
    ),
    "Strict-Transport-Security": (
        "Medium",
        "Without HSTS, users can be downgraded to plain HTTP by an attacker performing a "
        "man-in-the-middle / SSL-stripping attack.",
        "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' once HTTPS is confirmed stable.",
    ),
}


def scan(target_url):
    findings = []
    response = safe_get(target_url)

    if response is None:
        return findings

    present = {}
    missing = {}

    for header, (severity, risk, remediation) in SECURITY_HEADERS.items():
        if header in response.headers:
            present[header] = response.headers[header]
        else:
            missing[header] = (severity, risk, remediation)

    for header, (severity, risk, remediation) in missing.items():
        findings.append({
            "vulnerability": f"Missing Security Header: {header}",
            "severity": severity,
            "url": target_url,
            "description": risk,
            "evidence": f"'{header}' was not present in the HTTP response headers.",
            "recommendation": remediation,
            "category": "Security Headers",
        })

    if present:
        findings.append({
            "vulnerability": "Security Headers Present",
            "severity": "Informational",
            "url": target_url,
            "description": f"{len(present)} of {len(SECURITY_HEADERS)} recommended security headers were found.",
            "evidence": ", ".join(f"{k}: {v}" for k, v in present.items()),
            "recommendation": "Continue to maintain these headers and review their values periodically.",
            "category": "Security Headers",
        })

    return findings
