"""
scanner/info_gathering.py

Passive information gathering module.

Collects publicly-visible information about the target from the HTTP
response of the homepage only: page title, server banner, response
headers, HTTP status code, and a very small heuristic "technology
detection" pass based on header/HTML fingerprints. This is entirely
passive - a single GET request to the target.
"""

import re
from bs4 import BeautifulSoup

from scanner import safe_get

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Django": [r"csrfmiddlewaretoken"],
    "Laravel": [r"laravel_session"],
    "React": [r"__reactContainer|react-root|data-reactroot"],
    "Bootstrap": [r"bootstrap(\.min)?\.css|bootstrap(\.min)?\.js"],
    "jQuery": [r"jquery(\.min)?\.js"],
    "PHP": [r"\.php(\?|\"|')"],
    "ASP.NET": [r"__VIEWSTATE|\.aspx"],
    "Nginx": [],   # detected via Server header instead
    "Apache": [],
    "Cloudflare": [],
}


def gather(target_url):
    """
    Returns a dict of information gathered about the target, and a list
    of Informational-severity findings ready for storage.
    """
    findings = []
    info = {
        "title": None,
        "server": None,
        "status_code": None,
        "headers": {},
        "technologies": [],
    }

    response = safe_get(target_url)
    if response is None:
        findings.append({
            "vulnerability": "Target Unreachable",
            "severity": "Informational",
            "url": target_url,
            "description": "The target did not respond to an initial information-gathering request.",
            "evidence": "No HTTP response received.",
            "recommendation": "Verify the target URL is correct and publicly accessible.",
            "category": "Information Gathering",
        })
        return info, findings

    info["status_code"] = response.status_code
    info["headers"] = dict(response.headers)
    info["server"] = response.headers.get("Server", "Not disclosed")

    soup = BeautifulSoup(response.text, "html.parser")
    info["title"] = soup.title.string.strip() if soup.title and soup.title.string else "(no title found)"

    body_sample = response.text[:20000]

    detected = []
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, body_sample, re.IGNORECASE):
                detected.append(tech)
                break

    server_header = info["server"].lower()
    if "nginx" in server_header:
        detected.append("Nginx")
    if "apache" in server_header:
        detected.append("Apache")
    if "cloudflare" in server_header:
        detected.append("Cloudflare")

    info["technologies"] = sorted(set(detected))

    findings.append({
        "vulnerability": "Information Gathering Summary",
        "severity": "Informational",
        "url": target_url,
        "description": f"Page title: '{info['title']}'. HTTP status: {info['status_code']}.",
        "evidence": f"Server header: {info['server']}. Technologies detected: "
                    f"{', '.join(info['technologies']) or 'none identified'}.",
        "recommendation": "Avoid disclosing detailed server/technology version information in "
                           "response headers where possible (e.g. via 'Server' or 'X-Powered-By').",
        "category": "Information Gathering",
    })

    if "X-Powered-By" in response.headers:
        findings.append({
            "vulnerability": "X-Powered-By Header Disclosure",
            "severity": "Low",
            "url": target_url,
            "description": "The X-Powered-By header discloses backend technology details to any visitor.",
            "evidence": f"X-Powered-By: {response.headers['X-Powered-By']}",
            "recommendation": "Remove or suppress the X-Powered-By header at the server/framework level.",
            "category": "Information Gathering",
        })

    return info, findings
