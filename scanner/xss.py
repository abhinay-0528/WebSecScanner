"""
scanner/xss.py

Reflected XSS Detection Module (safe / non-exploitative).

Methodology:
  1. For every discovered URL that has query-string parameters, and
     for every GET form found by the crawler, substitute each
     parameter's value with a harmless, unique marker string.
  2. Re-request the page and check whether the marker is reflected
     back UNENCODED in the HTML response.
  3. If the raw marker (including angle brackets) appears verbatim,
     flag it as a potential reflected XSS point.

Important safety notes:
  * The payload used is an inert marker - it does not contain any
    <script> tag that would actually execute, and no browser/DOM
    execution is attempted. This module only checks for string
    reflection in the raw HTTP response body.
  * This is a heuristic indicator, not proof of exploitability -
    the report language reflects that ("possible reflected XSS").
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import uuid

from scanner import safe_get

MAX_URLS_TO_TEST = 15


def _build_marker():
    # Unique per-request marker so we can be certain a match came from OUR
    # request and not some coincidental existing content. Includes angle
    # brackets so we can also observe whether output encoding is applied,
    # but performs no actual script execution.
    token = uuid.uuid4().hex[:8]
    return f'"><xsschk{token}>', f"xsschk{token}"


def _test_url_params(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    for param_name in params:
        marker, needle = _build_marker()
        new_params = {k: (marker if k == param_name else v[0]) for k, v in params.items()}
        test_query = urlencode(new_params)
        test_url = urlunparse(parsed._replace(query=test_query))

        response = safe_get(test_url)
        if response is None:
            continue

        reflected_raw = marker in response.text
        reflected_encoded_only = (not reflected_raw) and (needle in response.text)

        if reflected_raw:
            findings.append({
                "vulnerability": "Possible Reflected XSS",
                "severity": "High",
                "url": test_url,
                "description": f"The parameter '{param_name}' is reflected in the response without "
                                f"apparent HTML-encoding of special characters.",
                "evidence": f"Injected marker containing angle brackets was found unescaped in the "
                            f"response body for parameter '{param_name}'.",
                "recommendation": "Apply context-appropriate output encoding (HTML entity encoding) "
                                   "to all user-controlled data rendered into HTML responses, and "
                                   "consider a Content-Security-Policy as defense in depth.",
                "category": "Reflected XSS",
            })
        elif reflected_encoded_only:
            findings.append({
                "vulnerability": "Parameter Reflected (Encoded)",
                "severity": "Informational",
                "url": test_url,
                "description": f"The parameter '{param_name}' is reflected in the response, but "
                                f"special characters appear to be encoded, which mitigates XSS risk.",
                "evidence": f"Marker token found in response body without raw angle brackets for "
                            f"parameter '{param_name}'.",
                "recommendation": "No action required if encoding is consistently applied; continue "
                                   "to validate on any output-context changes (HTML, JS, URL, attribute).",
                "category": "Reflected XSS",
            })

    return findings


def scan(urls, forms):
    findings = []
    tested = 0

    # Test query-string parameters on crawled URLs
    for url in urls:
        if tested >= MAX_URLS_TO_TEST:
            break
        if "?" not in url:
            continue
        findings.extend(_test_url_params(url))
        tested += 1

    # Test GET forms (POST forms are not auto-submitted to avoid side effects)
    for form in forms:
        if tested >= MAX_URLS_TO_TEST:
            break
        if form["method"] != "GET" or not form["inputs"]:
            continue
        query_params = {i["name"]: "test" for i in form["inputs"] if i["name"]}
        if not query_params:
            continue
        test_url = form["action"] + ("&" if "?" in form["action"] else "?") + urlencode(query_params)
        findings.extend(_test_url_params(test_url))
        tested += 1

    if not findings:
        findings.append({
            "vulnerability": "No Reflected XSS Indicators Found",
            "severity": "Informational",
            "url": "",
            "description": f"Tested {tested} parameterized endpoint(s) for reflected XSS; no raw "
                            f"reflection of injected markers was observed.",
            "evidence": "N/A",
            "recommendation": "Continue to apply output encoding as a matter of secure-by-default practice.",
            "category": "Reflected XSS",
        })

    return findings
