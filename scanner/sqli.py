"""
scanner/sqli.py

SQL Injection Error-Detection Module (non-destructive).

Methodology:
  1. For URLs with query parameters, substitute each parameter's value
     with a small set of BENIGN characters known to commonly trigger
     a database error if the value is concatenated unsafely into a
     SQL query (e.g. a single quote, or a harmless boolean-altering
     expression).
  2. Inspect the response body for well-known database error-message
     signatures (MySQL, PostgreSQL, MSSQL, SQLite, generic ODBC/JDBC).
  3. Report a possible indicator - this module never attempts to
     extract data, use UNION-based extraction, time-based blind
     techniques, or any destructive/write statement. It performs
     read-only, single-character-class probes only.

This is intentionally limited to ERROR-based detection, which is the
safest and least invasive SQLi testing technique.
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner import safe_get

MAX_URLS_TO_TEST = 15

# Benign probe values - a lone quote / boolean tautology, nothing destructive
PROBES = ["'", "\"", "')", "' OR '1'='1", "1'"]

# Database error fingerprint -> engine name
ERROR_SIGNATURES = {
    "you have an error in your sql syntax": "MySQL",
    "warning: mysql": "MySQL",
    "unclosed quotation mark after the character string": "MSSQL",
    "microsoft ole db provider for sql server": "MSSQL",
    "unclosed quotation mark": "MSSQL",
    "pg_query()": "PostgreSQL",
    "postgresql query failed": "PostgreSQL",
    "sqlstate": "PostgreSQL",
    "sqlite3::query": "SQLite",
    "sqlite3.operationalerror": "SQLite",
    "near \"": "SQLite",
    "odbc sql server driver": "MSSQL",
    "supplied argument is not a valid mysql": "MySQL",
    "syntax error at or near": "PostgreSQL",
}


def _detect_signature(body):
    lowered = body.lower()
    for signature, engine in ERROR_SIGNATURES.items():
        if signature in lowered:
            return engine, signature
    return None, None


def _test_url_params(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    for param_name in params:
        for probe in PROBES:
            new_params = {k: (probe if k == param_name else v[0]) for k, v in params.items()}
            test_query = urlencode(new_params)
            test_url = urlunparse(parsed._replace(query=test_query))

            response = safe_get(test_url)
            if response is None:
                continue

            engine, signature = _detect_signature(response.text)
            if engine:
                findings.append({
                    "vulnerability": "Possible SQL Injection (Error-Based Indicator)",
                    "severity": "High",
                    "url": test_url,
                    "description": f"Submitting a benign probe value to parameter '{param_name}' "
                                    f"produced a response containing a {engine} error signature, "
                                    f"suggesting the input may be concatenated unsafely into a SQL query.",
                    "evidence": f"Probe used: {probe!r}. Matched error fragment: '{signature}'.",
                    "recommendation": "Use parameterized queries / prepared statements for all "
                                       "database access, and ensure verbose database errors are never "
                                       "returned to the client.",
                    "category": "SQL Injection",
                })
                # One confirmed indicator per parameter is enough - stop probing further
                break

    return findings


def scan(urls):
    findings = []
    tested = 0

    for url in urls:
        if tested >= MAX_URLS_TO_TEST:
            break
        if "?" not in url:
            continue
        findings.extend(_test_url_params(url))
        tested += 1

    if not findings:
        findings.append({
            "vulnerability": "No SQL Injection Error Indicators Found",
            "severity": "Informational",
            "url": "",
            "description": f"Tested {tested} parameterized endpoint(s) with benign probe values; "
                            f"no known database error signatures were observed in responses.",
            "evidence": "N/A",
            "recommendation": "This does not rule out blind or logic-based SQL injection; "
                               "manual/authorized penetration testing is recommended for full coverage.",
            "category": "SQL Injection",
        })

    return findings
