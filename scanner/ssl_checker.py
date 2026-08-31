"""
scanner/ssl_checker.py

SSL/TLS Analyzer.

Checks:
  * Whether HTTPS is available at all for the target host
  * Certificate validity window (not-before / not-after)
  * Days remaining until expiration
  * Whether the certificate appears to be self-signed

Uses Python's built-in ssl/socket modules to fetch and parse the
certificate directly - no external network scanning tools, and no
attempt is made to exploit or downgrade the connection.
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

from scanner import safe_get

CERT_TIMEOUT = 6


def _parse_cert_date(date_str):
    # certificate dates look like 'Jun  1 12:00:00 2026 GMT'
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")


def analyze(target_url):
    findings = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or 443

    risk_score = 0  # 0 = best, higher = worse

    # 1. Does HTTPS even work?
    https_url = target_url if parsed.scheme == "https" else target_url.replace("http://", "https://", 1)
    https_response = safe_get(https_url, timeout=CERT_TIMEOUT)

    if https_response is None:
        findings.append({
            "vulnerability": "HTTPS Not Available",
            "severity": "High",
            "url": target_url,
            "description": "The target does not appear to support HTTPS, or the HTTPS endpoint "
                            "could not be reached. Traffic may be transmitted in plaintext.",
            "evidence": f"Connection to {https_url} failed or was refused.",
            "recommendation": "Deploy a valid TLS certificate and enforce HTTPS for all traffic.",
            "category": "SSL/TLS",
        })
        return findings

    # 2. Inspect the certificate itself
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=CERT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = _parse_cert_date(cert["notAfter"])
        not_before = _parse_cert_date(cert["notBefore"])
        days_remaining = (not_after - datetime.utcnow()).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        is_self_signed = issuer.get("commonName") == subject.get("commonName")

        findings.append({
            "vulnerability": "TLS Certificate Information",
            "severity": "Informational",
            "url": target_url,
            "description": f"Certificate valid from {not_before.date()} to {not_after.date()} "
                            f"({days_remaining} days remaining).",
            "evidence": f"Issuer CN: {issuer.get('commonName', 'unknown')}, "
                        f"Subject CN: {subject.get('commonName', 'unknown')}",
            "recommendation": "No action needed if the certificate is from a trusted CA and renewed "
                               "well before expiration.",
            "category": "SSL/TLS",
        })

        if days_remaining < 0:
            findings.append({
                "vulnerability": "Expired TLS Certificate",
                "severity": "High",
                "url": target_url,
                "description": "The TLS certificate has already expired, which will cause browser "
                                "warnings and may break HTTPS connections entirely.",
                "evidence": f"Certificate expired on {not_after.date()}.",
                "recommendation": "Renew the TLS certificate immediately.",
                "category": "SSL/TLS",
            })
            risk_score += 3
        elif days_remaining < 30:
            findings.append({
                "vulnerability": "TLS Certificate Expiring Soon",
                "severity": "Medium",
                "url": target_url,
                "description": f"The TLS certificate expires in {days_remaining} days.",
                "evidence": f"Certificate expires on {not_after.date()}.",
                "recommendation": "Renew the certificate before it expires to avoid service disruption.",
                "category": "SSL/TLS",
            })
            risk_score += 1

        if is_self_signed:
            findings.append({
                "vulnerability": "Self-Signed Certificate",
                "severity": "Medium",
                "url": target_url,
                "description": "The certificate appears to be self-signed rather than issued by a "
                                "trusted Certificate Authority, which will trigger browser trust warnings.",
                "evidence": f"Issuer CN equals Subject CN: {issuer.get('commonName')}",
                "recommendation": "Use a certificate issued by a publicly trusted CA (e.g. Let's Encrypt).",
                "category": "SSL/TLS",
            })
            risk_score += 2

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "vulnerability": "TLS Certificate Verification Failed",
            "severity": "High",
            "url": target_url,
            "description": "The certificate presented by the server failed verification against "
                            "trusted root authorities (may be self-signed, expired, or mismatched).",
            "evidence": str(e),
            "recommendation": "Ensure a valid certificate from a trusted CA matching the hostname is installed.",
            "category": "SSL/TLS",
        })
        risk_score += 3
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        findings.append({
            "vulnerability": "TLS Connection Error",
            "severity": "Medium",
            "url": target_url,
            "description": "Could not establish a raw TLS socket connection to inspect the certificate.",
            "evidence": str(e),
            "recommendation": "Manually verify TLS configuration using a tool such as `openssl s_client`.",
            "category": "SSL/TLS",
        })
        risk_score += 1

    findings.append({
        "vulnerability": "SSL/TLS Risk Score",
        "severity": "Informational",
        "url": target_url,
        "description": f"Computed SSL/TLS risk score: {risk_score} (0 = best, higher = worse).",
        "evidence": "Score derived from HTTPS availability, certificate validity window, and CA trust.",
        "recommendation": "Aim for a risk score of 0 by using a valid, CA-issued, non-expiring-soon certificate.",
        "category": "SSL/TLS",
    })

    return findings
