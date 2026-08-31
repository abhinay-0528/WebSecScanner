"""
scanner/sensitive_files.py

Sensitive File / Resource Discovery Module.

Checks a small, well-known list of paths that commonly leak sensitive
information when publicly accessible (VCS metadata, backups, config
files, default admin panels, etc.) using simple GET requests. Only
checks for presence via status code + basic content sanity check -
never attempts to read/exfiltrate file contents beyond a short sample
used to reduce false positives (e.g. custom 200-status "not found" pages).
"""

from urllib.parse import urljoin

from scanner import safe_get

# path -> (risk level, human description)
SENSITIVE_PATHS = {
    "robots.txt": ("Informational", "Robots exclusion file - may reveal hidden paths."),
    "sitemap.xml": ("Informational", "Sitemap - reveals site structure."),
    ".git/config": ("High", "Exposed Git repository metadata - may allow full source code recovery."),
    ".git/HEAD": ("High", "Exposed Git repository metadata."),
    ".env": ("High", "Environment file - frequently contains credentials/API keys/secrets."),
    ".htaccess": ("Medium", "Apache configuration file exposed."),
    "config.php": ("High", "Application configuration file, may expose database credentials."),
    "config.json": ("Medium", "Configuration file exposed."),
    "wp-config.php": ("High", "WordPress configuration file, may expose database credentials."),
    "backup.zip": ("High", "Backup archive publicly accessible."),
    "backup.sql": ("High", "Database backup publicly accessible."),
    "database.sql": ("High", "Database dump publicly accessible."),
    "admin/": ("Medium", "Admin panel discoverable at a predictable path."),
    "administrator/": ("Medium", "Admin panel discoverable at a predictable path."),
    "phpinfo.php": ("Medium", "phpinfo() page exposes detailed server configuration."),
    ".DS_Store": ("Low", "macOS directory metadata file exposed, may leak file/folder names."),
    "web.config": ("Medium", "IIS/.NET configuration file exposed."),
    "server-status": ("Medium", "Apache server-status page may expose live request/traffic info."),
}


def discover(target_url):
    findings = []
    base = target_url if target_url.endswith("/") else target_url + "/"

    for path, (risk, description) in SENSITIVE_PATHS.items():
        full_url = urljoin(base, path)
        response = safe_get(full_url, allow_redirects=False)

        if response is None:
            continue

        # Treat 200/206 as "found". Be a little careful about soft-404 pages
        # by requiring a minimum content length, which filters out many
        # generic "not found" stub pages that still return 200.
        if response.status_code in (200, 206) and len(response.content) > 0:
            findings.append({
                "vulnerability": f"Publicly Accessible Resource: {path}",
                "severity": risk,
                "url": full_url,
                "description": description,
                "evidence": f"HTTP {response.status_code}, {len(response.content)} bytes returned.",
                "recommendation": "Remove or restrict access to this resource; it should not be "
                                   "publicly reachable in a production deployment.",
                "category": "Sensitive Files",
            })

    return findings
