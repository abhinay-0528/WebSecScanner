
# WebSec Scanner

A lightweight, modular **Web Application Security Scanner** built with Python and Flask. It crawls a target web application and runs a suite of non-destructive detection modules — security headers, SSL/TLS, sensitive file exposure, form hygiene, reflected XSS, SQL injection error indicators, open redirects, and directory discovery — then presents the results on a dark, cybersecurity-themed dashboard and generates downloadable PDF/HTML reports.

> **Scope & Intent:** This project performs **detection only**. It never attempts exploitation, denial-of-service, credential brute forcing, or any destructive action. It was built as a cybersecurity portfolio project to demonstrate secure coding practices, web security concepts, and full-stack application design — **only scan targets you own or are explicitly authorized to test.**

---

## Feature List

| Module | What it does |
|---|---|
| **Dashboard** | Live stats: total scans, total vulnerabilities, severity breakdown, recent activity |
| **Target Scanner** | Validates and normalizes the target URL, verifies accessibility, tracks scan status |
| **Website Crawler** | Same-domain breadth-first crawl (depth/page-limited) extracting links & forms |
| **Information Gathering** | Page title, server banner, response headers, lightweight tech fingerprinting |
| **Security Headers Scanner** | Checks CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS |
| **SSL/TLS Analyzer** | HTTPS availability, certificate validity window, expiry, self-signed detection, risk score |
| **Sensitive File Discovery** | Checks `.git`, `.env`, backups, config files, default admin panels, etc. |
| **Form Analyzer** | Classifies forms (login/registration/search/contact), checks method, CSRF heuristic, autocomplete |
| **Reflected XSS Detection** | Injects a harmless unique marker into parameters and checks for unescaped reflection |
| **SQL Injection Error Detection** | Sends benign probes (`'`, `"`, tautologies) and matches known DB error signatures |
| **Open Redirect Detection** | Tests common redirect parameters against a neutral external test URL |
| **Directory Discovery** | Small built-in wordlist (`admin`, `backup`, `uploads`, ...) |
| **Vulnerability Management** | Every finding stores name, severity, description, evidence, URL, recommendation |
| **Report Generator** | Downloadable PDF (ReportLab) and HTML reports with executive summary & risk breakdown |
| **Results Dashboard** | Search, filter by severity, per-scan finding browser |

---

## Technology Stack

- **Backend:** Python 3, Flask
- **Frontend:** HTML5, CSS3, Bootstrap 5, vanilla JavaScript
- **Database:** SQLite (via `sqlite3`, no ORM)
- **Key libraries:** `requests`, `beautifulsoup4`, `validators`, `reportlab`

---

## Architecture

```
                        ┌────────────────────┐
                        │   Browser (UI)      │
                        │ Dashboard / Results  │
                        └──────────▲───────────┘
                                   │ HTTP / polling
                        ┌──────────┴───────────┐
                        │      Flask app.py     │
                        │  routes + scan runner │
                        └──────────┬───────────┘
                                   │ background thread
                 ┌─────────────────┼─────────────────┐
                 │        scanner/  modules            │
                 │ crawler → info_gathering → headers   │
                 │ → ssl_checker → sensitive_files       │
                 │ → forms → xss → sqli → redirects      │
                 │ → directories → report_generator      │
                 └─────────────────┬─────────────────┘
                                   │ findings
                        ┌──────────┴───────────┐
                        │   database/db.py      │
                        │   SQLite (scans,      │
                        │   findings tables)    │
                        └───────────────────────┘
```

Each scan runs in a background thread so the UI can poll `/api/scan/<id>/status` for live progress while the modules execute sequentially and persist findings as they go.

### Project Structure

```
WebAppSecurityScanner/
├── app.py                     # Flask app, routes, scan orchestration
├── database/
│   ├── __init__.py
│   └── db.py                  # SQLite schema + helper functions
├── scanner/
│   ├── __init__.py            # shared HTTP helpers (safe_get/safe_head)
│   ├── crawler.py
│   ├── info_gathering.py
│   ├── headers.py
│   ├── ssl_checker.py
│   ├── sensitive_files.py
│   ├── forms.py
│   ├── xss.py
│   ├── sqli.py
│   ├── redirects.py
│   ├── directories.py
│   └── report_generator.py
├── templates/                 # Jinja2 templates (dark dashboard UI)
├── static/
│   ├── css/style.css
│   └── js/main.js
├── reports/                   # generated PDF/HTML reports land here
├── requirements.txt
└── README.md
```

---

## Installation Guide

**Requirements:** Python 3.9+

```bash
# 1. Clone / unzip the project, then enter the folder
cd WebAppSecurityScanner

# 2. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

The app initializes its SQLite database automatically on first run (`database/scanner.db`) and starts at:

```
http://127.0.0.1:5000
```

---

## Usage Guide

1. Open the app in your browser and go to **New Scan**.
2. Enter a target URL you own or are authorized to test (e.g. `https://your-test-site.com`). If no scheme is given, `https://` is assumed.
3. The scan runs in the background; the progress page polls live status and current step.
4. Once complete, view **Results** — filter by severity, search findings, and review evidence/recommendations per finding.
5. Download a **PDF** or view an **HTML** report from the results page for sharing or archiving.
6. All past scans are listed under **Scan History**, and the **Dashboard** aggregates stats across every scan you've run.

---

## Screenshots Section

<img width="1912" height="906" alt="Screenshot 2026-08-31 160753" src="https://github.com/user-attachments/assets/1f900cbf-9d23-424b-9d0b-eb4daa9976c4" />

<img width="1910" height="916" alt="Screenshot 2026-08-31 160734" src="https://github.com/user-attachments/assets/117da06b-ce75-42fe-bae1-0fe83eac8eaf" />



---

## Sample Reports

<img width="1853" height="927" alt="Screenshot 2026-08-31 161052" src="https://github.com/user-attachments/assets/f0fc5c5e-40f8-424b-bd0c-5f12dc8af11d" />

<img width="1890" height="912" alt="Screenshot 2026-08-31 160820" src="https://github.com/user-attachments/assets/8c106004-a458-4d88-b212-10b04082695c" />


---

## Future Improvements

- Authenticated scanning (session cookie / login flow support)
- Asynchronous task queue (Celery/RQ) instead of a single background thread, for concurrent scans
- Blind / time-based SQL injection detection
- DOM-based XSS detection via headless browser rendering
- CVE/CVSS scoring integration for third-party component fingerprints
- Multi-user accounts and role-based access to scan history
- Docker Compose setup for one-command deployment
- Rate-limiting / scan throttling controls configurable per target
- Export findings to CSV/JSON for integration with other tooling

---

## Disclaimer

This tool is provided for educational purposes and authorized security testing only. Scanning systems without explicit permission from the owner may be illegal in your jurisdiction. The authors accept no liability for misuse.
=======
# WebSecScanner
Modular, non-invasive website application vulnerabilities scanner developed using Python and Flask. It can crawl target websites to check for lack of security headers, SSL/TLS problems, exposure of sensitive files, XSS, SQLi, open redirects and many others.

