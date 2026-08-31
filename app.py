"""
app.py

Main Flask application for the Web Application Security Scanner.

Routes:
  GET  /                          Dashboard
  GET  /scan/new                  New scan form
  POST /scan/new                  Validate + kick off a scan (background thread)
  GET  /scan/<id>                 Scan progress / results page
  GET  /api/scan/<id>/status      JSON polling endpoint for scan progress
  GET  /history                   All past scans
  GET  /results/<id>              Full results view with search/sort/filter
  GET  /report/<id>/pdf           Download PDF report
  GET  /report/<id>/html          Download / view HTML report

Scans run in a background thread so the UI can show live progress via
polling, while the actual scanning modules (crawler, headers, ssl,
sensitive files, forms, xss, sqli, redirects, directories) run
sequentially and persist findings into SQLite as they go.

IMPORTANT / SCOPE: This application performs DETECTION ONLY. It does
not attempt exploitation, denial-of-service, credential brute forcing,
or any destructive action against a target. It is intended for
authorized security testing / educational use against systems you own
or have explicit permission to test.
"""

import threading
import validators
from flask import (
    Flask, render_template, request, redirect, url_for, jsonify, send_file, flash, abort
)

from database import db
from scanner import crawler, info_gathering, headers as headers_scanner, ssl_checker
from scanner import sensitive_files, forms as forms_analyzer, xss, sqli, redirects, directories
from scanner import report_generator

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"  # fine for a local portfolio demo

# In-memory cache of the last-gathered "info" dict per scan id, used by
# the report generator (title/server/tech). Not persisted to keep the
# schema simple - acceptable for a single-process demo app.
_scan_info_cache = {}


# ---------------------------------------------------------------------------
# Scan orchestration (runs in a background thread)
# ---------------------------------------------------------------------------

def run_scan(scan_id: int, target_url: str):
    try:
        db.update_scan_progress(scan_id, 5, "Verifying target accessibility")
        info, info_findings = info_gathering.gather(target_url)
        _scan_info_cache[scan_id] = info
        for f in info_findings:
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 15, "Crawling website")
        crawl_result = crawler.crawl(target_url)
        pages = crawl_result["pages"]
        links = crawl_result["links"]
        page_forms = crawl_result["forms"]
        db.update_scan_stats(scan_id, len(pages), len(page_forms))
        db.add_finding(
            scan_id,
            vulnerability="Crawl Summary",
            severity="Informational",
            url=target_url,
            description=f"Discovered {len(pages)} page(s) and {len(page_forms)} form(s).",
            evidence=f"{len(links)} unique link(s) observed.",
            recommendation="N/A",
            category="Crawler",
        )

        db.update_scan_progress(scan_id, 30, "Scanning security headers")
        for f in headers_scanner.scan(target_url):
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 40, "Analyzing SSL/TLS configuration")
        for f in ssl_checker.analyze(target_url):
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 50, "Checking for sensitive files")
        for f in sensitive_files.discover(target_url):
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 60, "Analyzing discovered forms")
        for f in forms_analyzer.analyze(page_forms, target_url):
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 70, "Testing for reflected XSS")
        for f in xss.scan(pages + links, page_forms):
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 80, "Testing for SQL injection indicators")
        for f in sqli.scan(pages + links):
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 88, "Checking for open redirects")
        for f in redirects.scan(pages + links):
            db.add_finding(scan_id, **f)

        db.update_scan_progress(scan_id, 95, "Enumerating common directories")
        for f in directories.discover(target_url):
            db.add_finding(scan_id, **f)

        db.complete_scan(scan_id, status="Completed")
    except Exception as e:  # noqa: BLE001 - top-level scan safety net
        db.complete_scan(scan_id, status="Failed", error=str(e))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    stats = db.get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/scan/new", methods=["GET", "POST"])
def new_scan():
    if request.method == "GET":
        return render_template("new_scan.html")

    target_url = request.form.get("target_url", "").strip()

    if not target_url:
        flash("Please enter a target URL.", "danger")
        return redirect(url_for("new_scan"))

    # Normalize: add scheme if missing
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    if not validators.url(target_url):
        flash("The URL entered is not a valid, well-formed URL.", "danger")
        return redirect(url_for("new_scan"))

    scan_id = db.create_scan(target_url)

    thread = threading.Thread(target=run_scan, args=(scan_id, target_url), daemon=True)
    thread.start()

    return redirect(url_for("scan_progress", scan_id=scan_id))


@app.route("/scan/<int:scan_id>")
def scan_progress(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    return render_template("scan_progress.html", scan=scan)


@app.route("/api/scan/<int:scan_id>/status")
def api_scan_status(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    counts = db.get_severity_counts(scan_id)
    return jsonify({
        "id": scan["id"],
        "status": scan["status"],
        "progress": scan["progress"],
        "current_step": scan["current_step"],
        "pages_discovered": scan["pages_discovered"],
        "forms_discovered": scan["forms_discovered"],
        "error": scan["error"],
        "severity_counts": counts,
    })


@app.route("/history")
def history():
    scans = db.get_all_scans()
    return render_template("history.html", scans=scans)


@app.route("/results/<int:scan_id>")
def results(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    severity_filter = request.args.get("severity", "All")
    findings = db.get_findings(scan_id, severity_filter)
    counts = db.get_severity_counts(scan_id)
    return render_template(
        "results.html", scan=scan, findings=findings, counts=counts,
        severity_filter=severity_filter,
    )


@app.route("/report/<int:scan_id>/pdf")
def report_pdf(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    findings = db.get_findings(scan_id)
    info = _scan_info_cache.get(scan_id)
    filepath = report_generator.generate_pdf(scan, findings, info)
    return send_file(filepath, as_attachment=True,
                      download_name=f"security_report_scan_{scan_id}.pdf")


@app.route("/report/<int:scan_id>/html")
def report_html(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    findings = db.get_findings(scan_id)
    info = _scan_info_cache.get(scan_id)
    filepath = report_generator.generate_html(scan, findings, info)
    return send_file(filepath, mimetype="text/html")


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
