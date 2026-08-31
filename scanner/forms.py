"""
scanner/forms.py

Form Analyzer.

Takes the list of forms discovered by the crawler and classifies each
one (login / registration / search / contact / generic), then checks
basic hygiene properties: HTTP method used, presence of a password
field, autocomplete setting, and a heuristic check for a CSRF token
field. Purely inspects already-fetched HTML - no additional requests.
"""


def _classify_form(form):
    names = " ".join((i["name"] or "").lower() for i in form["inputs"])
    action = form["action"].lower()

    if form["has_password"] and ("register" in action or "signup" in names or "confirm" in names):
        return "Registration Form"
    if form["has_password"]:
        return "Login Form"
    if "search" in action or "q" in [i["name"].lower() for i in form["inputs"] if i["name"]]:
        return "Search Form"
    if any(k in names for k in ("email", "message", "subject", "contact")):
        return "Contact Form"
    return "Generic Form"


def analyze(forms, target_url):
    findings = []

    if not forms:
        findings.append({
            "vulnerability": "No Forms Discovered",
            "severity": "Informational",
            "url": target_url,
            "description": "The crawler did not discover any HTML forms on the pages it visited.",
            "evidence": "0 forms found.",
            "recommendation": "N/A",
            "category": "Form Analysis",
        })
        return findings

    for form in forms:
        form_type = _classify_form(form)

        findings.append({
            "vulnerability": f"{form_type} Discovered",
            "severity": "Informational",
            "url": form["page_url"],
            "description": f"A {form_type.lower()} was found submitting via {form['method']} to "
                            f"{form['action']}.",
            "evidence": f"Fields: {', '.join(i['name'] for i in form['inputs'] if i['name']) or 'none named'}",
            "recommendation": "Verify this form is intended to be publicly accessible.",
            "category": "Form Analysis",
        })

        if form["method"] == "GET" and form["has_password"]:
            findings.append({
                "vulnerability": "Login Form Uses GET Method",
                "severity": "High",
                "url": form["page_url"],
                "description": "A form containing a password field submits via GET, which causes "
                                "credentials to be included in the URL, browser history, and server logs.",
                "evidence": f"Form action: {form['action']}, method: GET",
                "recommendation": "Change the form method to POST for any form handling credentials.",
                "category": "Form Analysis",
            })

        if form["has_password"] and form["autocomplete"] != "off":
            findings.append({
                "vulnerability": "Password Field Allows Autocomplete",
                "severity": "Low",
                "url": form["page_url"],
                "description": "The form containing a password field does not disable autocomplete, "
                                "which may allow credentials to be cached by the browser on shared devices.",
                "evidence": f"autocomplete='{form['autocomplete']}'",
                "recommendation": "Consider setting autocomplete='off' on sensitive credential fields "
                                   "for shared/public-terminal use cases (note: modern browsers may "
                                   "partially ignore this).",
                "category": "Form Analysis",
            })

        if form["method"] == "POST" and not form["has_csrf_token"]:
            findings.append({
                "vulnerability": "Possible Missing CSRF Token",
                "severity": "Medium",
                "url": form["page_url"],
                "description": "No field with a name resembling a CSRF token was detected on this "
                                "POST form. This is a heuristic check only - the application may "
                                "protect this form via cookies, headers, or another mechanism not "
                                "visible in the static HTML.",
                "evidence": f"Fields present: {', '.join(i['name'] for i in form['inputs'] if i['name']) or 'none named'}",
                "recommendation": "Confirm CSRF protection is implemented (e.g. synchronizer token, "
                                   "double-submit cookie, or SameSite cookies) for all state-changing forms.",
                "category": "Form Analysis",
            })

    return findings
