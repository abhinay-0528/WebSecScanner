"""
scanner/crawler.py

Lightweight, same-origin website crawler.

Given a starting URL, discovers internal pages (breadth-first) up to a
configurable depth/page limit, and extracts every <a href> link and
<form> element it encounters. External domains are skipped entirely,
and a "visited" set prevents infinite loops on link cycles.

This module performs read-only GET requests only.
"""

from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from scanner import safe_get

MAX_PAGES = 25
MAX_DEPTH = 3

# File extensions we don't want to try to crawl as HTML pages
SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".pdf",
    ".zip", ".rar", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".ico",
)


def _same_domain(base_netloc, candidate_url):
    return urlparse(candidate_url).netloc == base_netloc


def _normalize(url):
    """Strip fragments so #section links don't count as separate pages."""
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


def extract_forms(soup, page_url):
    """Extract structured form data from a parsed page."""
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text") if inp.name == "input" else inp.name,
            })
        action = form.get("action") or page_url
        forms.append({
            "page_url": page_url,
            "action": urljoin(page_url, action),
            "method": (form.get("method") or "GET").upper(),
            "inputs": inputs,
            "has_password": any(i["type"] == "password" for i in inputs),
            "has_csrf_token": any(
                "csrf" in (i["name"] or "").lower() or "token" in (i["name"] or "").lower()
                for i in inputs
            ),
            "autocomplete": form.get("autocomplete", "on"),
        })
    return forms


def crawl(start_url, max_pages=MAX_PAGES, max_depth=MAX_DEPTH, progress_cb=None):
    """
    Breadth-first crawl of start_url, restricted to the same domain.

    Returns a dict:
        {
            "pages": [url, ...],
            "links": [url, ...],          # de-duplicated set of all links seen
            "forms": [form_dict, ...],
            "pages_html": {url: response_text}   # kept for downstream modules
        }
    """
    base_netloc = urlparse(start_url).netloc
    visited = set()
    all_links = set()
    forms = []
    pages_html = {}

    queue = deque([(start_url, 0)])

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        norm_url = _normalize(url)

        if norm_url in visited or depth > max_depth:
            continue
        if any(norm_url.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
            continue

        response = safe_get(norm_url)
        visited.add(norm_url)

        if progress_cb:
            progress_cb(len(visited), norm_url)

        if response is None or "text/html" not in response.headers.get("Content-Type", ""):
            continue

        pages_html[norm_url] = response.text

        soup = BeautifulSoup(response.text, "html.parser")

        # Extract forms on this page
        forms.extend(extract_forms(soup, norm_url))

        # Extract links
        for a in soup.find_all("a", href=True):
            link = urljoin(norm_url, a["href"])
            link = _normalize(link)
            if not link.startswith(("http://", "https://")):
                continue
            all_links.add(link)
            if _same_domain(base_netloc, link) and link not in visited:
                queue.append((link, depth + 1))

    return {
        "pages": list(visited),
        "links": list(all_links),
        "forms": forms,
        "pages_html": pages_html,
    }
