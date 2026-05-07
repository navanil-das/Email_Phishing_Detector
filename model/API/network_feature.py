import requests
import socket
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Global Configuration
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
TIMEOUT = 6


def fetch_page(url: str):
    """Fetch page content and tracks redirects."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        return resp.text, resp.url, resp.history
    except Exception:
        return None, None, None


# --- URL Based Features ---

def double_slash_redirecting(url: str):
    try:
        path = urlparse(url).path
        return -1 if "//" in path else 1
    except Exception:
        return -1


def port_feature(url: str):
    try:
        parsed = urlparse(url)
        return -1 if parsed.port not in (None, 80, 443) else 1
    except Exception:
        return -1


def https_token(url: str):
    try:
        parsed = urlparse(url)
        return -1 if "https" in parsed.netloc.lower() else 1
    except Exception:
        return -1


def abnormal_url(url: str, final_url: str):
    try:
        return -1 if urlparse(url).netloc != urlparse(final_url).netloc else 1
    except Exception:
        return -1


# --- HTML Content Features ---

def submitting_to_email(html: str):
    if not html:
        return -1  # fail-safe suspicious
    try:
        soup = BeautifulSoup(html, "html.parser")
        for f in soup.find_all("form"):
            if (f.get("action", "")).lower().startswith("mailto:"):
                return -1
        return 1
    except Exception:
        return -1


def iframe(html: str):
    if not html:
        return -1
    try:
        soup = BeautifulSoup(html, "html.parser")
        return -1 if soup.find("iframe") else 1
    except Exception:
        return -1


def on_mouseover(html: str):
    if not html:
        return -1
    try:
        return -1 if "onmouseover" in html.lower() else 1
    except Exception:
        return -1


def right_click(html: str):
    if not html:
        return -1
    try:
        return -1 if "event.button==2" in html.lower() else 1
    except Exception:
        return -1


def pop_up_window(html: str):
    if not html:
        return -1
    try:
        return -1 if "window.open" in html.lower() else 1
    except Exception:
        return -1


def sfh_feature(url: str, html: str):
    if not html:
        return -1
    try:
        soup = BeautifulSoup(html, "html.parser")
        domain = urlparse(url).netloc
        for f in soup.find_all("form"):
            action = f.get("action", "")
            if action in ["", "about:blank"]:
                return -1
            full = urljoin(url, action)
            if urlparse(full).netloc and urlparse(full).netloc != domain:
                return -1
        return 1
    except Exception:
        return -1


# --- Link Analysis ---

def url_of_anchor(url: str, html: str):
    if not html:
        return -1
    try:
        soup = BeautifulSoup(html, "html.parser")
        anchors = soup.find_all("a", href=True)
        if not anchors:
            return -1

        domain = urlparse(url).netloc
        unsafe = 0
        for a in anchors:
            href = a["href"].lower()
            if href.startswith(("#", "javascript:", "mailto:")):
                unsafe += 1
            else:
                full = urljoin(url, href)
                if urlparse(full).netloc and urlparse(full).netloc != domain:
                    unsafe += 1

        return -1 if (unsafe / len(anchors)) > 0.5 else 1
    except Exception:
        return -1


def links_in_tags(url: str, html: str):
    if not html:
        return -1
    try:
        soup = BeautifulSoup(html, "html.parser")
        tags = soup.find_all(["meta", "script", "link"])
        domain = urlparse(url).netloc

        external, total = 0, 0
        for tag in tags:
            src = tag.get("content") or tag.get("src") or tag.get("href")
            if src:
                total += 1
                full = urljoin(url, src)
                if urlparse(full).netloc and urlparse(full).netloc != domain:
                    external += 1

        if total == 0:
            return -1

        return -1 if (external / total) > 0.5 else 1
    except Exception:
        return -1


def request_url(url: str, html: str):
    if not html:
        return -1
    try:
        soup = BeautifulSoup(html, "html.parser")
        domain = urlparse(url).netloc
        tags = soup.find_all(["img", "audio", "embed", "iframe", "script", "link"])

        external, total = 0, 0
        for tag in tags:
            src = tag.get("src") or tag.get("href")
            if src:
                total += 1
                full = urljoin(url, src)
                if urlparse(full).netloc and urlparse(full).netloc != domain:
                    external += 1

        if total == 0:
            return -1

        return -1 if (external / total) > 0.5 else 1
    except Exception:
        return -1


# --- Network & Domain Features ---

def dns_record(url: str):
    try:
        domain = urlparse(url).netloc
        socket.gethostbyname(domain)
        return 1
    except Exception:
        return -1


def age_of_domain(url: str):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not isinstance(creation, datetime):
            return -1

        age_days = (datetime.now() - creation).days
        return 1 if age_days > 180 else -1
    except Exception:
        return -1


def redirect_count(history):
    try:
        if not history:
            return 1
        return -1 if len(history) > 2 else 1
    except Exception:
        return -1
