from __future__ import annotations

import re
import time
from threading import Lock
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from .config import Config
from .llm import summarize_context
from .moderation import detect_injection
from .logging_utils import log_event

# Hard allowlist of trusted authorities (ignores broader env overrides)
TRUSTED_DOMAINS = [
    "owasp.org",
    "cisa.gov",
    "nist.gov",
    "ncsc.gov.uk",
    "enisa.europa.eu",
    "cyber.gov.au",
    "pcisecuritystandards.org",
    "cert.govt.nz",
    "publicsafety.gc.ca",
]

MAX_RESULTS = Config.max_search_results or 6
MIN_RESULTS = Config.min_search_results or 3

_search_cache: dict[str, tuple[float, List[str]]] = {}
_page_cache: dict[str, tuple[float, str]] = {}
_search_lock = Lock()
_page_lock = Lock()


def _strip_www(host: str) -> str:
    host = (host or "").lower()
    return host[4:] if host.startswith("www.") else host


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = _strip_www(parsed.netloc)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    query_pairs = parse_qs(parsed.query, keep_blank_values=True)
    cleaned_query = {
        k: v
        for k, v in query_pairs.items()
        if not (k.lower().startswith("utm_") or k.lower() in {"gclid", "fbclid"})
    }
    query = "&".join(
        f"{key}={val}" if isinstance(val, str) else f"{key}={val[0]}"
        for key, val in cleaned_query.items()
        if val
    )
    return urlunparse((scheme, host, path, "", query, ""))


def _is_trusted(url: str) -> bool:
    host = _strip_www(urlparse(url).netloc)
    return any(host == dom or host.endswith(f".{dom}") for dom in TRUSTED_DOMAINS)


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _build_query(query: str) -> str:
    site_filters = " ".join(f"site:{dom}" for dom in TRUSTED_DOMAINS)
    return f"{query} {site_filters}".strip()


DENY_PATHS = [p.lower() for p in (Config.deny_paths or [])]
PREFER_PATHS = [p.lower() for p in (Config.prefer_paths or [])]


def _path_allowed(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    for deny in DENY_PATHS:
        if path.startswith(deny):
            return False
    return True


def _path_score(url: str) -> int:
    path = urlparse(url).path.lower()
    score = 0
    for allow in PREFER_PATHS:
        if allow in path:
            score += 1
    return score


DENY_FRAGMENTS = [
    "/search",
    "/donate",
    "/about",
    "/contact",
    "/privacy",
    "/terms",
    "/cookies",
    "/events",
    "/jobs",
    "/careers",
]

CISA_DENY_HUBS = {
    "/resources-tools",
    "/resources-tools/resources",
    "/resources-tools/all-resources-tools",
    "/resources-tools/services",
}

PREFER_FRAGMENTS = [
    "/guidance",
    "/resources",
    "/learn",
    "/advisories",
    "/alerts",
    "/publications",
    "/secure-our-world",
    "/www-community",
    "/top10",
]


def extract_result_links(domain: str, base_url: str, html: str, query_tokens: set[str] | None = None) -> List[str]:
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    anchors = soup.find_all("a", href=True)
    out: List[tuple[int, str]] = []
    base_host = _strip_www(urlparse(base_url).netloc)

    def is_denied(path: str) -> bool:
        path = path.lower()
        if path in {"/", ""}:
            return True
        for frag in DENY_FRAGMENTS:
            if path == frag or path.startswith(frag):
                return True
        return False

    def score_path(path: str) -> int:
        path = path.lower()
        score = 0
        for frag in PREFER_FRAGMENTS:
            if frag in path:
                score += 1
        return score

    for a in anchors:
        href = a.get("href") or ""
        if href.startswith(("mailto:", "javascript:", "tel:")):
            continue
        resolved = urljoin(base_url, href)
        candidate = _normalize_url(resolved)
        parsed = urlparse(candidate)
        host = _strip_www(parsed.netloc)
        path = parsed.path or "/"

        if candidate.lower().endswith(".pdf"):
            log_event("drop_url", {"reason": "pdf", "url": candidate})
            continue
        if not _is_trusted(candidate):
            log_event("drop_url", {"reason": "domain", "url": candidate})
            continue
        if host != base_host:
            log_event("drop_url", {"reason": "cross_domain", "url": candidate})
            continue
        if is_denied(path):
            log_event("drop_url", {"reason": "deny_path", "url": candidate})
            continue

        # domain-specific gating
        keep = True
        if domain.endswith("cisa.gov"):
            lower_path = path.lower()
            token_in_path = any(tok in lower_path for tok in (query_tokens or []))
            if lower_path in CISA_DENY_HUBS and not token_in_path:
                log_event("drop_url", {"reason": "cisa_hub", "url": candidate})
                keep = False
            else:
                keep = any(
                    frag in lower_path
                    for frag in [
                        "/secure-our-world/",
                        "/resources-tools/",
                        "/news/",
                        "/alerts/",
                        "/topics/",
                    ]
                )
        elif domain.endswith("owasp.org"):
            keep = (
                "/www-community/" in path.lower()
                or "/top10/" in path.lower()
                or "/api-security/" in path.lower()
            )

        if not keep:
            log_event("drop_url", {"reason": "domain_filter", "url": candidate})
            continue
        if query_tokens:
            lower_path = path.lower()
            if not any(tok in lower_path for tok in query_tokens):
                log_event("drop_url", {"reason": "no_query_token", "url": candidate})
                continue

        score = score_path(path)
        out.append((score, candidate))

    # sort by score desc then preserve order
    deduped: List[str] = []
    for _, url in sorted(out, key=lambda x: x[0], reverse=True):
        if url not in deduped:
            deduped.append(url)
        if len(deduped) >= MAX_RESULTS:
            break
    return deduped


def extract_cisa_result_links(html: str) -> List[str]:
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    selectors = [
        "div.gsc-webResult a.gs-title",
        "div.gsc-webResult a.gs-title[href]",
        "a.gs-title[href]",
        "div.gsc-result a[href]",
    ]
    links: List[str] = []
    for sel in selectors:
        anchors = soup.select(sel)
        if anchors:
            for a in anchors:
                href = a.get("href") or ""
                if href and href not in links:
                    links.append(href)
            if links:
                break
    return links


def site_search(domain: str, query: str, max_results: int = MAX_RESULTS) -> List[str]:
    headers = {
        "User-Agent": Config.search_user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
    }
    urls: List[str] = []
    base_domain = domain if domain.startswith("http") else f"https://{domain}"

    def fetch(url: str, params: dict | None = None) -> str:
        try:
            log_event("search_site_start", {"domain": domain, "q": query, "url": url})
            resp = requests.get(url, params=params, headers=headers, timeout=Config.search_timeout)
            resp.raise_for_status()
            log_event(
                "search_site_response",
                {"domain": domain, "status": resp.status_code, "bytes": len(resp.content), "url": resp.url},
            )
            return resp.text
        except Exception as exc:
            log_event("search_error", {"domain": domain, "error": str(exc), "url": url})
            return ""

    # CISA specialized template
    tokens_raw = re.findall(r"[a-z0-9]+", query.lower())
    tokens = {t for t in tokens_raw if len(t) >= 4} or set(tokens_raw)
    if domain.endswith("cisa.gov"):
        html = fetch(
            "https://www.cisa.gov/search",
            params={"g": query, "gsc.q": query, "gsc.page": 1, "gsc.tab": 0},
        )
        direct_links = extract_cisa_result_links(html)
        if direct_links:
            extracted = []
            for href in direct_links:
                resolved = urljoin("https://www.cisa.gov/search", href)
                candidate = _normalize_url(resolved)
                if candidate.lower().endswith(".pdf"):
                    log_event("drop_url", {"reason": "pdf", "url": candidate})
                    continue
                if not _is_trusted(candidate):
                    log_event("drop_url", {"reason": "domain", "url": candidate})
                    continue
                if _strip_www(urlparse(candidate).netloc) != "cisa.gov":
                    log_event("drop_url", {"reason": "cross_domain", "url": candidate})
                    continue
                path = urlparse(candidate).path or "/"
                if is_denied(path):
                    log_event("drop_url", {"reason": "deny_path", "url": candidate})
                    continue
                if tokens and not any(tok in path.lower() for tok in tokens):
                    log_event("drop_url", {"reason": "no_query_token", "url": candidate})
                    continue
                if candidate not in extracted:
                    extracted.append(candidate)
            urls.extend(extracted)
        if len(urls) < max_results:
            urls.extend(extract_result_links(domain, "https://www.cisa.gov/search", html, tokens))
        if len(urls) >= max_results:
            urls = list(dict.fromkeys(urls))
            log_event("search_site_urls", {"domain": domain, "count": len(urls), "urls": urls[:max_results]})
            return urls[:max_results]

    templates = [
        f"{base_domain}/search?q={query}",
        f"{base_domain}/search?query={query}",
        f"{base_domain}/site-search?query={query}",
        f"{base_domain}/?s={query}",
    ]
    for tpl in templates:
        if len(urls) >= max_results:
            break
        html = fetch(tpl)
        urls.extend(extract_result_links(domain, tpl, html, tokens))
        urls = list(dict.fromkeys(urls))  # dedupe
    if urls:
        log_event("search_site_urls", {"domain": domain, "count": len(urls), "urls": urls[:max_results]})
    return urls[:max_results]


def web_search(query: str, max_results: int = MAX_RESULTS) -> List[str]:
    if not Config.enable_live_search:
        return []
    now = time.time()
    with _search_lock:
        cached = _search_cache.get(query)
        if cached and now - cached[0] < Config.search_cache_ttl:
            log_event("search_cache_hit", {"query": query})
            return cached[1]
    log_event("search_cache_miss", {"query": query})
    urls: List[str] = []
    # Always include the trusted set; extend with any configured domains.
    domain_list = list(dict.fromkeys((Config.allowed_domains or []) + TRUSTED_DOMAINS))
    for dom in domain_list:
        if len(urls) >= max_results:
            break
        if _strip_www(dom) not in TRUSTED_DOMAINS and not any(
            _strip_www(dom).endswith(f".{d}") for d in TRUSTED_DOMAINS
        ):
            continue
        results = site_search(dom, query, max_results=max_results - len(urls))
        for url in results:
            if url not in urls:
                urls.append(url)
            if len(urls) >= max_results:
                break
    if urls and Config.search_cache_ttl > 0:
        with _search_lock:
            _search_cache[query] = (now, urls)
    log_event("search_complete", {"query": query, "urls": urls})
    if not urls:
        log_event("search_no_urls", {"query": query})
    return urls


def fetch_and_extract(url: str) -> str:
    if not url or not _is_trusted(url):
        return ""
    now = time.time()
    with _page_lock:
        cached = _page_cache.get(url)
        if cached and now - cached[0] < Config.fetch_cache_ttl:
            return cached[1]
    headers = {
        "User-Agent": Config.search_user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
    }
    try:
        log_event("fetch_attempt", {"url": url})
        resp = requests.get(url, headers=headers, timeout=Config.fetch_timeout)
        resp.raise_for_status()
        ctype = resp.headers.get("Content-Type", "")
        if "pdf" in ctype.lower():
            log_event("drop_url", {"reason": "pdf", "url": url})
            text = ""
        else:
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup(["script", "style", "header", "footer", "nav", "aside", "noscript"]):
                tag.decompose()
            container = soup.find("main") or soup.find("article") or soup.body
            raw_text = container.get_text("\n") if container else ""
            cleaned = _clean_text(raw_text)
            if detect_injection(cleaned):
                log_event("drop_url", {"reason": "injection", "url": url})
                text = ""
            else:
                text = cleaned
        if text:
            log_event("fetch_ok", {"url": url})
    except Exception:
        text = ""
    with _page_lock:
        _page_cache[url] = (now, text)
    return text


def filter_injection_snippets(text: str) -> str:
    if not text:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    kept = [s for s in sentences if s and not detect_injection(s)]
    return _clean_text(" ".join(kept))


def answer_with_web_sources(question: str) -> Tuple[str, List[str]]:
    if not Config.enable_live_search:
        return "", []
    urls = web_search(question)
    # sort by prefer path score
    urls = sorted(urls, key=_path_score, reverse=True)
    contexts: List[str] = []
    used: List[str] = []
    for url in urls:
        text = fetch_and_extract(url)
        if not text:
            continue
        safe_text = filter_injection_snippets(text)
        if not safe_text:
            continue
        contexts.append(safe_text[:2000])
        used.append(url)
        if len(contexts) >= 4:
            break
    if not contexts:
        return "", []
    combined = "\n\n".join(contexts)
    summary = summarize_context(question, combined)
    if not summary.strip():
        # fallback to stitched excerpt
        fallback = " ".join(ctx[:400] for ctx in contexts[:2]).strip()
        summary = fallback
    return summary, used
