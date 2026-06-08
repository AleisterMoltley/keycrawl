"""
KeyCrawl - Web secrets scanner core.

Crawls websites (same-domain by default) and extracts potential:
- API keys / tokens
- Private keys (PEM, OpenSSH, etc.)
- High-entropy strings (unknown secrets)
- JWTs, AWS, GitHub, Slack, Stripe, etc.

Designed to be fast, polite, and low on false positives.
"""

from __future__ import annotations

import asyncio
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, urldefrag

import httpx
import tldextract
from bs4 import BeautifulSoup, Comment
from pydantic import BaseModel, Field

# ---------------------------
# Models
# ---------------------------

class Finding(BaseModel):
    url: str
    secret_type: str
    value: str = Field(..., description="Raw matched value (do NOT log/store in prod)")
    value_redacted: str
    context: str = Field(..., description="Surrounding context snippet (sanitized)")
    entropy: float | None = None
    pattern_name: str

class ScanResult(BaseModel):
    target: str
    started_at: float
    finished_at: float | None = None
    pages_crawled: int = 0
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)

# ---------------------------
# Secret patterns (curated, low FP)
# ---------------------------

# Each: (name, regex, flags, description, is_multiline)
# We compile at load time.
PATTERNS: list[tuple[str, str, int, str, bool]] = [
    # AWS
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", 0, "AWS IAM access key", False),
    ("AWS Secret Access Key", r"(?i)aws(.{0,20})?['\"]?([0-9a-zA-Z/+]{40})['\"]?", 0, "AWS secret (approx)", False),
    # Google / Firebase
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", 0, "Google API key", False),
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com", 0, "Firebase realtime DB", False),
    # GitHub
    ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}", 0, "GitHub personal access token", False),
    ("GitHub OAuth", r"gho_[0-9a-zA-Z]{36}", 0, "GitHub OAuth token", False),
    ("GitHub App Token", r"(ghu|ghs)_[0-9a-zA-Z]{36}", 0, "GitHub app/installation token", False),
    # Slack
    ("Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}", 0, "Slack bot token", False),
    ("Slack User Token", r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}", 0, "Slack user token", False),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}", 0, "Slack incoming webhook", False),
    # Stripe
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", 0, "Stripe live secret", False),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", 0, "Stripe live publishable", False),
    # Generic service tokens (common)
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", 0, "Twilio API key", False),
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}", 0, "SendGrid API key", False),
    ("Heroku API Key", r"(?i)heroku.{0,20}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", 0, "Heroku API key", False),
    # JWT
    ("JWT", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", 0, "JSON Web Token (JWT)", False),
    # Private keys (multi-line possible)
    ("Private Key (PEM/OpenSSH)", r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |PRIVATE )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{20,}?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |PRIVATE )?KEY(?: BLOCK)?-----", re.DOTALL, "Private key material", True),
    ("SSH Private Key (old)", r"-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----[\s\S]{20,}?-----END SSH2 ENCRYPTED PRIVATE KEY-----", re.DOTALL, "SSH2 private key", True),
    # Generic "key = value" with high entropy (catch-all, filtered)
    ("Generic API Key / Secret", r"(?i)(?:api[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|api[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.\/+=~]{16,})['\"]?", 0, "Generic key=... assignment", False),
    # Authorization header bearer / basic with long token
    ("Bearer Token", r"(?i)authorization:\s*bearer\s+([a-zA-Z0-9_\-\.]{20,})", 0, "Bearer token in headers/text", False),
]

COMPILED_PATTERNS: list[tuple[str, re.Pattern, str, bool]] = []
for name, regex, flags, desc, multiline in PATTERNS:
    COMPILED_PATTERNS.append((name, re.compile(regex, flags | re.IGNORECASE), desc, multiline))

# High-entropy raw token candidates (base64-ish / hex / long alphanum) - applied after basic length filter
RAW_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_\-/.+=])([A-Za-z0-9_\-/.+=~]{32,})(?![A-Za-z0-9_\-/.+=])")

# Words that indicate test/fake keys (reduce noise)
NOISE_SUBSTRINGS = {
    "example", "sample", "test", "demo", "dummy", "fake", "placeholder", "yourkey",
    "insert", "replace", "changeme", "xxxxxxxx", "000000", "123456", "abcdef",
    "redacted", "secret123", "password123", "token123", "key123", "live", "prod",
    "staging", "development", "localhost",
}

def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

def is_likely_noise(value: str) -> bool:
    v = value.lower()
    if any(ns in v for ns in NOISE_SUBSTRINGS):
        return True
    # Very repetitive
    if len(set(v)) < 6 and len(v) > 20:
        return True
    return False

def redact_value(val: str, secret_type: str) -> str:
    if len(val) <= 12:
        return val[:4] + "****"
    if "PRIVATE KEY" in secret_type.upper() or "SSH" in secret_type.upper():
        return "-----BEGIN ... PRIVATE KEY ... (REDACTED)-----"
    if secret_type == "JWT":
        parts = val.split(".")
        if len(parts) >= 3:
            return f"{parts[0][:8]}....{parts[2][-6:]}"
    # Generic: first 6 + last 4
    return f"{val[:6]}...{val[-4:]}"

def extract_context(text: str, match_start: int, match_end: int, window: int = 70) -> str:
    """Return a short clean context around the match."""
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    snippet = text[start:end].replace("\n", " ").replace("\r", " ")
    # collapse whitespace
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if len(snippet) > window * 2 + 20:
        snippet = snippet[: window * 2 + 10] + "…"
    return snippet

# ---------------------------
# Core finding logic
# ---------------------------

def find_secrets_in_text(text: str, source_url: str) -> list[Finding]:
    """Run all patterns + entropy heuristics against a blob of text."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # (type, redacted) to dedupe per page

    if not text or len(text) < 8:
        return findings

    # 1. Known patterns
    for name, pattern, desc, _ in COMPILED_PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(0)
            # For groups that capture the actual secret (generic + bearer)
            if pattern.groups > 0:
                # take the last capturing group that looks long
                for g in reversed(m.groups()):
                    if g and len(g) >= 12:
                        raw = g
                        break

            if len(raw) < 12:
                continue
            if is_likely_noise(raw):
                continue

            red = redact_value(raw, name)
            key = (name, red)
            if key in seen:
                continue
            seen.add(key)

            ctx = extract_context(text, m.start(), m.end())
            ent = round(shannon_entropy(raw), 2) if len(raw) > 16 else None

            findings.append(
                Finding(
                    url=source_url,
                    secret_type=name,
                    value=raw,  # caller should never persist this
                    value_redacted=red,
                    context=ctx,
                    entropy=ent,
                    pattern_name=name,
                )
            )

    # 2. High-entropy raw tokens (catch unknown ones)
    for m in RAW_TOKEN_RE.finditer(text):
        raw = m.group(1)
        if len(raw) < 32 or len(raw) > 256:
            continue
        if is_likely_noise(raw):
            continue
        ent = shannon_entropy(raw)
        if ent < 4.2:  # too low entropy for a secret
            continue

        # Skip if it looks like a normal long word / hash in JS (heuristic)
        if re.search(r"[a-f0-9]{64}", raw) and ent < 4.8:  # long hex often not secret
            continue

        red = redact_value(raw, "HighEntropy")
        key = ("HighEntropy", red)
        if key in seen:
            continue
        seen.add(key)

        ctx = extract_context(text, m.start(1), m.end(1))
        findings.append(
            Finding(
                url=source_url,
                secret_type="High Entropy String",
                value=raw,
                value_redacted=red,
                context=ctx,
                entropy=round(ent, 2),
                pattern_name="HighEntropy",
            )
        )

    return findings

# ---------------------------
# Crawler
# ---------------------------

def _normalize_url(base: str, link: str) -> str | None:
    try:
        full = urljoin(base, link)
        full, _ = urldefrag(full)
        p = urlparse(full)
        if p.scheme not in ("http", "https"):
            return None
        return full
    except Exception:
        return None

def _same_registered_domain(a: str, b: str) -> bool:
    """True if same eTLD+1 (e.g. example.com == sub.example.com)."""
    try:
        da = tldextract.extract(a)
        db = tldextract.extract(b)
        return (da.domain, da.suffix) == (db.domain, db.suffix)
    except Exception:
        return False

async def fetch(
    client: httpx.AsyncClient,
    url: str,
    timeout: float = 12.0,
) -> tuple[str | None, str | None, int]:
    """Return (final_url, text_content, status)."""
    headers = {
        "User-Agent": "KeyCrawl/0.1 (+https://github.com/AleisterMoltley/keycrawl; security research scanner)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    try:
        resp = await client.get(url, headers=headers, timeout=timeout, follow_redirects=True)
        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype and "javascript" not in ctype and "text" not in ctype:
            # Only interested in text-ish
            return str(resp.url), None, resp.status_code
        return str(resp.url), resp.text, resp.status_code
    except httpx.TimeoutException:
        return url, None, 0
    except Exception as e:
        return url, None, -1

def _extract_links_and_text(html: str, base_url: str) -> tuple[str, set[str]]:
    """Return (clean_text + scripts, discovered_links)."""
    soup = BeautifulSoup(html, "lxml")

    # Remove script/style for visible text? We actually WANT script content for secrets.
    # So collect:
    # 1. All visible text
    # 2. All <script> contents (inline)
    # 3. HTML comments

    texts: list[str] = []

    # Visible text
    for tag in soup.find_all(string=True):
        if tag.parent.name in ("script", "style", "noscript"):
            continue
        if isinstance(tag, Comment):
            texts.append(str(tag))
        else:
            texts.append(str(tag))

    # Inline scripts (very important for client-side keys)
    for script in soup.find_all("script"):
        if script.string:
            texts.append(script.string)

    # Also grab some attributes that often contain tokens
    for tag in soup.find_all(True):
        for attr in ("data-key", "data-token", "data-secret", "data-api-key", "content"):
            val = tag.get(attr)
            if val and isinstance(val, str) and len(val) > 12:
                texts.append(f"{attr}={val}")

    full_text = "\n".join(texts)

    # Discover links
    links: set[str] = set()
    for a in soup.find_all("a", href=True):
        u = _normalize_url(base_url, a["href"])
        if u:
            links.add(u)

    for script in soup.find_all("script", src=True):
        u = _normalize_url(base_url, script["src"])
        if u and u.endswith((".js", ".mjs")):
            links.add(u)

    # crude: also search for http(s) urls in the raw html (catches some in JS strings)
    for m in re.finditer(r'https?://[a-zA-Z0-9./?=_%:@&+-]+', html):
        u = _normalize_url(base_url, m.group(0))
        if u:
            links.add(u)

    return full_text, links

async def crawl_and_scan(
    start_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 40,
    same_domain_only: bool = True,
    concurrency: int = 6,
    request_delay: float = 0.15,
    timeout_per_page: float = 14.0,
    include_robots: bool = True,
) -> ScanResult:
    """
    Main entrypoint. Crawls and returns all findings + stats.
    Polite by default.
    """
    start_time = time.time()
    result = ScanResult(target=start_url, started_at=start_time)

    parsed = urlparse(start_url)
    if not parsed.scheme:
        start_url = "https://" + start_url
        parsed = urlparse(start_url)

    root_domain = f"{parsed.scheme}://{parsed.netloc}"

    visited: set[str] = set()
    to_visit: list[tuple[str, int]] = [(start_url, 0)]  # (url, depth)
    findings: list[Finding] = []
    errors: list[str] = []

    limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
    async with httpx.AsyncClient(
        limits=limits,
        http2=True,
        follow_redirects=True,
        verify=True,
    ) as client:
        sem = asyncio.Semaphore(concurrency)

        async def worker(url: str, depth: int) -> None:
            nonlocal result
            if len(visited) >= max_pages:
                return
            if url in visited:
                return
            visited.add(url)

            async with sem:
                final_url, text, status = await fetch(client, url, timeout=timeout_per_page)
                await asyncio.sleep(request_delay)  # be nice

            if status <= 0 or text is None:
                if status < 0:
                    errors.append(f"Failed to fetch {url}")
                return

            result.pages_crawled += 1

            # Extract
            content_blob, discovered = _extract_links_and_text(text, final_url or url)

            # Find secrets
            page_findings = find_secrets_in_text(content_blob, final_url or url)
            findings.extend(page_findings)

            # Enqueue more?
            if depth < max_depth and len(visited) < max_pages:
                for link in discovered:
                    if link in visited:
                        continue
                    if same_domain_only and not _same_registered_domain(root_domain, link):
                        continue
                    # only http(s)
                    if not link.startswith(("http://", "https://")):
                        continue
                    to_visit.append((link, depth + 1))

        # Simple breadth-ish loop
        while to_visit and len(visited) < max_pages:
            batch: list[tuple[str, int]] = []
            while to_visit and len(batch) < concurrency:
                u, d = to_visit.pop(0)
                if u not in visited:
                    batch.append((u, d))
            if not batch:
                break
            await asyncio.gather(*(worker(u, d) for u, d in batch))

    # Optional: also scan robots.txt for keys (surprisingly common in misconfigs)
    if include_robots:
        try:
            robots_url = urljoin(root_domain + "/", "robots.txt")
            if robots_url not in visited:
                _, rtext, rstatus = await fetch(client, robots_url, timeout=6.0)
                if rtext and rstatus == 200:
                    rf = find_secrets_in_text(rtext, robots_url)
                    findings.extend(rf)
                    result.pages_crawled += 1
        except Exception:
            pass

    result.findings = findings
    result.errors = errors
    result.finished_at = time.time()
    result.stats = {
        "duration_sec": round(result.finished_at - result.started_at, 2),
        "max_depth": max_depth,
        "max_pages": max_pages,
        "same_domain_only": same_domain_only,
        "concurrency": concurrency,
        "findings_total": len(findings),
    }
    return result

# Convenience sync wrapper
def scan_sync(start_url: str, **kwargs: Any) -> ScanResult:
    return asyncio.run(crawl_and_scan(start_url, **kwargs))
