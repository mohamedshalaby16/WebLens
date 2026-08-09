import asyncio
import ipaddress
import logging
import re
import secrets
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from playwright.sync_api import sync_playwright
from scrapling import Selector as ScraplingSelector
from scrapling.fetchers import DynamicFetcher, Fetcher, StealthyFetcher

from models import CloneResult, FormData, PageResult

logger = logging.getLogger(__name__)

# Crawl bounds — a clone job walks internal links breadth-first up to these
# limits so cloning a site can't turn into an unbounded scrape of the target.
# DEFAULT_* covers a typical corporate site without every job defaulting to
# the full 15-minute budget; HARD_* lets a caller explicitly request deeper
# coverage via max_pages for a large site, capped well short of "crawl the
# entire live site" — combined with the proxy fallback's lazy-upgrade path
# (fetch_proxy_page/save_page), pages beyond even the hard cap still resolve
# fully-styled on first visit, they just aren't pre-fetched.
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 40
HARD_MAX_DEPTH = 6
HARD_MAX_PAGES = 150

# Timeouts — bound how long a single page fetch and the crawl as a whole
# may run, so a stalled page or hung network request can't hang a job.
PAGE_FETCH_TIMEOUT_SECONDS = 30.0
TOTAL_CRAWL_TIMEOUT_SECONDS = 900.0


def _normalize_url(url: str) -> str:
    """
    Normalize a URL for crawl de-duplication: drop query string and
    fragment, and strip a trailing slash, so query-string variants of the
    same path aren't treated as distinct pages.
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc.lower()}{path}"


def _url_path(url: str) -> str:
    """
    Extract and normalize a URL's path component for routing/storage —
    e.g. "/", "/about", "/products/shoes". Query string and fragment are
    dropped (urlparse already separates them out), and a trailing slash
    is stripped except on the root path.
    """
    path = urlparse(url).path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def _local_page_route(job_id: str, url_path: str) -> str:
    """
    The local /clone/{job_id}/... route a given URL path resolves to. The
    root path gets the short form so it matches the dedicated
    GET /clone/{job_id} route instead of the catch-all.
    """
    return f"/clone/{job_id}" if url_path == "/" else f"/clone/{job_id}{url_path}"


_INTERCEPTOR_TEMPLATE_PATH = (
    Path(__file__).parent / "static" / "js" / "weblens_interceptor.js"
)
_interceptor_template_cache: str | None = None


def _get_interceptor_template() -> str:
    """Read+cache the interceptor script template (constant for process lifetime)."""
    global _interceptor_template_cache
    if _interceptor_template_cache is None:
        _interceptor_template_cache = _INTERCEPTOR_TEMPLATE_PATH.read_text(
            encoding="utf-8"
        )
    return _interceptor_template_cache


def _rewrite_forms_to_capture(html: str, job_id: str) -> str:
    """
    Rewrite every <form> in `html` to submit to /capture/{job_id} via POST,
    so phishing-simulation form submissions are captured locally instead of
    sent to the real target site. Shared by the full-crawl page rewriter
    and the live single-page proxy fallback.
    """
    capture_url = f"http://localhost:8000/capture/{job_id}"

    def rewrite_form_action(match):
        return match.group(0).replace(match.group(1), capture_url)

    html = re.sub(
        r'<form[^>]+action=["\']([^"\']*)["\']',
        rewrite_form_action,
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r'<form(?![^>]*action=)([^>]*)>',
        f'<form action="{capture_url}"\\1>',
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r'(<form[^>]+)method=["\']get["\']',
        r'\1method="POST"',
        html,
        flags=re.IGNORECASE,
    )
    return html


def inject_interceptor(html: str, job_id: str, base_domain: str) -> str:
    """
    Inject the navigation-interceptor script as the first thing in <head>,
    so it runs before any of the cloned page's own JavaScript. It patches
    pushState/replaceState, fetch, XMLHttpRequest, window.location, and
    <a> clicks so client-side (SPA-style) navigation stays under
    /clone/{job_id}/... instead of leaving localhost.
    """
    try:
        template = _get_interceptor_template()
    except OSError as exc:
        logger.warning("Could not load navigation interceptor script: %s", exc)
        return html

    script = template.replace("{{JOB_ID}}", job_id).replace(
        "{{BASE_DOMAIN}}", base_domain
    )
    injection = f"<script>{script}</script>"

    if "<head>" in html:
        return html.replace("<head>", f"<head>{injection}", 1)
    if "<HEAD>" in html:
        return html.replace("<HEAD>", f"<HEAD>{injection}", 1)
    return injection + html


# Explicit extra blocks — not reliably covered by ipaddress's built-in
# is_private/is_link_local/is_loopback flags on every Python version.
_CGNAT_RANGE = ipaddress.ip_network("100.64.0.0/10")    # RFC 6598
_IPV6_ULA_RANGE = ipaddress.ip_network("fc00::/7")       # RFC 4193


def is_safe_ip(ip: str) -> bool:
    """
    Check whether a single resolved IP address (v4 or v6) is safe to
    connect to — not private, loopback, reserved, link-local, multicast,
    unspecified, CGNAT, or an IPv6 unique-local address.

    Shared by is_safe_url() (validation time) and check_no_rebind()
    (post-fetch re-check), so both use identical rules.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if (addr.is_private or
        addr.is_loopback or
        addr.is_reserved or
        addr.is_link_local or
        addr.is_multicast or
        addr.is_unspecified):
        return False

    # _BaseNetwork.__contains__ returns False (not an error) when the
    # address and network are different IP versions, so these are safe
    # to check unconditionally.
    if addr in _CGNAT_RANGE or addr in _IPV6_ULA_RANGE:
        return False

    return True


def _resolve_ips(hostname: str) -> list[str]:
    """
    Resolve a hostname to every IPv4/IPv6 address it currently maps to.
    Returns an empty list if resolution fails.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    return list({info[4][0] for info in infos})


def is_safe_url(url: str) -> bool:
    """
    Validate URL is safe to fetch.
    Blocks private IPs, loopback, reserved ranges, and non-HTTP schemes.
    """
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if len(url) > 2000:
            return False

        ips = _resolve_ips(parsed.hostname)
        if not ips:
            return False

        return all(is_safe_ip(ip) for ip in ips)

    except Exception:
        return False


def check_no_rebind(hostname: str | None) -> bool:
    """
    Re-resolve `hostname` and verify every address it currently maps to
    is still safe. Call this right after a fetch completes, before the
    response is processed or stored, to catch DNS rebinding: a hostname
    that resolved safely when is_safe_url() validated it, but was
    repointed at a private/loopback/etc. address by the time (or after)
    the actual connection was made.
    """
    if not hostname:
        return False

    ips = _resolve_ips(hostname)
    if not ips:
        return False

    for ip in ips:
        if not is_safe_ip(ip):
            logger.warning(
                "Potential DNS rebinding detected for host '%s' — "
                "now resolves to unsafe IP %s",
                hostname, ip,
            )
            return False

    return True

ASSET_TAGS = [
    ("img", "src"),
    ("link", "href"),
    ("script", "src"),
]


def _safe_extension(url: str) -> str:
    """
    Safely extract file extension from a URL.
    Returns empty string if extension looks invalid.
    """
    import re
    from urllib.parse import unquote
    try:
        path = urlparse(url).path
        path = unquote(path)
        last_segment = path.rstrip('/').split('/')[-1]
        last_segment = last_segment.split('?')[0].split('#')[0]
        if '.' in last_segment:
            ext = '.' + last_segment.rsplit('.', 1)[-1]
            if re.match(r'^\.[a-zA-Z0-9]{1,5}$', ext):
                return ext
        return ''
    except Exception:
        return ''


class ScraplingCloner:

    ALWAYS_DYNAMIC_DOMAINS = [
        'tiktok.com',
        'instagram.com',
        'facebook.com',
        'twitter.com',
        'x.com',
        'linkedin.com',
        'netflix.com',
        'spotify.com',
        'pinterest.com',
        'reddit.com',
        'discord.com',
        'notion.so',
        'figma.com',
    ]

    async def auto_select_fetcher(self, url: str) -> str:
        # HTTP sites — use basic Fetcher
        if url.startswith("http://"):
            return "Fetcher"

        # Check for Cloudflare protection with a quick probe
        try:
            page = Fetcher(auto_match=False).get(url, stealthy_headers=True)
            html = page.html_content if hasattr(page, "html_content") else str(page)
            if "cf-browser-verification" in html or "challenge-running" in html:
                logger.info("Cloudflare detected for %s", url)
                return "StealthyFetcher"
        except Exception:
            pass

        # Default to DynamicFetcher for everything else
        # It renders full JavaScript before capturing HTML
        logger.info("Using DynamicFetcher for %s", url)
        return "DynamicFetcher"

    def _fetch_page(self, url: str, fetcher_name: str):
        if fetcher_name == "DynamicFetcher":
            return DynamicFetcher(auto_match=False).fetch(url)
        if fetcher_name == "StealthyFetcher":
            fetcher = StealthyFetcher(auto_match=False)
            return fetcher.fetch(url)
        return Fetcher(auto_match=False).get(url, stealthy_headers=True)

    def _fetch_page_with_interception_sync(
        self, url: str
    ) -> tuple[str, dict[str, bytes]]:
        """
        Use Playwright sync API to fetch a page and intercept all network
        requests. Returns (html_content, {absolute_url: bytes}).
        Runs synchronously — call via asyncio.to_thread from async context.
        """
        captured_assets: dict[str, bytes] = {}
        lock = threading.Lock()

        def handle_response(response):
            try:
                url_str = response.url
                content_type = response.headers.get('content-type', '')
                asset_types = [
                    'text/css',
                    'application/javascript',
                    'text/javascript',
                    'font/',
                    'image/',
                    'application/font',
                    'application/x-font',
                ]
                is_asset = any(t in content_type for t in asset_types)
                if is_asset and response.status == 200:
                    body = response.body()
                    if body:
                        with lock:
                            captured_assets[url_str] = body
                        logger.debug(
                            "Intercepted: %s (%d bytes)", url_str, len(body)
                        )
            except Exception as exc:
                logger.debug("Could not capture response: %s", exc)

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                ]
            )
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent=(
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/120.0.0.0 Safari/537.36'
                ),
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.on('response', handle_response)

            try:
                page.goto(url, wait_until='networkidle', timeout=60000)
                page.wait_for_timeout(3000)
                html_content = page.content()
            finally:
                browser.close()

        return html_content, captured_assets

    async def _fetch_page_with_interception(
        self, url: str
    ) -> tuple[str, dict[str, bytes]]:
        """
        Async wrapper around _fetch_page_with_interception_sync.
        Runs the sync Playwright in a thread to avoid event loop conflicts
        on Python 3.14 Windows.
        """
        return await asyncio.to_thread(
            self._fetch_page_with_interception_sync, url
        )

    async def _download_assets(
        self,
        page,
        base_url: str,
        job_id: str,
        assets_bytes: dict[str, bytes] | None = None,
        url_to_local: dict[str, str] | None = None,
        raw_to_local: dict[str, str] | None = None,
        seen: set[str] | None = None,
    ) -> tuple[dict[str, bytes], dict[str, str], dict[str, str], int]:
        """
        Download all assets referenced by a page. Shared dicts/set may be
        passed in so multiple pages of the same crawl reuse already
        downloaded assets instead of re-fetching them.
        Returns: assets_bytes, url_to_local, raw_to_local, failed_count
        """
        if assets_bytes is None:
            assets_bytes = {}
        if url_to_local is None:
            url_to_local = {}
        if raw_to_local is None:
            raw_to_local = {}
        if seen is None:
            seen = set()
        failed_count: int = 0

        urls_to_fetch: list[tuple[str, str]] = []
        for tag, attr in ASSET_TAGS:
            for el in page.css(tag) or []:
                raw = el.attrib.get(attr, "").strip()
                if not raw or raw.startswith("data:"):
                    continue
                absolute = urljoin(base_url, raw)
                if absolute not in seen:
                    seen.add(absolute)
                    urls_to_fetch.append((absolute, raw))
                elif absolute in url_to_local:
                    raw_to_local[raw] = url_to_local[absolute]

        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            for absolute_url, raw_value in urls_to_fetch:
                try:
                    response = await client.get(absolute_url)
                    response.raise_for_status()
                    extension = _safe_extension(absolute_url)
                    filename = secrets.token_hex(8) + extension
                    assets_bytes[filename] = response.content
                    url_to_local[absolute_url] = f"/clone/assets/{job_id}/{filename}"
                    raw_to_local[raw_value] = f"/clone/assets/{job_id}/{filename}"
                    logger.debug("Downloaded asset: %s", absolute_url)

                    if filename.endswith('.css'):
                        processed = await self._process_css_assets(
                            css_content=response.content,
                            css_url=absolute_url,
                            assets_bytes=assets_bytes,
                            url_to_local=url_to_local,
                            client=client,
                            seen=seen,
                            job_id=job_id,
                        )
                        assets_bytes[filename] = processed

                except Exception:
                    logger.warning("Failed to download asset: %s", absolute_url)
                    failed_count += 1

        return assets_bytes, url_to_local, raw_to_local, failed_count

    async def _process_css_assets(
        self,
        css_content: bytes,
        css_url: str,
        assets_bytes: dict[str, bytes],
        url_to_local: dict[str, str],
        client: httpx.AsyncClient,
        seen: set[str],
        job_id: str,
    ) -> bytes:
        import re
        try:
            text = css_content.decode('utf-8', errors='ignore')
            pattern = re.compile(r'url\(\s*["\']?([^)"\']+)["\']?\s*\)')
            matches = list(pattern.finditer(text))

            for match in matches:
                inner = match.group(1).strip().strip('"\'')
                if not inner or inner.startswith('data:') or inner.startswith('#'):
                    continue

                absolute = urljoin(css_url, inner)

                if absolute in url_to_local:
                    local = url_to_local[absolute]
                    text = text.replace(match.group(0), f"url('{local}')")
                    continue

                if absolute in seen:
                    continue

                seen.add(absolute)

                try:
                    response = await client.get(absolute)
                    response.raise_for_status()
                    extension = _safe_extension(absolute)
                    filename = secrets.token_hex(8) + extension
                    while filename in assets_bytes:
                        filename = secrets.token_hex(8) + extension
                    assets_bytes[filename] = response.content
                    local_path = f'/clone/assets/{job_id}/{filename}'
                    url_to_local[absolute] = local_path
                    # Also store without query string as fallback
                    clean_url = absolute.split('?')[0]
                    if clean_url != absolute:
                        url_to_local[clean_url] = local_path
                    text = text.replace(match.group(0), f"url('{local_path}')")
                    logger.debug("Downloaded CSS asset: %s", absolute)
                except Exception:
                    logger.warning("Failed to download CSS asset: %s", absolute)

            return text.encode('utf-8')

        except Exception as exc:
            logger.warning("CSS processing failed for %s: %s", css_url, exc)
            return css_content

    def _rewrite_html(
        self,
        html: str,
        url_to_local: dict[str, str],
        raw_to_local: dict[str, str],
        base_url: str,
    ) -> str:
        for original_url, local_path in url_to_local.items():
            html = html.replace(f'"{original_url}"', f'"{local_path}"')
            html = html.replace(f"'{original_url}'", f"'{local_path}'")

        for raw_value, local_path in raw_to_local.items():
            if raw_value not in html:
                continue
            html = html.replace(f'"{raw_value}"', f'"{local_path}"')
            html = html.replace(f"'{raw_value}'", f"'{local_path}'")

        return html

    def _inline_css(
        self,
        html: str,
        assets_bytes: dict[str, bytes],
        url_to_local: dict[str, str],
    ) -> str:
        """
        Replace <link rel="stylesheet"> tags with inline <style> blocks.
        Also embeds fonts and images referenced inside CSS as base64 data URIs.
        """
        import re
        import base64

        # Build reverse map: local_path -> bytes
        local_to_bytes: dict[str, bytes] = {}
        for _asset_url, local_path in url_to_local.items():
            filename = local_path.rsplit('/', 1)[-1]
            if filename in assets_bytes:
                local_to_bytes[local_path] = assets_bytes[filename]

        link_pattern = re.compile(
            r'<link[^>]+rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*/?>',
            re.IGNORECASE
        )

        def replace_link(match):
            href = match.group(1)
            css_bytes = local_to_bytes.get(href)
            if not css_bytes:
                return match.group(0)

            try:
                css_text = css_bytes.decode('utf-8', errors='ignore')

                # Match any url() reference, not just assets/ prefixed ones
                font_pattern = re.compile(r'url\(["\']?([^)"\']+)["\']?\)')

                mime_map = {
                    '.woff': 'font/woff',
                    '.woff2': 'font/woff2',
                    '.ttf': 'font/truetype',
                    '.eot': 'application/vnd.ms-fontobject',
                    '.otf': 'font/opentype',
                    '.png': 'image/png',
                    '.jpg': 'image/jpeg',
                    '.jpeg': 'image/jpeg',
                    '.gif': 'image/gif',
                    '.svg': 'image/svg+xml',
                }

                def embed_asset(font_match):
                    inner_path = font_match.group(1)

                    # Skip data URIs and anchor references
                    if inner_path.startswith('data:') or inner_path.startswith('#'):
                        return font_match.group(0)

                    asset_filename = None
                    asset_bytes_data = None

                    if inner_path.startswith('assets/') or '/clone/assets/' in inner_path:
                        asset_filename = inner_path.rsplit('/', 1)[-1]
                        asset_bytes_data = assets_bytes.get(asset_filename)

                    # Fallback: match via url_to_local by URL suffix or basename
                    if asset_bytes_data is None:
                        inner_basename = inner_path.split('/')[-1].split('?')[0]
                        for orig_url, local_path in url_to_local.items():
                            if inner_path in orig_url or (
                                inner_basename and orig_url.endswith(inner_basename)
                            ):
                                fn = local_path.rsplit('/', 1)[-1]
                                b = assets_bytes.get(fn)
                                if b:
                                    asset_filename = fn
                                    asset_bytes_data = b
                                    break

                    if not asset_bytes_data:
                        return font_match.group(0)

                    ext = Path(asset_filename).suffix.lower()
                    mime = mime_map.get(ext, 'application/octet-stream')
                    b64 = base64.b64encode(asset_bytes_data).decode('ascii')
                    return f"url('data:{mime};base64,{b64}')"

                css_text = font_pattern.sub(embed_asset, css_text)
                return f'<style>\n{css_text}\n</style>'

            except Exception as exc:
                logger.warning("Could not inline CSS %s: %s", href, exc)
                return match.group(0)

        return link_pattern.sub(replace_link, html)

    def _fix_viewport(self, html: str) -> str:
        """
        Ensure the cloned page has a correct viewport meta tag.
        If one exists, leave it alone.
        If one is missing, inject the standard responsive viewport tag.
        If one exists but uses a fixed width, replace it with responsive.
        """
        import re

        viewport_pattern = re.compile(
            r'<meta[^>]+name=["\']viewport["\'][^>]*/?>',
            re.IGNORECASE
        )

        correct_viewport = (
            '<meta name="viewport" '
            'content="width=device-width, initial-scale=1.0">'
        )

        existing = viewport_pattern.search(html)

        if not existing:
            # No viewport tag — inject one
            if '<head>' in html:
                html = html.replace('<head>', f'<head>\n{correct_viewport}', 1)
            elif '<HEAD>' in html:
                html = html.replace('<HEAD>', f'<HEAD>\n{correct_viewport}', 1)
            logger.debug("Injected missing viewport meta tag")
            return html

        # Viewport exists — check if it uses a fixed pixel width
        existing_tag = existing.group(0)
        content_match = re.search(
            r'content=["\']([^"\']+)["\']',
            existing_tag,
            re.IGNORECASE
        )

        if content_match:
            content = content_match.group(1)
            # If it sets a fixed numeric width (not device-width), replace it
            if re.search(r'width=\d+', content):
                html = html.replace(existing_tag, correct_viewport, 1)
                logger.debug(
                    "Replaced fixed-width viewport '%s' with responsive",
                    content
                )

        return html

    def _extract_forms(self, page, job_id: str) -> list[FormData]:
        forms = []
        for form_el in page.css("form") or []:
            original_action = form_el.attrib.get("action", "")
            method = (form_el.attrib.get("method", "get")).upper()
            fields = [
                inp.attrib.get("name", inp.attrib.get("id", "unnamed"))
                for inp in (form_el.css("input, select, textarea") or [])
            ]
            forms.append(FormData(
                action=original_action,
                method=method,
                fields=fields,
            ))
        return forms

    def _extract_links(self, page, base_url: str) -> tuple[list[str], list[str]]:
        base_domain = urlparse(base_url).netloc
        internal, external = [], []
        for a in page.css("a") or []:
            href = a.attrib.get("href", "").strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue
            absolute = urljoin(base_url, href)
            if urlparse(absolute).netloc == base_domain:
                internal.append(absolute)
            else:
                external.append(absolute)
        return internal, external

    def _extract_anchor_map(self, page, base_url: str) -> dict[str, str]:
        """
        Map each internal-link raw href (as authored) to its absolute URL,
        so the crawler can rewrite that exact href in the page's own HTML.
        """
        base_domain = urlparse(base_url).netloc
        anchors: dict[str, str] = {}
        for a in page.css("a") or []:
            href = a.attrib.get("href", "").strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue
            absolute = urljoin(base_url, href)
            if urlparse(absolute).netloc == base_domain:
                anchors[href] = absolute
        return anchors

    async def _process_page(
        self,
        html: str,
        page,
        page_url: str,
        job_id: str,
        base_domain: str,
        anchors: dict[str, str],
        page_routes: dict[str, str],
        assets_bytes: dict[str, bytes],
        url_to_local: dict[str, str],
        raw_to_local: dict[str, str],
        seen: set[str],
        intercepted_assets: dict[str, bytes] | None = None,
    ) -> tuple[str, dict[str, bytes], dict[str, str], dict[str, str], int]:
        """
        Run the full page-processing pipeline (asset download, CSS
        processing, CSS inlining, viewport fix, form rewrite, link
        rewrite, interceptor injection) on a single page's HTML. Used by
        both the main crawl loop and the live proxy fallback, so every
        page — crawled or lazily fetched — gets identical treatment.

        assets_bytes/url_to_local/raw_to_local/seen are threaded through
        (mutated and returned) so assets are deduped across pages in the
        same job, exactly as the crawl loop already did before this was
        extracted.

        Returns: (rewritten_html, assets_bytes, url_to_local, raw_to_local, failed_count)
        """
        assets_bytes, url_to_local, raw_to_local, failed_count = \
            await self._download_assets(
                page, page_url, job_id,
                assets_bytes=assets_bytes, url_to_local=url_to_local,
                raw_to_local=raw_to_local, seen=seen,
            )

        for asset_url, asset_bytes in (intercepted_assets or {}).items():
            if asset_url in url_to_local:
                continue
            extension = _safe_extension(asset_url)
            filename = secrets.token_hex(8) + extension
            while filename in assets_bytes:
                filename = secrets.token_hex(8) + extension
            assets_bytes[filename] = asset_bytes
            local_path = f'/clone/assets/{job_id}/{filename}'
            url_to_local[asset_url] = local_path
            seen.add(asset_url)
            parsed = urlparse(asset_url)
            if parsed.path and parsed.path not in url_to_local:
                url_to_local[parsed.path] = local_path
                raw_to_local[parsed.path] = local_path

        html = self._rewrite_html(html, url_to_local, raw_to_local, page_url)
        html = self._inline_css(html, assets_bytes, url_to_local)
        html = self._fix_viewport(html)
        html = _rewrite_forms_to_capture(html, job_id)

        # Point every internal link at the local /clone/{job_id}/...
        # route — pages we actually crawled resolve immediately; pages
        # outside the crawl's depth/page limits (or, for the proxy
        # fallback, simply not in page_routes at all) still get a local
        # route so navigation never leaves localhost.
        for raw_href, absolute in anchors.items():
            child_norm = _normalize_url(absolute)
            target = page_routes.get(child_norm) or _local_page_route(
                job_id, _url_path(absolute)
            )
            if raw_href == target:
                continue
            html = html.replace(f'"{raw_href}"', f'"{target}"')
            html = html.replace(f"'{raw_href}'", f"'{target}'")

        html = inject_interceptor(html, job_id, base_domain)

        return html, assets_bytes, url_to_local, raw_to_local, failed_count

    async def _fetch_one(
        self, url: str, fetcher_name: str
    ) -> tuple[str, object, dict[str, bytes]]:
        """
        Fetch a single page. Returns (html_content, page_selector, intercepted_assets).
        """
        if fetcher_name == "DynamicFetcher":
            html_content, intercepted_assets = \
                await self._fetch_page_with_interception(url)
            # Build a parse-able page object from the rendered HTML for
            # forms/links/title extraction and HTML-tag asset discovery
            page = ScraplingSelector(html_content, url=url)
            return html_content, page, intercepted_assets

        raw_page = await asyncio.to_thread(self._fetch_page, url, fetcher_name)
        html_content = (
            raw_page.html_content
            if hasattr(raw_page, "html_content")
            else str(raw_page)
        )
        return html_content, raw_page, {}

    async def fetch_proxy_page(
        self, target_url: str, job_id: str
    ) -> tuple[str, dict[str, bytes]]:
        """
        Live, on-demand fetch of a page that fell outside the original
        crawl's depth/page limits — used by the
        /clone/proxy/{job_id}/{path} fallback route. Runs the SAME full
        processing pipeline as a normally crawled page (assets, CSS,
        inlining, link/form rewriting, interceptor injection) via
        _process_page(), so the result is visually identical to what a
        deeper initial crawl would have produced. The caller (main.py) is
        responsible for persisting the returned HTML/assets via
        storage.save_page(), upgrading this page from "proxied" to
        "stored" for all future visits.

        Returns: (rewritten_html, assets_bytes) — assets_bytes contains
        ONLY the assets newly downloaded for this page (not the whole
        job's asset set), since the job's existing asset map isn't
        available in this single-page, uncached code path.
        """
        if not is_safe_url(target_url):
            raise ValueError(f"URL '{target_url}' is not allowed for proxying.")

        raw_page = await asyncio.wait_for(
            asyncio.to_thread(self._fetch_page, target_url, "Fetcher"),
            timeout=PAGE_FETCH_TIMEOUT_SECONDS,
        )
        html = (
            raw_page.html_content
            if hasattr(raw_page, "html_content")
            else str(raw_page)
        )

        # DNS-rebinding re-check — same reasoning as the crawl loop: the
        # target's origin was validated when the original job was created,
        # but that could have been minutes, hours, or days ago.
        if not check_no_rebind(urlparse(target_url).hostname):
            raise ValueError(
                f"Aborted proxy fetch for {target_url}: possible DNS rebinding detected"
            )

        base_domain = urlparse(target_url).netloc
        anchors = self._extract_anchor_map(raw_page, target_url)
        url_path = _url_path(target_url)
        page_routes = {
            _normalize_url(target_url): _local_page_route(job_id, url_path)
        }

        html, assets_bytes, _url_to_local, _raw_to_local, _failed = \
            await self._process_page(
                html=html,
                page=raw_page,
                page_url=target_url,
                job_id=job_id,
                base_domain=base_domain,
                anchors=anchors,
                page_routes=page_routes,
                assets_bytes={},
                url_to_local={},
                raw_to_local={},
                seen=set(),
            )

        return html, assets_bytes

    async def clone(
        self,
        url: str,
        job_id: str,
        force_fetcher: str | None = None,
        max_depth: int | None = None,
        max_pages: int | None = None,
        progress_callback=None,
    ) -> CloneResult:
        """
        progress_callback, if given, is called with the current crawled
        page count every few pages — lets the caller surface crawl
        progress (e.g. to job status) for jobs that can now legitimately
        take several minutes at higher page counts.
        """
        if not is_safe_url(url):
            raise ValueError(
                f"URL '{url}' is not allowed. "
                "Only public HTTP/HTTPS URLs are accepted. "
                "Internal, private, and loopback addresses are blocked."
            )

        depth_limit = min(max_depth, HARD_MAX_DEPTH) if max_depth else DEFAULT_MAX_DEPTH
        pages_limit = min(max_pages, HARD_MAX_PAGES) if max_pages else DEFAULT_MAX_PAGES
        depth_limit = max(0, depth_limit)
        pages_limit = max(1, pages_limit)

        entry_normalized = _normalize_url(url)
        base_domain = urlparse(url).netloc

        # ── Phase 1: breadth-first crawl of internal links ──────────────────
        visited: dict[str, str] = {}  # normalized_url -> page_id
        crawled: dict[str, dict] = {}  # normalized_url -> raw page data
        queue: deque[tuple[str, int]] = deque([(url, 0)])
        timed_out_pages: list[str] = []
        crawl_deadline = time.monotonic() + TOTAL_CRAWL_TIMEOUT_SECONDS

        while queue and len(crawled) < pages_limit:
            if time.monotonic() > crawl_deadline:
                logger.warning(
                    "Job %s exceeded the %.0fs total crawl timeout — "
                    "stopping with %d page(s) already cloned",
                    job_id, TOTAL_CRAWL_TIMEOUT_SECONDS, len(crawled),
                )
                break

            current_url, depth = queue.popleft()
            norm = _normalize_url(current_url)
            if norm in visited:
                continue
            if not is_safe_url(current_url):
                continue

            if force_fetcher and force_fetcher != "Auto":
                fetcher_name = force_fetcher
            else:
                fetcher_name = await self.auto_select_fetcher(current_url)
            logger.info(
                "Cloning %s with %s (job_id=%s, depth=%d)",
                current_url, fetcher_name, job_id, depth,
            )

            try:
                html_content, page, intercepted_assets = await asyncio.wait_for(
                    self._fetch_one(current_url, fetcher_name),
                    timeout=PAGE_FETCH_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                logger.warning("Page fetch timed out: %s", current_url)
                timed_out_pages.append(current_url)
                if norm == entry_normalized:
                    raise RuntimeError(f"Fetch timed out for {url}") from None
                continue
            except Exception as exc:
                if norm == entry_normalized:
                    raise RuntimeError(f"Fetch failed for {url}: {exc}") from exc
                logger.warning("Fetch failed for %s: %s", current_url, exc)
                continue

            # DNS-rebinding re-check — is_safe_url() validated this
            # hostname before we connected, but the DNS record could
            # have been repointed at a private/loopback address in the
            # time between that check and the fetch actually completing.
            # Re-resolve now, before this response's HTML/assets are
            # processed or stored, and drop the page if it rebound.
            if not check_no_rebind(urlparse(current_url).hostname):
                if norm == entry_normalized:
                    raise RuntimeError(
                        f"Aborted fetch for {url}: possible DNS rebinding detected"
                    )
                logger.warning(
                    "Skipping %s: possible DNS rebinding detected", current_url
                )
                continue

            page_id = _url_path(current_url)
            visited[norm] = page_id

            anchors = self._extract_anchor_map(page, current_url)
            forms = self._extract_forms(page, job_id)
            links_internal, links_external = self._extract_links(page, current_url)
            title_el = page.find("title")
            page_title = title_el.text if title_el else ""

            crawled[norm] = {
                "url": current_url,
                "page_id": page_id,
                "html": html_content,
                "page": page,
                "intercepted_assets": intercepted_assets,
                "anchors": anchors,
                "forms": forms,
                "links_internal": links_internal,
                "links_external": links_external,
                "page_title": page_title,
                "fetcher_used": fetcher_name,
            }

            if progress_callback and (len(crawled) == 1 or len(crawled) % 5 == 0):
                try:
                    progress_callback(len(crawled))
                except Exception as exc:
                    logger.warning("progress_callback failed: %s", exc)

            if depth < depth_limit:
                for absolute in anchors.values():
                    child_norm = _normalize_url(absolute)
                    if child_norm not in visited and len(crawled) + len(queue) < pages_limit:
                        queue.append((absolute, depth + 1))

        if entry_normalized not in crawled:
            raise RuntimeError(
                f"Fetch failed for {url}: total crawl timeout exceeded "
                "before the entry page could be cloned"
            )

        # ── Phase 2: process each page — assets, CSS, forms, links, ─────────
        # interceptor — via the shared _process_page() pipeline, deduping
        # assets across pages exactly as before (page_routes only depends
        # on crawled page paths, all known now that Phase 1 is done, so it
        # can be built once upfront).
        page_routes = {
            norm: _local_page_route(job_id, data["page_id"])
            for norm, data in crawled.items()
        }

        assets_bytes: dict[str, bytes] = {}
        url_to_local: dict[str, str] = {}
        raw_to_local: dict[str, str] = {}
        seen: set[str] = set()
        total_failed = 0

        pages: list[PageResult] = []
        for data in crawled.values():
            html, assets_bytes, url_to_local, raw_to_local, failed_count = \
                await self._process_page(
                    html=data["html"],
                    page=data["page"],
                    page_url=data["url"],
                    job_id=job_id,
                    base_domain=base_domain,
                    anchors=data["anchors"],
                    page_routes=page_routes,
                    assets_bytes=assets_bytes,
                    url_to_local=url_to_local,
                    raw_to_local=raw_to_local,
                    seen=seen,
                    intercepted_assets=data["intercepted_assets"],
                )
            total_failed += failed_count

            pages.append(PageResult(
                page_id=data["page_id"],
                url=data["url"],
                html=html,
                page_title=data["page_title"],
                forms=data["forms"],
                links_internal=data["links_internal"],
                links_external=data["links_external"],
            ))

        entry_data = crawled[entry_normalized]
        entry_page = next(p for p in pages if p.page_id == entry_data["page_id"])

        logger.info(
            "Cloned %d page(s) for job %s (depth_limit=%d, pages_limit=%d, timed_out=%d)",
            len(pages), job_id, depth_limit, pages_limit, len(timed_out_pages),
        )

        return CloneResult(
            job_id=job_id,
            url=url,
            fetcher_used=entry_data["fetcher_used"],
            html=entry_page.html,
            clone_path="",  # filled by main.py after storage saves
            assets_downloaded=len(assets_bytes),
            assets_failed=total_failed,
            assets_data=assets_bytes,
            forms=entry_page.forms,
            links_internal=entry_page.links_internal,
            links_external=entry_page.links_external,
            page_title=entry_page.page_title,
            timestamp=datetime.now(timezone.utc).isoformat(),
            pages=pages,
            timed_out_pages=timed_out_pages,
            entry_path=entry_page.page_id,
        )
