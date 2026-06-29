import asyncio
import ipaddress
import logging
import secrets
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse


import httpx
from scrapling.fetchers import DynamicFetcher, Fetcher, StealthyFetcher

from models import CloneResult, FormData

logger = logging.getLogger(__name__)


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

        try:
            ip_str = socket.gethostbyname(parsed.hostname)
            ip = ipaddress.ip_address(ip_str)

            if (ip.is_private or
                ip.is_loopback or
                ip.is_reserved or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_unspecified):
                return False

        except socket.gaierror:
            return False

        return True

    except Exception:
        return False

ASSET_TAGS = [
    ("img", "src"),
    ("link", "href"),
    ("script", "src"),
]


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
        from urllib.parse import urlparse as _urlparse
        domain = _urlparse(url).netloc.lower().replace('www.', '')
        if any(d in domain for d in self.ALWAYS_DYNAMIC_DOMAINS):
            logger.info("Domain %s is JS-heavy, forcing DynamicFetcher", domain)
            return "DynamicFetcher"

        if url.startswith("http://"):
            return "Fetcher"
        try:
            page = Fetcher(auto_match=False).get(url, stealthy_headers=True)
            html = page.html_content if hasattr(page, "html_content") else str(page)
            if "cf-browser-verification" in html or "challenge-running" in html:
                return "StealthyFetcher"
            if page.css("form") or page.css("input"):
                return "Fetcher"
            root = page.css("div#root, div#app")
            inputs = page.css("input")
            if root and not inputs:
                return "DynamicFetcher"
            return "Fetcher"
        except Exception:
            logger.exception("Auto-select probe failed for %s", url)
            return "Fetcher"

    def _fetch_page(self, url: str, fetcher_name: str):
        if fetcher_name == "DynamicFetcher":
            return DynamicFetcher(auto_match=False).fetch(url)
        if fetcher_name == "StealthyFetcher":
            fetcher = StealthyFetcher(auto_match=False)
            return fetcher.fetch(url)          
        return Fetcher(auto_match=False).get(url, stealthy_headers=True)

    async def _download_assets(
        self, page, base_url: str
    ) -> tuple[dict[str, bytes], dict[str, str], int]:
        """
        Download all assets.
        Returns: assets_bytes, url_to_local mapping, failed_count
        """
        assets_bytes: dict[str, bytes] = {}
        url_to_local: dict[str, str] = {}
        raw_to_local: dict[str, str] = {}
        seen: set[str] = set()
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

        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            for absolute_url, raw_value in urls_to_fetch:
                try:
                    response = await client.get(absolute_url)
                    response.raise_for_status()
                    parsed = urlparse(absolute_url)
                    extention = Path(parsed.path).suffix or ""
                    filename = secrets.token_hex(8) + extention
                    assets_bytes[filename] = response.content
                    url_to_local[absolute_url] = f"assets/{filename}"
                    raw_to_local[raw_value] = f"assets/{filename}"
                    logger.debug("Downloaded asset: %s", absolute_url)

                    if filename.endswith('.css'):
                        processed = await self._process_css_assets(
                            css_content=response.content,
                            css_url=absolute_url,
                            assets_bytes=assets_bytes,
                            url_to_local=url_to_local,
                            client=client,
                            seen=seen,
                        )
                        assets_bytes[filename] = processed

                except Exception:
                    logger.warning("Failed to download asset: %s", absolute_url)
                    failed_count += 1

        return assets_bytes, url_to_local, failed_count, raw_to_local

    async def _process_css_assets(
        self,
        css_content: bytes,
        css_url: str,
        assets_bytes: dict[str, bytes],
        url_to_local: dict[str, str],
        client: httpx.AsyncClient,
        seen: set[str],
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
                    extension = Path(urlparse(absolute).path).suffix or ''
                    filename = secrets.token_hex(8) + extension
                    while filename in assets_bytes:
                        filename = secrets.token_hex(8) + extension
                    assets_bytes[filename] = response.content
                    local_path = f'assets/{filename}'
                    url_to_local[absolute] = local_path
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

    def _extract_forms(self, page) -> list[FormData]:
        forms = []
        for form_el in page.css("form") or []:
            action = form_el.attrib.get("action", "")
            method = (form_el.attrib.get("method", "get")).upper()
            fields = [
                inp.attrib.get("name", inp.attrib.get("id", "unnamed"))
                for inp in (form_el.css("input, select, textarea") or [])
            ]
            forms.append(FormData(action=action, method=method, fields=fields))
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

    async def clone(
        self, url: str, job_id: str, force_fetcher: str | None = None
    ) -> CloneResult:
        if not is_safe_url(url):
            raise ValueError(
                f"URL '{url}' is not allowed. "
                "Only public HTTP/HTTPS URLs are accepted. "
                "Internal, private, and loopback addresses are blocked."
            )

        if force_fetcher and force_fetcher != "Auto":
            fetcher_name = force_fetcher
        else:
            fetcher_name = await self.auto_select_fetcher(url)
        logger.info("Cloning %s with %s (job_id=%s)", url, fetcher_name, job_id)

        try:
            page = await asyncio.to_thread(self._fetch_page, url, fetcher_name)
        except Exception as exc:
            raise RuntimeError(f"Fetch failed for {url}: {exc}") from exc

        html_content = page.html_content if hasattr(page, "html_content") else str(page)

        assets_bytes, url_to_local, failed_count, raw_to_local = \
            await self._download_assets(page, url)

        rewritten_html = self._rewrite_html(
            html_content, url_to_local, raw_to_local, url
        )

        forms = self._extract_forms(page)
        links_internal, links_external = self._extract_links(page, url)

        # ── Fix: safely extract page title ───────────────────────────────────
        title_el = page.find("title")
        page_title = title_el.text if title_el else ""

        return CloneResult(
            job_id=job_id,
            url=url,
            fetcher_used=fetcher_name,
            html=rewritten_html,
            clone_path="",  # filled by main.py after storage saves
            assets_downloaded=len(assets_bytes),
            assets_failed=failed_count,
            assets_data=assets_bytes,
            forms=forms,
            links_internal=links_internal,
            links_external=links_external,
            page_title=page_title,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
