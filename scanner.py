"""
Web Security Scanner v8.0 — Production-Grade DAST Engine.

Architecture:
    cli.py                         CLI entry point
    scanner.py                     Orchestrator (lifecycle, spider, detector dispatch)
    src/
      schemas/                     Canonical data models (Finding, HttpRequest, HttpResponse)
      core/                        Constants, exceptions, base types
      engine/
        crawler/                   Spider, SPA rendering, URL dedup
        http_client.py             Unified HTTP client (Playwright + aiohttp)
        passive_proxy.py           Passive traffic analysis (17 sensitive patterns)
        session_manager.py         Multi-step auth macro recording/replay
        concurrent.py              Adaptive rate limiting + circuit breaker
        browser_pool.py            Parallel Playwright context pool
        dedup.py                   Multi-dimensional root-cause grouping
        persistence.py             SQLite scan history + trend analysis
      detectors/                   28 vulnerability detection modules
      payloads/                    500+ payloads (SQLi, XSS, SSTI, SSRF, Traversal, CMDi)
      waf/                         WAF fingerprinting + adaptive bypass
      oob/                         HTTP+DNS callback server for blind detection
      reporting/                   Professional HTML reports
      compliance/                  PCI-DSS / HIPAA / SOC2 / ISO 27001 mapping
      plugins/                     YAML hot-reload plugin loader
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.constants import SEVERITY
from src.engine.http_client import HttpClient, HAS_PLAYWRIGHT as _HAS_PW
from src.engine.passive_proxy import PassiveProxy
from src.engine.concurrent import ConcurrentScanner
from src.engine.dedup import DedupEngine
from src.engine.session_manager import SessionManager
from src.engine.browser_pool import BrowserPool
from src.engine.persistence import ScanPersistence
from src.engine.crawler.spider import Spider
from src.waf.detector import WAFDetector
from src.oob.callback import CallbackServer
from src.logging import log, Logger, LogLevel
from src.policy import ScanPolicy, get_policy

HAS_PLAYWRIGHT = _HAS_PW

try:
    from src.plugins import PluginLoader
except ImportError:
    PluginLoader = None

from src.reporting.html_reporter import HTMLReporter
from src.reporting.compliance_reporter import ComplianceReporter


class WebSecurityScanner:
    """Tier-1 DAST Scanner — orchestrates crawl + detection + reporting.

    Usage:
        scanner = WebSecurityScanner(target_url="https://target.com", policy="full")
        asyncio.run(scanner.run())
    """

    def __init__(
        self,
        target_url: str,
        *,
        policy: str = "full",
        output: str = "report.json",
        max_pages: int = 150,
        timeout: int = 15000,
        no_spa: bool = False,
        passive_only: bool = False,
        oob_port: int = 8889,
        log_level: str = "INFO",
        fail_on: str = "none",
        compliance: str = "",
        html_report: bool = True,
        no_browser: bool = False,
        proxy: str = "",
        custom_headers: dict[str, str] | None = None,
        custom_cookies: dict[str, str] | None = None,
        scan_id: str = "",
        resume: bool = False,
        is_internal: bool = False,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.output_file = output
        self.timeout = timeout
        self.no_spa = no_spa
        self.passive_only = passive_only
        self.oob_port = oob_port
        self.fail_on = fail_on
        self.compliance_fw = compliance
        self.html_report = html_report
        self.no_browser = no_browser or not HAS_PLAYWRIGHT
        self.proxy = proxy
        self.custom_headers = custom_headers or {}
        self.custom_cookies = custom_cookies or {}
        self.scan_id = scan_id or hashlib.md5(
            f"{self.target_url}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        self.resume_mode = resume
        self.is_internal = is_internal
        self.completed_detectors: list[str] = []

        log.set_level(LogLevel[log_level.upper()])

        try:
            self.policy: ScanPolicy = get_policy(policy)
        except ValueError:
            log.warning("Unknown policy '%s', using 'full'", policy)
            self.policy = get_policy("full")
        if max_pages:
            self.policy.max_pages = max_pages

        # ── Engine components ──
        self.passive_proxy = PassiveProxy(is_internal=self.is_internal)
        self.session_mgr = SessionManager(self.target_url)
        self.waf_adaptive = None  # Will be set in start() after WAF detection
        self.concurrent = ConcurrentScanner(
            max_concurrent=self.policy.concurrent_requests,
            rate_per_second=self.policy.rate_per_second,
            timeout=timeout,
        )
        self.concurrent.set_scope(self.target_url)
        self.dedup = DedupEngine()
        self.browser_pool = BrowserPool(
            pool_size=min(self.policy.concurrent_requests, 6))
        self.browser_pool.set_passive_proxy(self.passive_proxy)
        self.persistence = ScanPersistence()
        self.waf_detector = WAFDetector()
        self.plugin_loader = PluginLoader() if PluginLoader else None
        self.oob_server = CallbackServer(http_port=self.oob_port)
        self.http: HttpClient | None = None

        # ── Scan state ──
        self.findings: list[dict] = []
        self.visited: set[str] = set()
        self.forms_found: list[dict] = []
        self.js_files: list[str] = []
        self.console_logs: list[str] = []
        self.detected_waf: str | None = None
        self.auth_type: str | None = None
        self.scan_start_time: datetime | None = None
        self.tech_stack: dict[str, str] = {}

        # ── Browser handles ──
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    # ═══════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════

    def add_finding(
        self, category: str, severity: str, title: str,
        endpoint: str = "", evidence: str = "", payload: str = "",
        parameter: str = "", remediation: str = "",
        cvss: float | None = None, cwe: str = "",
        **extra: Any,
    ) -> None:
        finding: dict = {
            "id": f"WEB-{len(self.findings) + 1:03d}",
            "category": category,
            "severity": severity,
            "title": title,
            "endpoint": endpoint,
            "evidence": evidence,
            "payload": payload,
            "parameter": parameter,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if remediation:
            finding["remediation"] = remediation
        if cvss:
            finding["cvss"] = cvss
        if cwe:
            finding["cwe"] = cwe
        finding.update(extra)
        self.findings.append(finding)
        self.dedup.add_finding(finding)
        log.finding(severity, title, endpoint=endpoint, payload=str(payload)[:80])

    async def _safe_goto(self, url: str, wait_until: str = "domcontentloaded") -> bool:
        try:
            await self._page.goto(url, wait_until=wait_until, timeout=self.timeout)
            return True
        except Exception:
            log.debug("Navigation failed: %s", url[:100])
            return False

    async def _check_xss_execution(self, marker: str = "XSS_CONFIRMED") -> bool:
        await asyncio.sleep(0.8)
        return marker in str(self.console_logs)

    async def _waf_aware_request(
        self, url: str, method: str = "GET", headers: dict | None = None,
        data: str | None = None, payload: str | None = None,
        timeout: int | None = None,
    ) -> list[tuple[dict, Any]]:
        """Send a request with WAF bypass variants if WAF is detected.

        Returns list of (request_dict, response_or_None) tuples.
        Detectors should iterate and check each response.
        """
        t = timeout or self.timeout
        base_request = {
            "url": url,
            "method": method,
            "headers": headers or {},
            "data": data or "",
            "timeout": t,
        }

        if not self.waf_adaptive or not self.waf_adaptive.is_active:
            # No WAF — send single request
            try:
                if self._context and hasattr(self._context, 'request'):
                    resp = await self._context.request.fetch(
                        url, method=method, headers=headers or {},
                        data=data, timeout=t, max_redirects=0)
                    return [(base_request, resp)]
            except Exception:
                pass
            return [(base_request, None)]

        # WAF detected — generate bypass variants
        variants = self.waf_adaptive.wrap_request(base_request, max_total=6)
        results: list[tuple[dict, Any]] = []

        for variant in variants:
            try:
                v_url = variant.get("url", url)
                v_method = variant.get("method", method)
                v_headers = variant.get("headers", headers or {})
                v_data = variant.get("data", data)

                if self._context and hasattr(self._context, 'request'):
                    resp = await self._context.request.fetch(
                        v_url, method=v_method, headers=v_headers,
                        data=v_data, timeout=t, max_redirects=0)
                    if resp and resp.status < 400:
                        strat = variant.get("_bypass_strategy", "")
                        self.waf_adaptive.report_bypass_success(strat)
                    results.append((variant, resp))
            except Exception:
                results.append((variant, None))

        return results if results else [(base_request, None)]

    def get_exit_code(self) -> int:
        sevs = {f.get("severity", "Info") for f in self.dedup.finalize()}
        if "Critical" in sevs:
            return 4
        if "High" in sevs:
            return 3
        if "Medium" in sevs:
            return 2
        return 0

    # ═══════════════════════════════════════════════════════
    # Lifecycle
    # ═══════════════════════════════════════════════════════

    async def start(self) -> None:
        self.scan_start_time = datetime.now(timezone.utc)
        log.info("=" * 60)
        log.info("Web Security Scanner v7.5 — Production-Grade DAST Engine")
        log.info("Target: %s | Policy: %s", self.target_url, self.policy.name)
        log.info("Browser: %s", "No" if self.no_browser else "Playwright/Chromium")
        log.info("=" * 60)

        # OOB callback server
        self.oob_server.start()
        log.info("OOB callback server started on port %d", self.oob_port)

        # YAML plugins
        if self.plugin_loader:
            count = self.plugin_loader.load_all()
            if count > 0:
                log.info("Plugins loaded: %d rules from %d files",
                         count, len(self.plugin_loader.loaded_files))

        # Browser or curl mode
        if not self.no_browser:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-dev-shm-usage"])
            self._context = await self._browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ignore_https_errors=True,
                viewport={"width": 1440, "height": 900})
            self._page = await self._context.new_page()

            # Console & dialog hooks
            self._page.on("console", lambda msg: self.console_logs.append(msg.text))
            self._page.on("dialog", lambda dialog: dialog.dismiss())

            # Passive proxy hooks
            self._page.on("request", lambda req: self.passive_proxy.intercept_request(
                req.url, req.method,
                dict(req.headers) if req.headers else {},
                req.post_data if hasattr(req, "post_data") else None))

            async def _on_resp(resp):
                try:
                    body = await resp.text()
                    self.passive_proxy.intercept_response(
                        resp.url, resp.status,
                        dict(resp.headers) if resp.headers else {}, body)
                except Exception:
                    log.debug("Response intercept failed for %s", resp.url)

            self._page.on("response", lambda resp: asyncio.ensure_future(_on_resp(resp)))
            await self.browser_pool.start()

            # WAF detection
            try:
                resp = await self._context.request.get(
                    self.target_url, timeout=self.timeout)
                self.detected_waf = self.waf_detector.detect(
                    dict(resp.headers), await resp.text(), status=resp.status)
                if self.detected_waf:
                    log.info("WAF detected: %s (confidence: %.0f%%)",
                             self.detected_waf, self.waf_detector.confidence * 100)
                    from src.engine.waf_adaptive import WAFAdaptiveEngine
                    self.waf_adaptive = WAFAdaptiveEngine(
                        self.waf_detector, self.detected_waf)
                    log.info("WAF adaptive bypass engine activated")
            except Exception:
                log.debug("WAF detection failed")

            # Authentication
            await self.session_mgr.discover_auth_endpoints(self._page)
            if not self.policy.skip_auth_testing:
                macro_path = Path("auth_macros.json")
                if macro_path.exists():
                    try:
                        self.session_mgr.load_macros(str(macro_path))
                    except Exception:
                        log.debug("Macro load failed")
                if await self.session_mgr.authenticate(self._context, "user1"):
                    self.auth_type = self.session_mgr.auth_type
                    log.info("Authenticated as user1 (type=%s)", self.auth_type)
                    await self.session_mgr.authenticate(self._context, "user2")
        else:
            log.info("Curl-only mode: using aiohttp for HTTP requests")
            self.http = HttpClient(no_browser=True, timeout=self.timeout)
            await self.http.start()
            self._context = self.http

        log.info("Scanner ready. Starting assessment...")

    async def stop(self) -> None:
        log.info("Shutting down...")
        self.oob_server.stop()
        log.info("OOB server stopped")
        await self.browser_pool.stop()
        if self.http:
            await self.http.stop()
        if not self.no_browser:
            for obj in [self._page, self._context]:
                if obj:
                    try:
                        await obj.close()
                    except Exception:
                        pass
            if self._browser:
                try:
                    await self._browser.close()
                except Exception:
                    pass
            if self._playwright:
                try:
                    await self._playwright.stop()
                except Exception:
                    pass
        self.persistence.close()

    # ═══════════════════════════════════════════════════════
    # Phase 1: Spider (delegated to Spider)
    # ═══════════════════════════════════════════════════════

    async def phase_spider(self) -> None:
        log.info("--- Phase 1: Spider ---")

        # Resume: restore state from checkpoint
        if self.resume_mode:
            cp = self.persistence.load_checkpoint(self.scan_id)
            if cp and cp["phase"] in ("spider_done", "detecting", "plugins_done", "done"):
                log.info("Resuming from checkpoint: phase=%s, pages=%d, findings=%d",
                         cp["phase"], len(cp["visited_urls"]), cp["findings_count"])
                self.visited = cp["visited_urls"]
                self.forms_found = cp["forms_found"]
                self.js_files = cp["js_files"]
                self.completed_detectors = cp["completed_detectors"]
                if cp["phase"] != "spider_done":
                    log.info("Spider already completed, skipping to detection")
                    return
            elif cp:
                log.info("Resuming spider from checkpoint...")

        if self.no_browser:
            log.info("Curl-only spider: fetching target page for passive analysis")
            resp = await self.http.get(self.target_url)
            if resp and resp.body:
                self.passive_proxy.intercept_response(
                    resp.url, resp.status, resp.headers, resp.body)
                self.visited.add(self.target_url)
                crawled = await self.http.spider(
                    self.target_url,
                    max_pages=min(self.policy.max_pages, 10),
                    max_depth=self.policy.crawl_depth,
                )
                self.visited, self.forms_found, self.js_files = crawled
            self._save_checkpoint("spider_done")
            return

        if not self._page:
            log.info("No browser — skipping spider")
            return

        spider = Spider(
            start_url=self.target_url,
            max_pages=self.policy.max_pages,
            max_depth=self.policy.crawl_depth,
            rate_per_second=self.policy.rate_per_second,
            spa_mode=not self.no_spa,
            timeout_ms=self.timeout,
            browser_pool=self.browser_pool,
        )
        self.visited, self.forms_found, self.js_files = await spider.run()
        self._save_checkpoint("spider_done")

    # ═══════════════════════════════════════════════════════
    # Phase 2: Detector Dispatch
    # ═══════════════════════════════════════════════════════

    async def run_all_detections(self) -> None:
        if self.passive_only:
            log.info("Passive-only mode — skipping active detection")
            return

        from src.detectors import get_detector_registry
        registry = get_detector_registry()

        for name, detector_cls in registry:
            if not self.policy.is_detector_enabled(name):
                log.debug("Skipping detector: %s", name)
                continue
            # Skip already-completed detectors (from resume)
            if name in self.completed_detectors:
                log.debug("Skipping already-completed detector: %s", name)
                continue
            detector = detector_cls(self)
            log.info("--- %s ---", detector_cls.__name__)
            try:
                await detector.run()
                self.completed_detectors.append(name)
                self._save_checkpoint("detecting")
            except Exception as exc:
                log.error("Detector '%s' failed: %s", name, str(exc)[:120])

    # ═══════════════════════════════════════════════════════
    # Report Generation
    # ═══════════════════════════════════════════════════════

    def generate_report(self) -> dict:
        merged = self.dedup.finalize()

        # Merge passive findings
        for pf in self.passive_proxy.get_passive_report():
            if not any(m.get("title") == pf.get("title") for m in merged):
                merged.append(pf)

        # Enrich with CVSS and priority
        from src.reporting.cvss import enrich_finding_with_cvss, sort_by_priority
        enriched = [enrich_finding_with_cvss(f) for f in merged]
        merged = sort_by_priority(enriched)

        sevs: dict[str, int] = {}
        for f in merged:
            sev = f.get("severity", "Info")
            sevs[sev] = sevs.get(sev, 0) + 1

        duration = "N/A"
        if self.scan_start_time:
            elapsed = (datetime.now(timezone.utc) - self.scan_start_time).total_seconds()
            duration = f"{elapsed:.0f}s"

        return {
            "engine": "Web-Security-Full v8.0",
            "target": self.target_url,
            "scan_time": self.scan_start_time.isoformat() if self.scan_start_time else "",
            "duration": duration,
            "policy": self.policy.name,
            "waf_detected": self.detected_waf,
            "auth_type": self.auth_type,
            "tech_stack": self.tech_stack,
            "summary": {
                "total": len(merged),
                "by_severity": sevs,
                "pages": len(self.visited),
                "forms": len(self.forms_found),
                "js": len(self.js_files),
                "passive": {
                    "requests": self.passive_proxy.request_count,
                    "responses": self.passive_proxy.response_count,
                },
            },
            "findings": merged,
        }

    async def save_report(self) -> str:
        report = self.generate_report()
        p = Path(self.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("JSON report saved: %s", self.output_file)

        # HTML report
        if self.html_report:
            html_path = str(p.with_suffix(".html"))
            try:
                HTMLReporter.generate(report, html_path)
                log.info("HTML report saved: %s", html_path)
            except Exception as exc:
                log.warning("HTML report generation failed: %s", exc)

        # Compliance report
        if self.compliance_fw:
            comp_path = str(p.with_suffix(f".compliance_{self.compliance_fw}.json"))
            try:
                ComplianceReporter.generate_file(
                    report, self.compliance_fw, comp_path)
                log.info("Compliance report saved: %s", comp_path)
            except Exception as exc:
                log.warning("Compliance report failed: %s", exc)

        # Persistence
        try:
            self.persistence.save_scan(report, policy=self.policy.name)
        except Exception:
            log.debug("Persistence save failed")

        s = report["summary"]
        log.info("SCAN COMPLETE — Duration: %s, Pages: %d, Findings: %d",
                 report["duration"], s["pages"], s["total"])
        for sev, cnt in s["by_severity"].items():
            log.info("  %s: %d", sev, cnt)
        return str(p)

    async def run(self) -> str:
        await self.start()
        await self.phase_spider()
        if not self.passive_only:
            await self.run_all_detections()
            await self.phase_exploit_verification()
        await self.phase_plugins()
        rp = await self.save_report()
        await self.stop()
        return rp

    # ═══════════════════════════════════════════════════════
    # Phase 2.5: Exploit verification (confirm detector findings)
    # ═══════════════════════════════════════════════════════

    async def phase_exploit_verification(self) -> None:
        """Run safe PoC verification against confirmed findings."""
        from src.detectors.exploit_verifier import ExploitVerifier
        try:
            verifier = ExploitVerifier(self)
            await verifier.run()
        except Exception as exc:
            log.debug("Exploit verification phase skipped: %s", str(exc)[:100])

    # ═══════════════════════════════════════════════════════
    # Checkpoint helpers
    # ═══════════════════════════════════════════════════════

    def _save_checkpoint(self, phase: str) -> None:
        """Save scan state for potential resume."""
        try:
            self.persistence.save_checkpoint(
                scan_id=self.scan_id,
                target=self.target_url,
                policy=self.policy.name,
                phase=phase,
                visited=self.visited,
                forms=self.forms_found,
                js_files=self.js_files,
                findings_count=len(self.findings),
                completed_detectors=self.completed_detectors,
                extra={"detected_waf": self.detected_waf,
                       "auth_type": self.auth_type},
            )
        except Exception:
            log.debug("Checkpoint save failed")

    # ═══════════════════════════════════════════════════════
    # Phase 3: Plugin auto-execution
    # ═══════════════════════════════════════════════════════

    async def phase_plugins(self) -> None:
        """Execute YAML plugin requests and match responses automatically."""
        if not self.plugin_loader:
            return
        active_rules = self.plugin_loader.get_active_rules()
        if not active_rules:
            return

        log.info("--- Phase 3: Plugin Auto-Execution (%d rules) ---", len(active_rules))
        requests = self.plugin_loader.get_requests(self.target_url)

        if not requests:
            return

        # Use the concurrent scanner to send plugin requests
        results = await self.concurrent.execute(self._context, requests)

        # Match responses against rules
        responses_as_dicts = []
        for label, resp, error in results:
            if error or not resp:
                continue
            try:
                body = await resp.text()
            except Exception:
                body = ""
            responses_as_dicts.append({
                "url": resp.url,
                "status_code": resp.status,
                "headers": dict(resp.headers) if resp.headers else {},
                "body": body,
                "label": label,
            })

        plugin_findings = self.plugin_loader.match_responses(responses_as_dicts)
        for pf in plugin_findings:
            self.add_finding(**pf)

        if plugin_findings:
            log.info("Plugin findings: %d new issues from %d requests",
                     len(plugin_findings), len(requests))
        self._save_checkpoint("plugins_done")


# ═══════════════════════════════════════════════════════════
# CLI Entry Point — use cli.py as the canonical entry point.
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    print("Use 'python cli.py --url <target>' instead of 'python scanner.py'.",
          file=sys.stderr)
    sys.exit(1)
