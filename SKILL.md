---
name: Web Security Full Scan
description: Enterprise-grade DAST engine — 30 detectors, OOB blind detection, WAF bypass, exploit verification, compliance (PCI-DSS/HIPAA/SOC2/ISO 27001), CVE matching, checkpoint/resume, HTML reports with heatmap. Just say "scan example.com".
version: 8.0.0
tags: [web-security, dast, scanner, owasp, pentest, compliance, enterprise, vulnerability-scanner]
---

# Web Security Scanner v8.0

Production-grade open-source DAST engine. 30 vulnerability detectors, 500+ payloads, WAF fingerprinting with adaptive bypass, OOB blind detection (HTTP+DNS), exploit verification, API security assessment, and compliance reporting for PCI-DSS, HIPAA, SOC2, and ISO 27001.

## Quick Start

Just say any of these in a Claude Code conversation:

- **"Scan https://example.com"** — Full comprehensive assessment
- **"Do a passive security check on https://example.com"** — Zero attack traffic
- **"Run PCI-DSS compliance scan on https://example.com"** — With framework mapping
- **"Quick security triage on https://example.com"** — 5-minute surface scan
- **"API security audit on https://api.example.com"** — API-only testing

Claude Code invokes this skill, runs the scanner, and presents findings with an interactive HTML report.

## Direct CLI Usage

```bash
# Full scan
python cli.py --url https://target.com

# Production-safe passive (zero attack traffic)
python cli.py --url https://target.com --passive-only

# Curl-only mode (no browser dependency)
python cli.py --url https://target.com --no-browser

# PCI-DSS with pipeline fail-on
python cli.py --url https://target.com --policy pci-dss --compliance pci --fail-on critical

# Quick 5-minute triage
python cli.py --url https://target.com --policy quick

# API-only testing (OpenAPI/GraphQL aware)
python cli.py --url https://target.com --policy api-only

# Enterprise proxy + auth headers
python cli.py --url https://target.com --proxy http://corp-proxy:8080 \
  --custom-header "Authorization: Bearer TOKEN"

# Resume interrupted scan
python cli.py --url https://target.com --resume
```

## Architecture

```
web-security-full/
├── cli.py                           CLI entry point (canonical)
├── scanner.py                       Orchestrator — lifecycle, spider, detector dispatch
├── install.py                       One-click setup
├── Dockerfile                       Multi-stage Docker build (Playwright + Chromium)
├── docker-compose.yml               Scanner + OOB server + test server
├── requirements.txt                 Minimal deps (playwright, pyyaml, aiohttp)
├── pyproject.toml                   Package metadata
├── README.md                        GitHub README (EN/CN)
├── SKILL.md                         This file — Claude Code skill definition
├── LICENSE                          MIT
│
├── src/
│   ├── schemas/                     Canonical data models
│   │   ├── finding.py               Vulnerability finding schema
│   │   ├── http.py                  Request/response models
│   │   └── scan.py                  Scan config + result models
│   │
│   ├── core/                        Constants + exceptions
│   │   ├── constants.py             250+ lines: crawl/HTTP/timing/patterns/SQLi/XSS/SAML/WAF
│   │   └── exceptions.py           Typed error hierarchy
│   │
│   ├── detectors/                   30 vulnerability detection modules
│   │   ├── base.py                  Abstract BaseDetector with property accessors
│   │   ├── __init__.py              Lazy-loading registry
│   │   ├── injection/
│   │   │   ├── sqli.py              SQLi: error/time/boolean/UNION with adaptive baseline + retest
│   │   │   ├── nosql.py             NoSQL: 7 operators, auth bypass, blind, error signatures
│   │   │   ├── command_injection.py CMDi: 12 separators, baseline, error, OOB callback
│   │   │   ├── ssti.py              SSTI: polyglot probe, 11 engines, 3-phase verification
│   │   │   ├── xxe.py               XXE: file read, OOB, XInclude, billion laughs, error-based
│   │   │   └── ssrf.py              SSRF: 7 cloud metadata, 13 IP bypasses, OOB, header-based
│   │   ├── xss/
│   │   │   └── xss.py               XSS: DOM/Reflected/Stored/AJAX with execution verification
│   │   ├── auth/
│   │   │   ├── csrf.py              CSRF: token entropy, SameSite audit, Origin validation, CORS preflight
│   │   │   ├── oauth.py             OAuth: 6 redirect_uri bypasses, state/PKCE/response_type checks
│   │   │   ├── saml.py              SAML: XSW 1-8, signature exclusion, replay, metadata exposure
│   │   │   ├── idor.py              IDOR: sequential enumeration, path-based, cross-endpoint leak
│   │   │   └── jwt.py               JWT: 6 vectors (alg:none, key confusion, JWK, kid traversal, weak secret, expiry)
│   │   ├── infrastructure/
│   │   │   ├── headers.py           Security headers + cookie flags audit
│   │   │   ├── cors.py              CORS: origin reflection, null origin, wildcard+creds
│   │   │   ├── tls_crypto.py        TLS: certificate expiry, protocol version audit
│   │   │   ├── websocket.py         WebSocket: ws:// detection, origin validation
│   │   │   ├── request_smuggling.py HTTP smuggling: CL.TE, TE.CL, TE.TE
│   │   │   ├── cache_poisoning.py   Cache poisoning: unkeyed headers/params
│   │   │   └── clickjacking.py      Clickjacking: XFO + CSP frame-ancestors
│   │   ├── exposure/
│   │   │   ├── info_disclosure.py   Info disclosure: 12 patterns + error probes
│   │   │   ├── sensitive_files.py   Sensitive files: 100+ paths, content verification, concurrent
│   │   │   ├── debug_endpoints.py   Debug endpoints: 30+ paths with severity classification
│   │   │   ├── directory_listing.py Directory listing: 22 directories, signature matching
│   │   │   ├── open_redirect.py     Open redirect: parameter + header-based
│   │   │   ├── js_storage.py        JS storage: localStorage/sessionStorage audit
│   │   │   └── file_upload.py       File upload: SVG XSS, polyglot detection
│   │   ├── api/
│   │   │   └── api_security.py      API security: OpenAPI/GraphQL, mass assignment, BOLA, rate limiting
│   │   ├── exploit_verifier.py      Safe PoC: SQLi version/SSTI math/CMD id/XXE file read/SSRF OOB
│   │   ├── tech_stack.py            Tech fingerprinting: 31 JS libs + 8 servers + 4 CMS platforms
│   │   ├── postmessage.py           PostMessage: origin validation check via JS eval
│   │   ├── prototype_pollution.py   Prototype pollution: server-side + URL-based
│   │   └── plugin_probes.py         YAML plugin auto-execution
│   │
│   ├── engine/
│   │   ├── crawler/
│   │   │   ├── spider.py            BFS spider: SPA hydration, XHR intercept, sitemap/robots/JS API discovery
│   │   │   ├── api_discovery.py     OpenAPI/Swagger/GraphQL schema auto-discovery
│   │   │   └── dedup.py             URL deduplication
│   │   ├── http_client.py           Unified HTTP: Playwright → aiohttp → urllib fallback
│   │   ├── passive_proxy.py         Passive analysis: 28 secret patterns, JWT/Cookie/CSP audit, open redirect
│   │   ├── concurrent.py            Adaptive rate limiting + circuit breaker + backpressure
│   │   ├── session_manager.py       Multi-step auth macro recording/replay
│   │   ├── browser_pool.py          Parallel Playwright context pool
│   │   ├── waf_adaptive.py          WAF bypass strategy tracking + feedback learning
│   │   ├── waf_bypass_executor.py   Real HTTP-level bypass: HPP, chunked, multipart, verb tampering
│   │   ├── dedup.py                 Multi-dimensional root-cause finding deduplication
│   │   ├── persistence.py           SQLite scan history + checkpoint/resume
│   │   └── progress.py              Streaming progress tracker with ETA
│   │
│   ├── payloads/
│   │   ├── sqli.py                  SQLi payloads: error/time/boolean/UNION/stacked
│   │   ├── xss.py                   XSS payloads: HTML/JS/attribute/polyglot
│   │   ├── ssti.py                  SSTI: 35+ vectors across 11 engines with verification
│   │   ├── ssrf.py                  SSRF: 80+ vectors (encoding bypass, protocols, DNS rebinding)
│   │   ├── traversal.py             Path traversal: Unix/Windows variants
│   │   ├── injection.py             Generic injection payloads (NoSQL, CMD, XXE)
│   │   └── yaml_loader.py           YAML data-driven payload loader
│   │
│   ├── waf/
│   │   ├── detector.py              WAF fingerprinting: 8 types, header/body/cookie scoring
│   │   ├── bypass.py                Payload-level encoding cascades + signal strategies
│   │   └── profiles/                YAML profiles: cloudflare, aws_waf, imperva, modsecurity, akamai, etc.
│   │
│   ├── oob/
│   │   ├── callback.py              HTTP + DNS dual-channel callback server
│   │   └── external.py              Public callback via ngrok auto-tunnel
│   │
│   ├── compliance/
│   │   ├── base.py                  Abstract ComplianceMapper
│   │   ├── pci_dss.py               PCI-DSS v4.0: 25+ category mappings
│   │   ├── hipaa.py                 HIPAA Security Rule: 15+ mappings
│   │   ├── soc2.py                  SOC 2 Type II: 14+ mappings
│   │   └── iso27001.py              ISO 27001:2022: 17+ mappings
│   │
│   ├── reporting/
│   │   ├── html_reporter.py         Self-contained HTML report: SVG donut, heatmap, dark mode, CSV export
│   │   ├── compliance_reporter.py   Framework-specific compliance report generation
│   │   └── cvss.py                  CVSS v3.1 calculator: 46 category mappings + priority scoring
│   │
│   ├── plugins/
│   │   └── plugin_loader.py         YAML hot-reload plugin loader with response matching
│   │
│   ├── policy.py                    6 scan policy presets + detector toggle system
│   └── logging.py                   Structured JSON + color console logger
│
├── plugins/                         10 built-in YAML detection rules
│   ├── injection_probes.yaml        XMLRPC, GraphQL introspection
│   ├── auth_bypass.yaml             Auth bypass probes
│   ├── cloud_config.yaml            Cloud config exposure
│   ├── cloud_metadata.yaml          Cloud metadata endpoints
│   ├── api_enum.yaml                API endpoint enumeration
│   ├── info_leak.yaml               Information leakage
│   ├── spring_boot.yaml             Spring Boot actuator endpoints
│   └── jenkins_detect.yaml          Jenkins/Jenkinsfile exposure
│
├── scripts/
│   ├── nvd_downloader.py            NVD API 2.0 → SQLite (200K+ CVEs)
│   └── cve_matcher.py               Tech stack → CVE matching engine
│
├── tests/
│   ├── conftest.py                  Shared fixtures + auto-start test server
│   ├── test_server.py               Vulnerable target: 14+ intentional vulns on :8765
│   ├── test_integration_full.py     20 integration tests (auto-server, end-to-end)
│   ├── test_passive_proxy.py        Passive proxy unit tests
│   ├── test_passive_proxy_enhanced.py 28-pattern secret detection + JWT/Cookie/CSP audit tests
│   ├── test_api_security.py         OpenAPI/GraphQL/mass assignment tests
│   ├── test_waf_bypass_enhanced.py  WAF encoding cascade + strategy tracker tests
│   ├── test_ssti_detector.py        SSTI payload library + engine detection tests
│   ├── test_compliance_policy.py    PCI-DSS/HIPAA/CVSS/policy tests
│   ├── test_waf_detector.py         WAF fingerprinting tests
│   ├── test_waf_bypass.py           WAF bypass transformation tests
│   ├── test_payloads.py             Payload integrity tests
│   ├── test_dedup.py                Deduplication engine tests
│   ├── test_scanner_policy.py       Policy system tests
│   ├── test_logging.py              Logging framework tests
│   ├── test_persistence.py          Persistence/checkpoint tests
│   └── test_server.py               Vulnerable test target
│
└── docs/
    ├── saml-attacks.md              SAML attack methodology
    ├── waf-bypass.md                WAF bypass technique reference
    ├── oob-setup.md                 OOB callback configuration guide
    ├── auth-macros.md               Authentication macro guide
    └── curl-commands.md             Curl-mode usage examples
```

## Detection Coverage

### Injections (6 detectors)
| Detector | Methods | Verification |
|----------|---------|-------------|
| **SQLi** | Error, Time (adaptive baseline), Boolean (statistical retest), UNION (structure analysis) | DBMS version extraction |
| **NoSQL** | 7 operators ($ne/$gt/$regex/$where/$exists/$nin/$or), auth bypass, blind | Baseline-calibrated time delay |
| **CMD Injection** | 12 separators (Unix+Windows), encoding bypasses, error signature matching | Safe `id`/`whoami` command |
| **SSTI** | Polyglot probe, 11 engines, 3-phase: polyglot→math→blind | Alternate operand (7*7→7*8) |
| **XXE** | File read, OOB, XInclude, billion laughs, error-based, SVG upload | Safe file read (/etc/hostname) |
| **SSRF** | 7 cloud metadata endpoints, 13 IP encoding bypasses, DNS rebinding, header-based | OOB callback re-confirmation |

### Auth & Access (6 detectors)
| Detector | Coverage |
|----------|----------|
| **CSRF** | Token presence + entropy, SameSite audit, CORS preflight, Origin/Referer validation, double-submit cookie |
| **OAuth 2.0** | 6 redirect_uri bypasses, state CSRF, PKCE absence, response_type switching, OIDC discovery |
| **SAML 2.0** | XSW 1-8 (envelope/assertion wrapping, stripping, multi-assertion), signature exclusion, replay, metadata |
| **IDOR** | Sequential enumeration + response diffing, path-based, cross-endpoint ID leak, UUID discovery |
| **JWT** | alg:none, HMAC key confusion, JWK injection, kid path traversal, weak secret brute-force, missing expiry |

### Infrastructure (7 detectors)
| Detector | Coverage |
|----------|----------|
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORP/COOP/COEP |
| **CORS** | Origin reflection, null origin, wildcard + credentials, preflight analysis |
| **TLS/Crypto** | Certificate expiry, TLSv1.0/1.1 detection, cipher suite |
| **WebSocket** | ws:// detection, origin validation, message frame audit |
| **HTTP Smuggling** | CL.TE, TE.CL, TE.TE with timing anomaly detection |
| **Cache Poisoning** | Unkeyed headers (X-Forwarded-Host/Proto/Port), unkeyed query params |
| **Clickjacking** | X-Frame-Options + CSP frame-ancestors validation |

### Exposure (9 detectors)
| Detector | Coverage |
|----------|----------|
| **Info Disclosure** | 12 patterns (AWS/GitHub/Slack/Stripe keys, JWT, DB strings, private keys) + error probes |
| **Sensitive Files** | 100+ paths across 10 categories (Git, Cloud, Config, Backup, SSH, Java, NPM, Debug) |
| **Debug Endpoints** | 30+ endpoints with severity classification (Actuator, Swagger, Tomcat, DB consoles, profilers) |
| **Directory Listing** | 22+ common directories with signature-based detection |
| **Open Redirect** | Parameter + header-based injection |
| **JS Storage** | localStorage/sessionStorage/document.cookie sensitive data audit |
| **File Upload** | SVG XSS + GIF/JS polyglot detection |
| **API Security** | OpenAPI/Swagger/GraphQL discovery, mass assignment, BOLA/IDOR, rate limiting, fuzzing |
| **Tech Stack** | 31 JS libraries + 8 web servers + 4 CMS platforms from headers, cookies, scripts, meta tags |

### Enterprise Features
- **Exploit Verification**: Safe PoC for SQLi (DBMS version), SSTI (math), CMDi (id/whoami), XXE (hostname read), SSRF (OOB re-confirmation)
- **OOB Blind Detection**: HTTP callback server + DNS UDP listener for blind SSRF, XXE, SQLi, CMDi
- **WAF Bypass**: 8-type fingerprinting, payload-level encoding cascades, HTTP-level bypass (HPP, chunked, multipart, verb tampering, header overflow)
- **Compliance Reports**: PCI-DSS v4.0, HIPAA Security Rule, SOC 2 Type II, ISO 27001:2022 — with control ID mapping + remediation guidance
- **Checkpoint/Resume**: SQLite-backed scan state — resume interrupted scans
- **Enterprise Proxy**: HTTP/SOCKS proxy support with custom headers/cookies
- **CVE Matching**: 200K+ NVD database downloader + tech stack → CVE matcher
- **Plugin System**: YAML hot-reload — drop a `.yaml` file to add custom detection rules
- **CI/CD Integration**: Pipeline exit codes (0/2/3/4) + `--fail-on` flag + GitHub Actions example

## Scan Policies

| Policy | Destructive | Rate | Pages | Depth | Use Case |
|--------|:---:|:---:|:---:|:---:|----------|
| `safe` | No | 2/s | 50 | 1 | Production passive monitoring |
| `owasp-top10` | No | 3/s | 100 | 2 | OWASP compliance audit |
| `pci-dss` | Yes | 4/s | 200 | 3 | Cardholder data environment |
| `full` | Yes | 6/s | 500 | 4 | Comprehensive pentest |
| `quick` | No | 10/s | 20 | 1 | 5-minute triage |
| `api-only` | Yes | 5/s | 50 | 1 | API-focused testing (OpenAPI/GraphQL) |

## CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--url` | *(required)* | Target URL |
| `--output` | `report.json` | Output file path |
| `--policy` | `full` | `safe` / `owasp-top10` / `pci-dss` / `full` / `quick` / `api-only` |
| `--max-pages` | `150` | Max pages to crawl |
| `--timeout` | `15000` | Request timeout in milliseconds |
| `--no-spa` | off | Disable SPA/JS rendering |
| `--passive-only` | off | Passive analysis only — zero attack traffic |
| `--no-browser` | off | Curl-only mode — no Playwright required |
| `--oob-port` | `8889` | OOB callback server port |
| `--log-level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `--fail-on` | `none` | Pipeline exit trigger: `critical`(4) / `high`(3) / `medium`(2) |
| `--compliance` | *(none)* | Generate compliance report: `pci` / `hipaa` / `soc2` / `iso27001` |
| `--no-html` | off | Skip HTML report generation |
| `--proxy` | *(none)* | HTTP/SOCKS proxy (`http://corp-proxy:8080`) |
| `--resume` | off | Resume from last checkpoint |
| `--internal` | off | Internal network target (adjusts security baseline) |
| `--custom-header` | *(none)* | Custom request header `Key:Value` (repeatable) |

## CI/CD Integration

```yaml
# GitHub Actions
- name: DAST Security Scan
  run: |
    pip install playwright pyyaml aiohttp
    playwright install chromium
    python cli.py --url ${{ secrets.TARGET }} \
      --policy pci-dss --fail-on critical --compliance pci
- uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: report.*

# GitLab CI
dast_scan:
  stage: security
  script:
    - pip install playwright pyyaml aiohttp
    - playwright install chromium
    - python cli.py --url $TARGET_URL --policy full --fail-on high
  artifacts:
    paths: [report.json, report.html]
  allow_failure: true

# Jenkins
stage('DAST Scan') {
  steps {
    sh 'python cli.py --url ${TARGET_URL} --policy pci-dss --fail-on critical --compliance pci'
    archiveArtifacts artifacts: 'report.*'
  }
}
```

## Installation

```bash
# One-click (Python 3.9+)
python install.py

# With dev tools (pytest, mypy, ruff)
python install.py --dev

# Docker
docker compose build
docker compose run --rm scanner --url https://target.com

# Docker (full stack: scanner + OOB + test server)
docker compose up -d
```

## Requirements

- **Python 3.9+**
- **Playwright + Chromium** (~150MB) — optional with `--no-browser`
- **aiohttp** >= 3.9 — for curl mode (auto-falls back to urllib)
- **NVD API key**: optional, free from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)
- **ngrok**: optional, for external blind SSRF/XXE callback detection

## Plugin System

Drop a YAML file in `plugins/` to add custom detection rules. Hot-reloaded — no restart needed.

```yaml
name: "Detect Exposed Admin Panel"
severity: High
category: "Exposed Service"
description: "Admin panel accessible without authentication"
priority: 90
detection:
  response:
    status: [200]
    body_contains: ["admin", "dashboard"]
payload:
  method: GET
  path: "/admin"
remediation: "Restrict admin access to internal IPs with authentication."
```

See `docs/` for full plugin development guide.

## Test Suite

```bash
# All unit tests (230 tests)
python -m pytest tests/ -k "not integration" -q

# Integration tests (auto-starts test server)
python -m pytest tests/test_integration_full.py -v

# Full suite
python -m pytest tests/ -q
```

## License

MIT License — see `LICENSE` file.

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing ONLY.** You must have written authorization from the target system owner before use. Unauthorized scanning of systems you do not own is illegal in most jurisdictions. The authors assume no liability for misuse.
