# Web Security Scanner v8.0 — Production DAST Engine

<p align="center">
  <img src="https://img.shields.io/badge/version-8.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/python-3.9%2B-orange" alt="Python">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/detectors-30-red" alt="Detectors">
  <img src="https://img.shields.io/badge/tests-250-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/payloads-500%2B-purple" alt="Payloads">
</p>

<p align="center">
  <b>English</b> · <a href="#chinese">中文</a> · <a href="SKILL.md">Claude Code Skill</a>
</p>

---

Open-source DAST engine for web application security assessment. Production-ready: 30 modular detectors, adaptive WAF bypass, OOB blind detection (HTTP+DNS), API security analysis, exploit verification, and compliance reporting for PCI-DSS, HIPAA, SOC2, and ISO 27001.

## Quick Start

```bash
# Install (Python 3.9+)
python install.py

# Full security scan
python cli.py --url https://your-app.com

# Passive-only (zero attack traffic, production safe)
python cli.py --url https://your-app.com --passive-only

# PCI-DSS compliance scan
python cli.py --url https://your-app.com --policy pci-dss --compliance pci --fail-on critical

# Docker
docker compose build && docker compose run --rm scanner --url https://your-app.com
```

## What It Detects

| Category | Detectors | Highlights |
|----------|:---------:|------------|
| **Injections** | 6 | SQLi (error/time/boolean/UNION), NoSQL (7 operators), CMDi (12 separators), SSTI (11 engines), XXE (file/OOB/XInclude), SSRF (13 IP bypasses) |
| **Auth & Access** | 5 | CSRF (token entropy + Origin validation), OAuth (6 redirect_uri bypasses), SAML (XSW 1-8), IDOR (sequential + path-based), JWT (6 attack vectors) |
| **Infrastructure** | 7 | Security headers, CORS misconfig, TLS audit, WebSocket, HTTP smuggling, Cache poisoning, Clickjacking |
| **Data Exposure** | 8 | Secrets detection (28 patterns), sensitive files (100+ paths), debug endpoints (30+), directory listing, open redirect, JS storage, file upload |
| **API Security** | 1 | OpenAPI/Swagger/GraphQL discovery, mass assignment, BOLA, rate limiting, parameter fuzzing |
| **Enterprise** | 3 | Exploit verification (safe PoC), tech stack fingerprinting (31 JS + 8 server + 4 CMS), passive proxy (JWT/Cookie/CSP audit) |

**WAF Bypass**: 8-type fingerprinting (Cloudflare, AWS WAF, Imperva, ModSecurity, Akamai, Alibaba, Sucuri, F5 ASM) with adaptive bypass strategies and effectiveness tracking.

**OOB Blind Detection**: Built-in HTTP + DNS callback server for blind SSRF, XXE, SQLi, and command injection.

## Scan Policies

| Policy | Destructive | Rate | Pages | Use Case |
|--------|:---:|:---:|:---:|----------|
| `safe` | No | 2/s | 50 | Production passive monitoring — zero attack traffic |
| `owasp-top10` | No | 3/s | 100 | OWASP Top 10 compliance audit |
| `pci-dss` | Yes | 4/s | 200 | Cardholder data environment assessment |
| `full` | Yes | 6/s | 500 | Comprehensive penetration test |
| `quick` | No | 10/s | 20 | 5-minute triage |
| `api-only` | Yes | 5/s | 50 | API-focused (OpenAPI/GraphQL aware) |

## CLI Reference

```
python cli.py --url URL [OPTIONS]

Required:
  --url          Target URL to scan

Output:
  --output       Output file path (default: report.json)
  --no-html      Skip HTML report generation

Scan Control:
  --policy       Scan policy: safe|owasp-top10|pci-dss|full|quick|api-only
  --max-pages    Max pages to crawl (default: 150)
  --timeout      Request timeout in ms (default: 15000)
  --no-spa       Disable SPA/JS rendering
  --passive-only Passive analysis only (zero attack traffic)
  --no-browser   Curl-only mode (no Playwright required)

Enterprise:
  --proxy        HTTP/SOCKS proxy (e.g., http://corp-proxy:8080)
  --custom-header Custom header "Key:Value" (repeatable)
  --resume       Resume from last checkpoint
  --internal     Internal network target (adjusts baseline)

CI/CD:
  --fail-on      Exit on: critical(4)|high(3)|medium(2)
  --compliance   Generate: pci|hipaa|soc2|iso27001

Other:
  --oob-port     OOB callback server port (default: 8889)
  --log-level    DEBUG|INFO|WARNING|ERROR (default: INFO)
```

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
dast:
  stage: security
  script:
    - pip install playwright pyyaml aiohttp && playwright install chromium
    - python cli.py --url $TARGET_URL --policy full --fail-on high
  artifacts:
    paths: [report.json, report.html]
```

Exit codes: `0`=clean, `2`=medium+, `3`=high+, `4`=critical (blocks pipeline).

## Test Suite

```bash
# Unit tests (230 tests, < 1 second)
python -m pytest tests/ -k "not integration" -q

# Integration tests (20 tests, auto-starts test server)
python -m pytest tests/test_integration_full.py -v

# Full suite
python -m pytest tests/ -q
```

## Architecture

```
web-security-full/
├── cli.py                       CLI entry point
├── scanner.py                   Orchestrator (lifecycle, spider, detection dispatch)
├── install.py                   One-click setup
├── Dockerfile / docker-compose  Docker deployment
│
├── src/
│   ├── detectors/               30 vulnerability detection modules
│   │   ├── injection/           sqli, nosql, command_injection, ssti, xxe, ssrf
│   │   ├── xss/                 DOM/Reflected/Stored/AJAX XSS
│   │   ├── auth/                csrf, oauth, saml, idor, jwt
│   │   ├── infrastructure/      headers, cors, tls_crypto, websocket, smuggling, cache, clickjacking
│   │   ├── exposure/            info_disclosure, sensitive_files, debug_endpoints, directory_listing, open_redirect, js_storage, file_upload
│   │   └── api/                 api_security (OpenAPI/GraphQL/mass assignment/BOLA)
│   ├── engine/                  HTTP client, passive proxy, spider, WAF bypass executor, session manager
│   ├── payloads/                500+ payloads (SQLi, XSS, SSTI, SSRF, traversal, injection)
│   ├── waf/                     8-type fingerprinting + adaptive bypass engine
│   ├── oob/                     HTTP + DNS dual-channel callback server
│   ├── compliance/              PCI-DSS v4.0, HIPAA, SOC2, ISO 27001
│   ├── reporting/               HTML reports (dark mode, heatmap, CSV export) + CVSS calculator
│   └── plugins/                 YAML hot-reload plugin loader
│
├── plugins/                     10 built-in YAML detection rules
├── scripts/                     NVD CVE downloader (200K+) + matcher
├── tests/                       250 tests (230 unit + 20 integration)
└── docs/                        SAML attacks, WAF bypass, OOB setup, auth macros
```

## Requirements

- **Python 3.9+**
- **Playwright + Chromium** (~150MB) — optional, `--no-browser` uses aiohttp/urllib fallback
- **aiohttp** >= 3.9 — auto-installed by `install.py`
- **NVD API key** — optional, free from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)

## Running Against Production Systems

When scanning internal production systems:

1. **Start with `--policy safe`** — passive-only, zero attack traffic. Identifies exposed secrets, missing headers, info leakage with no risk.
2. **Then `--policy owasp-top10`** — non-destructive active checks. Injection probes with read-only payloads.
3. **Finally `--policy full`** — includes destructive checks. Run during maintenance windows only.
4. **Use `--internal` flag** for internal apps — adjusts severity ratings (e.g., HSTS requirement downgraded for internal-only apps).
5. **Always use `--resume`** for large scans — survives network interruptions.

### Internal Network Example

```bash
# Phase 1: Safe reconnaissance (can run any time)
python cli.py --url https://internal-app.corp.local --policy safe --internal --output phase1_safe.json

# Phase 2: Non-destructive active scan (business hours OK)
python cli.py --url https://internal-app.corp.local --policy owasp-top10 --internal --output phase2_owasp.json

# Phase 3: Full assessment (maintenance window)
python cli.py --url https://internal-app.corp.local --policy full --internal \
  --proxy http://corp-proxy:8080 \
  --custom-header "Authorization: Bearer $(vault read -field=token secret/scan-token)" \
  --compliance pci --fail-on high --output phase3_full.json
```

## Extending (Plugin System)

Drop YAML files in `plugins/` — hot-reloaded, no restart needed:

```yaml
name: "Detect Internal Admin Panel"
severity: High
category: "Exposed Admin"
description: "Admin panel without authentication"
priority: 90
detection:
  response:
    status: [200]
    body_contains: ["admin", "dashboard"]
payload:
  method: GET
  path: "/admin"
remediation: "Restrict to internal IP ranges with SSO authentication."
```

---

## <a name="chinese">中文文档</a>

生产级开源 Web 应用 DAST 扫描器。30 个检测模块、WAF 自适应绕过、OOB 盲检测（HTTP+DNS）、漏洞利用验证、API 安全分析、合规报告。

### 快速开始

```bash
python install.py
python cli.py --url https://目标站点.com --policy full
```

### 扫描策略

| 策略 | 破坏性 | 速率 | 页数 | 场景 |
|------|:---:|:---:|:---:|------|
| `safe` | 否 | 2/s | 50 | 生产环境被动监控 |
| `owasp-top10` | 否 | 3/s | 100 | OWASP 合规审计 |
| `pci-dss` | 是 | 4/s | 200 | 支付卡环境评估 |
| `full` | 是 | 6/s | 500 | 全面渗透测试 |
| `quick` | 否 | 10/s | 20 | 5 分钟快速排查 |

### 对内部生产系统扫描的建议

1. **先用 `--policy safe`** — 纯被动，零攻击流量，识别密钥泄露、缺少安全头、信息泄露
2. **再用 `--policy owasp-top10`** — 非破坏性主动检测，只读载荷
3. **最后 `--policy full`** — 包含破坏性检测，仅在维护窗口运行
4. **内部应用加 `--internal`** — 自动调整严重级别
5. **大站加 `--resume`** — 断点续扫，不怕网络中断

### CI/CD 集成

```bash
python cli.py --url $TARGET_URL --policy pci-dss --fail-on critical --compliance pci
```

退出码: `0`=无漏洞, `2`=中危, `3`=高危, `4`=严重

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. You must have written authorization from the target system owner before use. Unauthorized scanning is illegal.

---

MIT License — 2024-2026
