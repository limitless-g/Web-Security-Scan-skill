# Web Security Full Assessment v5.5 — Tier-1 DAST Engine

<p align="center">
  <b>Language:</b> <a href="#english">English</a> | <a href="#chinese">中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-5.5.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/python-3.9%2B-orange" alt="Python">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/categories-50%2B-red" alt="Vulnerability Coverage">
</p>

---

## English

A Tier-1 open-source Web Application DAST (Dynamic Application Security Testing) scanner. 50+ vulnerability categories, passive traffic analysis, CVE knowledge base (200K+ via NVD), compliance reporting for PCI-DSS/HIPAA/SOC2/ISO 27001, professional HTML reports with dashboards, YAML-based plugin system, and SAML 2.0 9-vector deep attack coverage.

### Quick Start

**With Claude Code (one command):**
```bash
git clone https://github.com/xxx/web-security-full.git ~/.claude/skills/web-security-full
pip install playwright pyyaml && playwright install chromium
# Done. Now type /web-security-full in Claude Code.
```

**Without Claude Code (standalone):**
```bash
# 1. Install
pip install playwright pyyaml
playwright install chromium

# 2. Scan
python scripts/web_auto_scanner.py --url https://target.com --output report.json

# 3. Report
python scripts/html_reporter.py --report report.json --output report.html
```

### Features

| Category | Coverage |
|----------|----------|
| **Injections** | SQL, NoSQL, Command, SSTI, XXE, XSS (Reflected/Stored/DOM/AJAX) |
| **Auth** | JWT, OAuth 2.0, SAML 2.0 (9 vectors), CSRF, Default Credentials |
| **Access Control** | IDOR (5 patterns), Vertical PrivEsc, Array Injection |
| **Transport** | TLS 1.0-1.3, Cipher Suites, HSTS, Certificates, OCSP |
| **Config** | 9 Security Headers, CORS (5-step), Error Leakage, Version Disclosure |
| **Cloud** | Alibaba Cloud, AWS, Azure, GCP metadata SSRF |
| **Frontend** | DOM XSS, PostMessage, Prototype Pollution, CSS Injection |
| **Protocol** | Request Smuggling (3 variants), Cache Poisoning, HTTP/2 (6 vectors), WebSocket |
| **Business Logic** | Race Condition, Price Manipulation, 2FA Bypass, Workflow Skip |
| **Info Leak** | .git/.env/Dockerfile/Source/Logs/API Keys |
| **File Ops** | Upload RCE, Path Traversal, XML Injection |

### Scripts

```
scripts/
├── web_auto_scanner.py     Main engine (19 detection methods + 6 engine components)
├── cve_matcher.py          CVE knowledge base (42 built-in + NVD API)
├── nvd_downloader.py       NVD 200K+ CVE downloader (SQLite cache)
├── compliance_reporter.py  PCI-DSS / HIPAA / SOC2 / ISO 27001 reports
├── html_reporter.py        Professional HTML reports (dashboard + heatmap)
├── openapi_parser.py       Swagger/GraphQL schema parser + test case generator
└── plugin_loader.py        YAML plugin engine (hot-reload, 12 condition types)

plugins/
├── sensitive_files.yaml    .git/.env/Dockerfile leak detection
├── auth_bypass.yaml        JWT alg:none + default credentials
├── info_leak.yaml          phpinfo/Actuator exposure
├── injection_probes.yaml   XMLRPC SSRF + GraphQL introspection
└── cloud_config.yaml       Alibaba Cloud/AWS metadata probes
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: DAST Scan
  run: |
    pip install playwright pyyaml && playwright install chromium
    python scripts/web_auto_scanner.py --url ${{ secrets.TARGET }} --quick --output report.json --fail-on critical
    python scripts/html_reporter.py --report report.json --output report.html
- uses: actions/upload-artifact@v4
  with: { name: security-report, path: report.html }
```

Exit codes: `0`=Clean, `2`=Medium, `3`=High, `4`=Critical (blocks pipeline).

### Comparison with Commercial Scanners

| Capability | v5.5 | Burp Pro | Invicti |
|------------|:---:|:---:|:---:|
| Vuln Coverage (50+) | ✓ | ✓ | ✓ |
| Passive Scanning | ✓ | ✓ | ✗ |
| CVE Database (200K+) | ✓ | ✗ | ✓ |
| Plugin System | YAML | BApp (Java) | ✗ |
| Compliance (4 standards) | ✓ | Plugin | ✓ |
| HTML Dashboard | ✓ | ✓ | ✓ |
| CI/CD | ✓ | ✓ | ✓ |
| SAML Depth (9 vectors) | ✓ | Plugin | ✓ |
| OAuth Full-chain | ✓ | Plugin | ✓ |
| AI Context Awareness | ✓ | ✗ | ✗ |
| Zero Deployment | ✓ | ✗ | ✗ |
| **Cost** | **$0** | $4K-10K/yr | $6K-50K/yr |

### Requirements

- Python 3.9+
- Playwright (Chromium ~150MB download on first install)
- Disk: ~100MB (with NVD CVE database)
- Network: target site access required
- NVD API key: optional (free from https://nvd.nist.gov/developers/request-an-api-key)

### ⚠️ Legal Disclaimer

**This tool is for authorized security testing ONLY.** You must have written authorization from the target system owner before use. Unauthorized scanning is illegal in most jurisdictions. The authors assume no liability for misuse.

---

## 中文

第一梯队开源 Web 应用 DAST 安全扫描器。50+ 漏洞类别，被动流量分析，CVE 知识库 (200K+)，PCI-DSS/HIPAA/SOC2/ISO 27001 合规报告，HTML 专业报告（仪表盘+热力图），YAML 插件热加载系统，SAML 2.0 九向量深度攻击。

### 快速开始

```bash
# 1. 安装
pip install playwright pyyaml
playwright install chromium

# 2. 扫描
python scripts/web_auto_scanner.py --url https://target.com --output report.json

# 3. 报告
python scripts/html_reporter.py --report report.json --output report.html

# 4. CVE 匹配 (可选: 首次需下载 NVD 数据库 ~50MB)
python scripts/nvd_downloader.py --init
python scripts/cve_matcher.py --match '{"nginx":"1.31.1","react":"18.2.0"}'

# 5. 合规报告 (可选)
python scripts/compliance_reporter.py --report report.json --framework pci
```

### 扫描器架构

```
web_auto_scanner.py        ← 主引擎 (19 检测方法 + 6 引擎组件)
    ├── PassiveProxy           被动流量分析 (拦截所有请求/响应)
    ├── SessionManager         自动发现登录 → 认证 → Token维护 → 双账号IDOR
    ├── ConcurrentScanner      并发引擎 (4-6x, 连接池复用, 智能节流)
    ├── DedupEngine            同根因去重 + 多源置信度计算
    ├── BrowserPool            多浏览器Context并行池
    └── ScanPersistence        SQLite持久化 + 历史对比 + 修复验证

cve_matcher.py              ← 42 内置 CVE + NVD API
nvd_downloader.py           ← NVD 200K+ CVE 下载 (SQLite缓存)
compliance_reporter.py      ← PCI-DSS/HIPAA/SOC2/ISO27001 自动映射
openapi_parser.py           ← Swagger/GraphQL Schema 解析 + 测试用例生成
html_reporter.py            ← HTML 专业报告 (仪表盘/热力图/合规摘要)
plugin_loader.py            ← YAML 插件引擎 (12 条件类型, 热加载)
```

### CI/CD 集成

```bash
# GitHub Actions / GitLab CI / Jenkins
python scripts/web_auto_scanner.py --url $TARGET_URL --quick --fail-on critical

# 增量扫描 (基于 baseline)
python scripts/web_auto_scanner.py --url $TARGET_URL --incremental --baseline baseline.json

# 仅被动模式 (生产环境安全)
python scripts/web_auto_scanner.py --url $TARGET_URL --passive-only
```

退出码: `0`=无漏洞, `2`=中危, `3`=高危, `4`=严重 (阻断CI)

### ⚠️ 法律声明

**本工具仅限授权安全测试使用。** 使用前必须获得目标系统所有者的书面授权。未经授权的扫描在大多数国家和地区属于违法行为。作者不对任何滥用行为承担责任。
