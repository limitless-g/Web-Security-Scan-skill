"""
Web Security Scanner v8.0 - One-click installation.
Handles Python version check, pip dependencies, Playwright browser, NVD database.
"""

import subprocess, sys, os
from pathlib import Path


def check_python():
    v = sys.version_info
    if v < (3, 9):
        print(f"[ERROR] Python 3.9+ required. You have {v.major}.{v.minor}.")
        sys.exit(1)
    print(f"[OK] Python {v.major}.{v.minor}.{v.micro}")


def install_pip_deps(dev=False):
    deps = ["playwright", "pyyaml"]
    if dev:
        deps.extend(["pytest", "mypy", "ruff"])
    print(f"\n[*] Installing: {', '.join(deps)}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade"] + deps)
    except subprocess.CalledProcessError:
        print("[WARN] Some pip installs failed. Continuing...")


def install_playwright_browser():
    print("\n[*] Installing Chromium (~150MB)...")
    try:
        subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])
        print("[OK] Chromium installed")
    except subprocess.CalledProcessError:
        print("[WARN] Playwright browser install failed.")
        print("  Run manually: playwright install chromium")


def offer_nvd_download():
    api_key = os.environ.get("NVD_API_KEY", "")
    if not api_key:
        print("\n[INFO] For CVE matching, get a free NVD API key:")
        print("  https://nvd.nist.gov/developers/request-an-api-key")
    choice = input("\n[?] Download NVD CVE database? (~50MB) [y/N]: ").strip().lower()
    if choice == "y":
        print("[*] Downloading NVD CVE data...")
        try:
            from scripts.nvd_downloader import NVDDatabase
            db = NVDDatabase(api_key=api_key)
            count = db.download_all()
            print(f"[OK] Downloaded {count:,} CVEs")
        except Exception as e:
            print(f"[WARN] NVD download failed: {e}")


def verify_installation():
    print("\n[*] Verifying installation...")
    base = Path(__file__).parent
    sys.path.insert(0, str(base))

    # PyYAML
    try:
        import yaml
        print("[OK] PyYAML")
    except ImportError:
        print("[WARN] PyYAML not found")

    # Playwright
    try:
        from playwright.sync_api import sync_playwright
        print("[OK] Playwright")
    except ImportError:
        print("[WARN] Playwright not found")

    # Detectors
    try:
        from src.detectors import get_detector_registry
        registry = get_detector_registry()
        print(f"[OK] {len(registry)} detector modules")
    except Exception as e:
        print(f"[WARN] Detector import: {e}")

    # Reporting
    try:
        from src.reporting.html_reporter import HTMLReporter
        from src.reporting.compliance_reporter import ComplianceReporter
        print("[OK] Reporting system")
    except Exception as e:
        print(f"[WARN] Reporting import: {e}")


def main():
    print("=" * 55)
    print("  Web Security Scanner v8.0 - Installation")
    print("=" * 55)

    check_python()

    # Create required directories
    for d in [Path.home() / ".websec", Path("plugins"), Path("src/detectors"),
              Path("src/reporting"), Path("scripts")]:
        d.mkdir(parents=True, exist_ok=True)

    dev_mode = "--dev" in sys.argv
    install_pip_deps(dev=dev_mode)
    install_playwright_browser()
    offer_nvd_download()
    verify_installation()

    print("\n" + "=" * 55)
    print("  Installation complete!")
    print("  Run: python cli.py --url https://example.com")
    print("=" * 55)


if __name__ == "__main__":
    main()
