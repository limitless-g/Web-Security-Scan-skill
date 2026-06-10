#!/bin/bash
# Web Security Full v5.5 — One-command installer for Claude Code
# Usage: bash install.sh

set -e

SKILL_DIR="${HOME}/.claude/skills/web-security-full"

echo "=== Web Security Full v5.5 Installer ==="
echo ""

# Check if already installed
if [ -d "$SKILL_DIR" ]; then
    echo "[!] Already installed at $SKILL_DIR"
    echo "    To reinstall: rm -rf $SKILL_DIR && bash install.sh"
    exit 1
fi

# Copy skill files
echo "[1/3] Installing skill files to $SKILL_DIR..."
mkdir -p "$SKILL_DIR"
cp -r ./* "$SKILL_DIR/"
echo "       Done."

# Install Python dependencies
echo "[2/3] Installing Python dependencies..."
pip install playwright pyyaml --quiet
echo "       Done."

# Install Playwright browser
echo "[3/3] Installing Chromium browser (this may take a minute)..."
playwright install chromium --quiet 2>/dev/null || playwright install chromium
echo "       Done."

echo ""
echo "=== Installation Complete ==="
echo ""
echo "  Skill: /web-security-full"
echo "  Usage: /web-security-full https://target.com"
echo "  Manual: python ${SKILL_DIR}/scripts/web_auto_scanner.py --help"
echo ""
echo "  Optional: Download CVE database (200K+ CVEs, ~50MB)"
echo "    python ${SKILL_DIR}/scripts/nvd_downloader.py --init"
echo ""
