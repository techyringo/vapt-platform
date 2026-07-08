"""
VAPT Multi-Agent System — Prerequisite Checker & Auto-Installer

Automatically detects, installs, and validates ALL dependencies:
  - Docker Engine (optional but recommended)
  - Docker images (auto-pull from config.yaml)
  - Go-based security tools (subfinder, httpx, nuclei, etc.)
  - Python-based tools (sqlmap, arjun, etc.)
  - Wordlists (SecLists, common wordlists)
  - NVD CVE database (local cache for offline matching)
  - API keys validation (Shodan, Censys, SecurityTrails, OpenAI)

Usage:
    python -m tools.prerequisites              # Check + install everything
    python -m tools.prerequisites --check-only  # Only check, don't install
    python -m tools.prerequisites --tools       # Only check/install tools
    python -m tools.prerequisites --docker      # Only check/pull Docker images
    python -m tools.prerequisites --wordlists   # Only download wordlists
    python -m tools.prerequisites --api-keys    # Only validate API keys
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml


# ═══════════════════════════════════════════════════════════════════
# Color output
# ═══════════════════════════════════════════════════════════════════

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"

    @staticmethod
    def ok(msg: str) -> str:
        return f"  {Colors.GREEN}[OK]{Colors.END} {msg}"

    @staticmethod
    def fail(msg: str) -> str:
        return f"  {Colors.RED}[FAIL]{Colors.END} {msg}"

    @staticmethod
    def warn(msg: str) -> str:
        return f"  {Colors.YELLOW}[WARN]{Colors.END} {msg}"

    @staticmethod
    def info(msg: str) -> str:
        return f"  {Colors.CYAN}[INFO]{Colors.END} {msg}"


C = Colors


# ═══════════════════════════════════════════════════════════════════
# Tool Definitions — 40+ tools across categories
# ═══════════════════════════════════════════════════════════════════

GO_TOOLS = {
    # Reconnaissance
    "subfinder":      {"repo": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",      "install": "go install"},
    "httpx":          {"repo": "github.com/projectdiscovery/httpx/cmd/httpx",                  "install": "go install"},
    "nuclei":         {"repo": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",             "install": "go install"},
    "katana":         {"repo": "github.com/projectdiscovery/katana/cmd/katana",                 "install": "go install"},
    "uncover":        {"repo": "github.com/projectdiscovery/uncover/cmd/uncover",              "install": "go install"},
    "dnsx":           {"repo": "github.com/projectdiscovery/dnsx/cmd/dnsx",                    "install": "go install"},
    "naabu":          {"repo": "github.com/projectdiscovery/naabu/v2/cmd/naabu",               "install": "go install"},
    "gf":             {"repo": "github.com/tomnomnom/gf",                                      "install": "go install"},
    "anew":           {"repo": "github.com/tomnomnom/anew",                                    "install": "go install"},
    "notify":         {"repo": "github.com/projectdiscovery/notify/cmd/notify",                "install": "go install"},
    "tlsx":           {"repo": "github.com/projectdiscovery/tlsx/cmd/tlsx",                    "install": "go install"},
    "crobat":         {"repo": "github.com/cgboal/sonarsearch/cmd/crobat",                    "install": "go install"},

    # Fuzzing / Brute force
    "ffuf":           {"repo": "github.com/ffuf/ffuf/v2",                                      "install": "go install"},
    "wfuzz":          {"note": "Python tool, installed via pip"},

    # Web crawling / scraping
    "hakrawler":      {"repo": "github.com/hakluke/hakrawler",                                 "install": "go install"},
    "gospider":       {"repo": "github.com/jaeles-project/gospider",                           "install": "go install"},
    "waybackurls":    {"repo": "github.com/tomnomnom/waybackurls",                             "install": "go install"},
    "gau":            {"repo": "github.com/lc/gau/v2/cmd/gau",                                 "install": "go install"},
    "meg":            {"repo": "github.com/tomnomnom/meg",                                      "install": "go install"},
    "hakluke/haklistgen": {"repo": "github.com/hakluke/haklistgen",                           "install": "go install"},

    # OSINT / Intel
    "amass":          {"repo": "github.com/owasp-amass/amass/v4/...",                          "install": "apt / github release"},
    "theHarvester":   {"note": "Python tool, installed via pip"},

    # Utility
    "interlace":      {"repo": "github.com/AnonJoker/interlace",                               "install": "go install"},
    "qsreplace":      {"repo": "github.com/tomnomnom/qsreplace",                               "install": "go install"},
    "unfurl":         {"repo": "github.com/tomnomnom/unfurl",                                  "install": "go install"},
    "filenamelength": {"repo": "github.com/tomnomnom/filenamelength",                          "install": "go install"},
    "urldedupe":      {"repo": "github.com/projectdiscovery/utils/url/urldedupe/cmd/urldedupe","install": "go install"},
}

PYTHON_TOOLS = {
    "sqlmap":         {"pip": "sqlmap"},
    "arjun":          {"pip": "arjun"},
    "dalfox":         {"note": "Go tool or standalone binary", "go_repo": "github.com/hahwul/dalfox/v2"},
    "commix":         {"pip": "commix"},
    "nikto":          {"note": "System package: apt install nikto"},
    "wpscan":         {"note": "System package: apt install wpscan or gem install wpscan"},
    "paramspider":    {"pip": "paramspider"},
    "secretfinder":   {"note": "Bundled as regex in agents/intel.py (no external tool needed)"},
    "theHarvester":   {"pip": "theHarvester"},
    "wappalyzer":     {"pip": "python-Wappalyzer"},
    "censys":         {"pip": "censys"},
    "shodan":         {"pip": "shodan"},
    "nmap":           {"note": "System package: apt install nmap"},
    "masscan":        {"note": "System package: apt install masscan or compile from source"},
    "hydra":          {"note": "System package: apt install hydra"},
    "wpscan":         {"note": "System package: apt install wpscan"},
}

SYSTEM_PACKAGES = {
    "nmap":           {"apt": "nmap",           "brew": "nmap"},
    "nikto":          {"apt": "nikto",          "brew": "nikto"},
    "hydra":          {"apt": "hydra",          "brew": "hydra"},
    "masscan":        {"apt": "masscan",        "brew": "masscan"},
    "wpscan":         {"apt": "wpscan",         "note": "Also available via gem"},
    "curl":           {"apt": "curl",           "brew": "curl"},
    "wget":           {"apt": "wget",           "brew": "wget"},
    "jq":             {"apt": "jq",             "brew": "jq"},
    "gnupg":          {"apt": "gnupg",          "brew": "gnupg"},
}

DOCKER_IMAGES = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/nuclei:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/uncover:latest",
    "projectdiscovery/dnsx:latest",
    "ghcr.io/sullo/nikto:latest",
    "sqlmapproject/sqlmap:latest",
    "wpscanteam/wpscan:latest",
    "hahwul/dalfox:latest",
    "commixproject/commix:latest",
    "xmendez/wfuzz:latest",
    "instrumentisto/nmap:latest",
    "caffix/amass:latest",
    "ghcr.io/projectdiscovery/nuclei-templates:latest",
]

WORDLIST_URLS = {
    "directory-list-2.3-medium.txt": {
        "url": "https://raw.githubusercontent.com/daviddias/node-dirbuster-lists/master/dirbuster/directory-list-2.3-medium.txt",
        "path": "wordlists/directory-list-2.3-medium.txt",
        "size_mb": 5.8,
    },
    "common.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "path": "wordlists/common.txt",
        "size_mb": 0.4,
    },
    "parameters.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
        "path": "wordlists/parameters.txt",
        "size_mb": 0.02,
    },
    "xss payloads.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/xss-payload-list.txt",
        "path": "wordlists/xss-payloads.txt",
        "size_mb": 0.03,
    },
    "sqli payloads.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
        "path": "wordlists/sqli-payloads.txt",
        "size_mb": 0.01,
    },
    "resolvers.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/resolvers.txt",
        "path": "wordlists/resolvers.txt",
        "size_mb": 0.01,
    },
    "ssti payloads.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSTI/ssti-payloads.txt",
        "path": "wordlists/ssti-payloads.txt",
        "size_mb": 0.01,
    },
    "api-endpoints.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "path": "wordlists/api-endpoints.txt",
        "size_mb": 0.05,
    },
    "js-extensions.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/js-extensions.txt",
        "path": "wordlists/js-extensions.txt",
        "size_mb": 0.001,
    },
}

API_KEY_ENV_VARS = {
    "OPENAI_API_KEY":       {"service": "OpenAI / GPT-4o",           "required_for": "LLM intelligent analysis"},
    "SHODAN_API_KEY":       {"service": "Shodan",                    "required_for": "IoT/CCTV scanning, port intelligence"},
    "CENSYS_API_ID":        {"service": "Censys",                    "required_for": "Certificate transparency, host intel"},
    "CENSYS_API_SECRET":    {"service": "Censys (secret)",           "required_for": "Censys authentication"},
    "SECURITYTRAILS_API":   {"service": "SecurityTrails",            "required_for": "DNS history, subdomain intel"},
    "VT_API_KEY":           {"service": "VirusTotal",                "required_for": "Malware scan, domain reputation"},
    "GITHUB_TOKEN":         {"service": "GitHub",                    "required_for": "Private repo enum, token scanning"},
}


# ═══════════════════════════════════════════════════════════════════
# Prerequisite Checker
# ═══════════════════════════════════════════════════════════════════

class PrerequisiteChecker:
    """Checks and auto-installs all VAPT dependencies."""

    def __init__(self, config_path: str = "config.yaml", check_only: bool = False):
        self.config_path = Path(config_path)
        self.check_only = check_only
        self.project_root = Path(__file__).parent.parent
        self.wordlist_dir = self.project_root / "wordlists"
        self.reports_dir = self.project_root / "reports"
        self.logs_dir = self.project_root / "logs"
        self.nvd_cache_dir = self.project_root / ".cache" / "nvd"

        self.results = {
            "docker": [],
            "go_tools": [],
            "python_tools": [],
            "system_packages": [],
            "wordlists": [],
            "api_keys": [],
            "nvd": [],
            "directories": [],
        }

    # ────────────────────────────────────────────────────────────────
    # Main entry point
    # ────────────────────────────────────────────────────────────────

    def run_all(self) -> dict:
        """Run all prerequisite checks and installations."""
        print(f"\n{C.BOLD}{'='*60}")
        print(f"  VAPT Multi-Agent System — Prerequisite Checker")
        print(f"  Mode: {'CHECK ONLY' if self.check_only else 'CHECK + AUTO-INSTALL'}")
        print(f"{'='*60}{C.END}\n")

        self._ensure_directories()
        self._check_docker()
        self._check_go_tools()
        self._check_python_tools()
        self._check_system_packages()
        self._check_wordlists()
        self._check_api_keys()
        self._check_nvd_cache()
        self._print_summary()
        return self.results

    def run_tools(self) -> dict:
        """Only check/install tools."""
        self._check_docker()
        self._check_go_tools()
        self._check_python_tools()
        self._check_system_packages()
        self._print_summary()
        return self.results

    def run_docker(self) -> dict:
        """Only check/pull Docker images."""
        self._check_docker()
        self._print_summary()
        return self.results

    def run_wordlists(self) -> dict:
        """Only download wordlists."""
        self._check_wordlists()
        self._print_summary()
        return self.results

    def run_api_keys(self) -> dict:
        """Only validate API keys."""
        self._check_api_keys()
        self._print_summary()
        return self.results

    # ────────────────────────────────────────────────────────────────
    # Directory Setup
    # ────────────────────────────────────────────────────────────────

    def _ensure_directories(self):
        """Create required project directories."""
        print(f"{C.BOLD}[1/7] Checking project directories...{C.END}")
        dirs = [
            self.wordlist_dir,
            self.reports_dir,
            self.logs_dir,
            self.nvd_cache_dir,
        ]
        for d in dirs:
            if d.exists():
                print(C.ok(f"{d}"))
                self.results["directories"].append({"path": str(d), "status": "exists"})
            else:
                if not self.check_only:
                    d.mkdir(parents=True, exist_ok=True)
                    print(C.ok(f"{d} (created)"))
                    self.results["directories"].append({"path": str(d), "status": "created"})
                else:
                    print(C.warn(f"{d} (missing)"))
                    self.results["directories"].append({"path": str(d), "status": "missing"})

    # ────────────────────────────────────────────────────────────────
    # Docker
    # ────────────────────────────────────────────────────────────────

    def _check_docker(self):
        """Check Docker availability and pull required images."""
        print(f"\n{C.BOLD}[2/7] Checking Docker...{C.END}")

        docker_path = shutil.which("docker")
        if not docker_path:
            print(C.fail("Docker not found on PATH"))
            print(C.info("Install Docker: https://docs.docker.com/get-docker/"))
            print(C.info("Tools will run in direct mode (no container isolation)"))
            self.results["docker"].append({"tool": "docker-engine", "status": "missing"})
            return

        # Check Docker daemon
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                print(C.fail("Docker daemon not running"))
                self.results["docker"].append({"tool": "docker-engine", "status": "daemon-stopped"})
                return
            print(C.ok("Docker Engine running"))
        except Exception as e:
            print(C.fail(f"Docker check failed: {e}"))
            return

        # Pull images
        images_to_pull = DOCKER_IMAGES
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    cfg = yaml.safe_load(f)
                if cfg and "tools" in cfg:
                    for name, tcfg in cfg["tools"].items():
                        img = tcfg.get("docker_image", "")
                        if img and img not in images_to_pull:
                            images_to_pull.append(img)
            except Exception:
                pass

        print(f"\n  Checking {len(images_to_pull)} Docker images...")
        for image in images_to_pull:
            self._check_docker_image(image)

    def _check_docker_image(self, image: str):
        """Check if a Docker image exists locally, pull if missing."""
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            print(C.ok(f"{image}"))
            self.results["docker"].append({"tool": image, "status": "present"})
        else:
            if self.check_only:
                print(C.fail(f"{image} (not pulled)"))
                self.results["docker"].append({"tool": image, "status": "missing"})
            else:
                print(f"  {C.YELLOW}[PULLING]{C.END} {image}...")
                try:
                    pull = subprocess.run(
                        ["docker", "pull", image],
                        capture_output=True, text=True, timeout=300,
                    )
                    if pull.returncode == 0:
                        print(C.ok(f"{image} (pulled)"))
                        self.results["docker"].append({"tool": image, "status": "pulled"})
                    else:
                        print(C.fail(f"{image} (pull failed: {pull.stderr[:100]})"))
                        self.results["docker"].append({"tool": image, "status": "pull-failed"})
                except subprocess.TimeoutExpired:
                    print(C.fail(f"{image} (pull timeout)"))
                    self.results["docker"].append({"tool": image, "status": "timeout"})
                except Exception as e:
                    print(C.fail(f"{image} (error: {e})"))
                    self.results["docker"].append({"tool": image, "status": "error"})

    # ────────────────────────────────────────────────────────────────
    # Go Tools
    # ────────────────────────────────────────────────────────────────

    def _check_go_tools(self):
        """Check and install Go-based security tools."""
        print(f"\n{C.BOLD}[3/7] Checking Go-based tools...{C.END}")

        go_path = shutil.which("go")
        if not go_path:
            print(C.warn("Go not found — Go-based tools cannot be installed"))
            print(C.info("Install Go: https://go.dev/dl/"))
            for tool in GO_TOOLS:
                self.results["go_tools"].append({"tool": tool, "status": "go-missing"})
            return

        print(C.ok(f"Go found: {go_path}"))

        gobin = os.path.expanduser("~/go/bin")
        if gobin not in os.environ.get("PATH", ""):
            print(C.warn(f"$GOPATH/bin ({gobin}) not in PATH — add it!"))
            print(C.info(f'  export PATH="$PATH:{gobin}"'))

        for tool, info in GO_TOOLS.items():
            # Some entries are informational only
            if "note" in info and "install" not in info.get("install", ""):
                print(C.info(f"{tool}: {info['note']}"))
                self.results["go_tools"].append({"tool": tool, "status": "info", "note": info["note"]})
                continue

            tool_path = shutil.which(tool)
            if tool_path:
                print(C.ok(f"{tool}"))
                self.results["go_tools"].append({"tool": tool, "status": "present", "path": tool_path})
            elif self.check_only:
                print(C.fail(f"{tool} (not installed)"))
                self.results["go_tools"].append({"tool": tool, "status": "missing"})
            else:
                print(f"  {C.YELLOW}[INSTALLING]{C.END} {tool}...")
                try:
                    repo = info.get("repo", "")
                    if not repo or repo.endswith("/..."):
                        # Can't auto-install (amass, etc.)
                        print(C.warn(f"{tool}: Manual install required — {info.get('install', 'see repo')}"))
                        self.results["go_tools"].append({"tool": tool, "status": "manual-required"})
                        continue

                    install_cmd = ["go", "install", repo + "@latest"]
                    result = subprocess.run(
                        install_cmd, capture_output=True, text=True, timeout=300,
                        env={**os.environ, "GO111MODULE": "on"},
                    )
                    if result.returncode == 0 and shutil.which(tool):
                        print(C.ok(f"{tool} (installed)"))
                        self.results["go_tools"].append({"tool": tool, "status": "installed"})
                    else:
                        err = result.stderr[:150] if result.stderr else "unknown"
                        print(C.fail(f"{tool} (install failed: {err})"))
                        self.results["go_tools"].append({"tool": tool, "status": "install-failed", "error": err})
                except subprocess.TimeoutExpired:
                    print(C.fail(f"{tool} (timeout)"))
                    self.results["go_tools"].append({"tool": tool, "status": "timeout"})
                except Exception as e:
                    print(C.fail(f"{tool} (error: {e})"))
                    self.results["go_tools"].append({"tool": tool, "status": "error"})

    # ────────────────────────────────────────────────────────────────
    # Python Tools
    # ────────────────────────────────────────────────────────────────

    def _check_python_tools(self):
        """Check and install Python-based tools."""
        print(f"\n{C.BOLD}[4/7] Checking Python-based tools...{C.END}")

        for tool, info in PYTHON_TOOLS.items():
            # Check if it's a pip package
            pip_pkg = info.get("pip", "")
            if pip_pkg and not self.check_only:
                try:
                    # Try importing first
                    module_name = pip_pkg.replace("-", "_").lower()
                    if module_name == "sqlmap":
                        # sqlmap is a CLI tool, not importable
                        if shutil.which("sqlmap"):
                            print(C.ok(f"{tool}"))
                            self.results["python_tools"].append({"tool": tool, "status": "present"})
                            continue
                    elif module_name == "theharvester":
                        if shutil.which("theharvester"):
                            print(C.ok(f"{tool}"))
                            self.results["python_tools"].append({"tool": tool, "status": "present"})
                            continue
                    else:
                        try:
                            __import__(module_name)
                            print(C.ok(f"{tool} (via pip: {pip_pkg})"))
                            self.results["python_tools"].append({"tool": tool, "status": "present"})
                            continue
                        except ImportError:
                            pass

                    # Try to install
                    print(f"  {C.YELLOW}[INSTALLING]{C.END} {tool} (pip: {pip_pkg})...")
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", pip_pkg, "-q", "--disable-pip-version-check"],
                        capture_output=True, text=True, timeout=120,
                    )
                    if result.returncode == 0:
                        print(C.ok(f"{tool} (installed)"))
                        self.results["python_tools"].append({"tool": tool, "status": "installed"})
                    else:
                        print(C.warn(f"{tool} (pip install failed, may be a system tool)"))
                        self.results["python_tools"].append({"tool": tool, "status": "pip-failed"})
                except subprocess.TimeoutExpired:
                    print(C.fail(f"{tool} (timeout)"))
                    self.results["python_tools"].append({"tool": tool, "status": "timeout"})

            elif pip_pkg:
                # Check only mode
                try:
                    module_name = pip_pkg.replace("-", "_").lower()
                    __import__(module_name)
                    print(C.ok(f"{tool} (via pip: {pip_pkg})"))
                    self.results["python_tools"].append({"tool": tool, "status": "present"})
                except ImportError:
                    if shutil.which(tool):
                        print(C.ok(f"{tool} (CLI found)"))
                        self.results["python_tools"].append({"tool": tool, "status": "present"})
                    else:
                        print(C.fail(f"{tool} (not installed)"))
                        self.results["python_tools"].append({"tool": tool, "status": "missing"})
            else:
                # System tool or note-only
                note = info.get("note", "System package")
                tool_path = shutil.which(tool)
                if tool_path:
                    print(C.ok(f"{tool} — {note}"))
                    self.results["python_tools"].append({"tool": tool, "status": "present", "path": tool_path})
                else:
                    print(C.warn(f"{tool} — {note} (not found)"))
                    self.results["python_tools"].append({"tool": tool, "status": "missing", "note": note})

    # ────────────────────────────────────────────────────────────────
    # System Packages
    # ────────────────────────────────────────────────────────────────

    def _check_system_packages(self):
        """Check system-level packages."""
        print(f"\n{C.BOLD}[5/7] Checking system packages...{C.END}")

        pkg_manager = None
        if shutil.which("apt-get"):
            pkg_manager = "apt"
        elif shutil.which("brew"):
            pkg_manager = "brew"
        elif shutil.which("dnf"):
            pkg_manager = "dnf"
        elif shutil.which("pacman"):
            pkg_manager = "pacman"

        if not pkg_manager:
            print(C.warn("No known package manager detected (apt/brew/dnf/pacman)"))
            for pkg in SYSTEM_PACKAGES:
                tool_path = shutil.which(pkg)
                status = "present" if tool_path else "missing"
                print(C.ok(pkg) if tool_path else C.fail(f"{pkg} (not found)"))
                self.results["system_packages"].append({"tool": pkg, "status": status})
            return

        print(C.ok(f"Package manager: {pkg_manager}"))

        for pkg, info in SYSTEM_PACKAGES.items():
            pkg_name = info.get(pkg_manager, info.get("apt", pkg))
            tool_path = shutil.which(pkg)
            if tool_path:
                print(C.ok(f"{pkg}"))
                self.results["system_packages"].append({"tool": pkg, "status": "present"})
            elif self.check_only:
                print(C.fail(f"{pkg} (not installed)"))
                self.results["system_packages"].append({"tool": pkg, "status": "missing"})
            else:
                print(f"  {C.YELLOW}[INSTALLING]{C.END} {pkg} ({pkg_name})...")
                try:
                    if pkg_manager == "apt":
                        cmd = ["sudo", "apt-get", "install", "-y", pkg_name]
                    elif pkg_manager == "brew":
                        cmd = ["brew", "install", pkg_name]
                    elif pkg_manager == "dnf":
                        cmd = ["sudo", "dnf", "install", "-y", pkg_name]
                    else:
                        cmd = ["sudo", "pacman", "-S", "--noconfirm", pkg_name]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if result.returncode == 0:
                        print(C.ok(f"{pkg} (installed)"))
                        self.results["system_packages"].append({"tool": pkg, "status": "installed"})
                    else:
                        print(C.fail(f"{pkg} (install failed — may need sudo)"))
                        self.results["system_packages"].append({"tool": pkg, "status": "install-failed"})
                except Exception as e:
                    print(C.fail(f"{pkg} (error: {e})"))
                    self.results["system_packages"].append({"tool": pkg, "status": "error"})

    # ────────────────────────────────────────────────────────────────
    # Wordlists
    # ────────────────────────────────────────────────────────────────

    def _check_wordlists(self):
        """Check and download required wordlists."""
        print(f"\n{C.BOLD}[6/7] Checking wordlists...{C.END}")

        self.wordlist_dir.mkdir(parents=True, exist_ok=True)

        for name, info in WORDLIST_URLS.items():
            local_path = self.wordlist_dir / info["path"].replace("wordlists/", "")
            if local_path.exists() and local_path.stat().st_size > 100:
                size_kb = local_path.stat().st_size / 1024
                print(C.ok(f"{name} ({size_kb:.0f} KB)"))
                self.results["wordlists"].append({"tool": name, "status": "present", "size_kb": size_kb})
            elif self.check_only:
                print(C.fail(f"{name} (missing)"))
                self.results["wordlists"].append({"tool": name, "status": "missing"})
            else:
                print(f"  {C.YELLOW}[DOWNLOADING]{C.END} {name}...")
                try:
                    import urllib.request
                    urllib.request.urlretrieve(info["url"], local_path)
                    size_kb = local_path.stat().st_size / 1024
                    print(C.ok(f"{name} ({size_kb:.0f} KB, downloaded)"))
                    self.results["wordlists"].append({"tool": name, "status": "downloaded", "size_kb": size_kb})
                except Exception as e:
                    print(C.fail(f"{name} (download failed: {e})"))
                    self.results["wordlists"].append({"tool": name, "status": "download-failed"})

    # ────────────────────────────────────────────────────────────────
    # API Keys
    # ────────────────────────────────────────────────────────────────

    def _check_api_keys(self):
        """Validate configured API keys."""
        print(f"\n{C.BOLD}[7/7] Checking API keys...{C.END}")

        for env_var, info in API_KEY_ENV_VARS.items():
            value = os.environ.get(env_var, "")
            if value:
                # Basic validation — check length and format
                if len(value) >= 8:
                    masked = value[:6] + "*" * (len(value) - 10) + value[-4:]
                    print(C.ok(f"{info['service']} ({env_var}={masked}) — {info['required_for']}"))
                    self.results["api_keys"].append({"service": info['service'], "status": "configured", "env_var": env_var})
                else:
                    print(C.warn(f"{info['service']} ({env_var}) — value seems too short"))
                    self.results["api_keys"].append({"service": info['service'], "status": "invalid", "env_var": env_var})
            else:
                print(C.warn(f"{info['service']} ({env_var}) — NOT SET — needed for: {info['required_for']}"))
                self.results["api_keys"].append({"service": info['service'], "status": "not-set", "env_var": env_var})

    # ────────────────────────────────────────────────────────────────
    # NVD Cache
    # ────────────────────────────────────────────────────────────────

    def _check_nvd_cache(self):
        """Check if NVD CVE database cache exists for offline matching."""
        print(f"\n{C.BOLD}[BONUS] Checking NVD CVE cache...{C.END}")

        cache_file = self.nvd_cache_dir / "nvdcve_2.0.json"
        if cache_file.exists():
            size_mb = cache_file.stat().st_size / (1024 * 1024)
            print(C.ok(f"NVD cache present ({size_mb:.1f} MB)"))
            self.results["nvd"].append({"status": "present", "size_mb": size_mb})
        else:
            if self.check_only:
                print(C.warn("NVD cache not present — CVE matching will use built-in database only"))
                self.results["nvd"].append({"status": "missing"})
            else:
                print(C.info("NVD cache not present. Downloading CVE data (this may take a few minutes)..."))
                try:
                    import urllib.request
                    self.nvd_cache_dir.mkdir(parents=True, exist_ok=True)
                    # NVD 2.0 CVE feed (recent)
                    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5000"
                    req = urllib.request.Request(url, headers={
                        "User-Agent": "VAPT-Agent/1.0 (security-scanner)",
                    })
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        data = resp.read()
                        with open(cache_file, "wb") as f:
                            f.write(data)
                    size_mb = len(data) / (1024 * 1024)
                    print(C.ok(f"NVD cache downloaded ({size_mb:.1f} MB)"))
                    self.results["nvd"].append({"status": "downloaded", "size_mb": size_mb})
                except Exception as e:
                    print(C.warn(f"NVD download failed: {e} — will use built-in CVE database"))
                    self.results["nvd"].append({"status": "download-failed", "error": str(e)})

    # ────────────────────────────────────────────────────────────────
    # Summary
    # ────────────────────────────────────────────────────────────────

    def _print_summary(self):
        """Print final summary of all checks."""
        total = 0
        present = 0
        missing = 0

        for category, items in self.results.items():
            for item in items:
                if isinstance(item, dict):
                    total += 1
                    status = item.get("status", "")
                    if status in ("present", "exists", "created", "pulled", "installed", "downloaded", "configured", "info"):
                        present += 1
                    elif status in ("missing", "not-set", "daemon-stopped", "go-missing", "manual-required"):
                        missing += 1

        print(f"\n{C.BOLD}{'='*60}")
        print(f"  SUMMARY: {present}/{total} ready, {missing} missing or warnings")
        print(f"{'='*60}{C.END}\n")

        if missing > 0:
            print(f"  {C.YELLOW}To install missing items, run: python -m tools.prerequisites{C.END}")
            print(f"  {C.YELLOW}For check-only mode: python -m tools.prerequisites --check-only{C.END}\n")

        # Save results to JSON
        report_path = self.project_root / ".cache" / "prereq-report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VAPT Agent — Prerequisite Checker & Auto-Installer")
    parser.add_argument("--check-only", action="store_true", help="Only check, don't install/pull/download")
    parser.add_argument("--tools", action="store_true", help="Only check/install tools")
    parser.add_argument("--docker", action="store_true", help="Only check/pull Docker images")
    parser.add_argument("--wordlists", action="store_true", help="Only download wordlists")
    parser.add_argument("--api-keys", action="store_true", help="Only validate API keys")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")

    args = parser.parse_args()

    checker = PrerequisiteChecker(
        config_path=args.config,
        check_only=args.check_only,
    )

    if args.tools:
        checker.run_tools()
    elif args.docker:
        checker.run_docker()
    elif args.wordlists:
        checker.run_wordlists()
    elif args.api_keys:
        checker.run_api_keys()
    else:
        checker.run_all()
