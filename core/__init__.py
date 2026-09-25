"""
BountyHub v2 — core package
Shared utilities: terminal styling, configuration, dependency checking.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Environment parsing helpers ───────────────────────────────────────────────
# Small, defensive coercions so every tunable can be overridden from the
# environment (systemd unit, Dockerfile, .env) without editing Python. An
# unset/blank/invalid value always falls back to the provided default.

def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return raw if raw is not None and raw.strip() != "" else default


# ═════════════════════════════════════════════════════════════════════════════
# TERMINAL STYLING
# ═════════════════════════════════════════════════════════════════════════════

class Colors:
    RESET     = "\033[0m"
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    UNDERLINE = "\033[4m"

    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    BLUE      = "\033[94m"
    MAGENTA   = "\033[95m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    GRAY      = "\033[90m"

    SUCCESS   = GREEN
    ERROR     = RED
    WARNING   = YELLOW
    INFO      = CYAN
    DATA      = WHITE
    AI        = MAGENTA
    SECTION   = BLUE


class Logger:
    @staticmethod
    def banner() -> None:
        b = f"""
{Colors.CYAN}{Colors.BOLD}
 ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗██╗  ██╗██╗   ██╗██████╗
 ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝██║  ██║██║   ██║██╔══██╗
 ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ ███████║██║   ██║██████╔╝
 ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  ██╔══██║██║   ██║██╔══██╗
 ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   ██║  ██║╚██████╔╝██████╔╝
 ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝
{Colors.RESET}
{Colors.GRAY}  ──────────────────────────────────────────────────────────────────────{Colors.RESET}
{Colors.YELLOW}  Recon & vulnerability-analysis pipeline{Colors.RESET}{Colors.DIM}   ·   scan-engine v2.0.0{Colors.RESET}
{Colors.GRAY}  Rate-bounded by design  ·  offline-first ($0)  ·  Claude-powered advisor{Colors.RESET}
{Colors.GRAY}  ──────────────────────────────────────────────────────────────────────{Colors.RESET}
{Colors.RED}{Colors.BOLD}  [!] Authorised targets only — you own scope and program-policy compliance.{Colors.RESET}
{Colors.GRAY}  ──────────────────────────────────────────────────────────────────────{Colors.RESET}
"""
        print(b)

    @staticmethod
    def section(title: str) -> None:
        line = "─" * 62
        print(f"\n{Colors.SECTION}{Colors.BOLD}{line}{Colors.RESET}")
        print(f"{Colors.SECTION}{Colors.BOLD}  {title}{Colors.RESET}")
        print(f"{Colors.SECTION}{Colors.BOLD}{line}{Colors.RESET}\n")

    @staticmethod
    def info(msg: str) -> None:
        print(f"{Colors.INFO}[*]{Colors.RESET} {msg}")

    @staticmethod
    def success(msg: str) -> None:
        print(f"{Colors.SUCCESS}[+]{Colors.RESET} {msg}")

    @staticmethod
    def warning(msg: str) -> None:
        print(f"{Colors.WARNING}[!]{Colors.RESET} {msg}")

    @staticmethod
    def error(msg: str) -> None:
        print(f"{Colors.ERROR}[-]{Colors.RESET} {msg}")

    @staticmethod
    def data(label: str, value: str) -> None:
        print(f"    {Colors.YELLOW}{label:<22}{Colors.RESET} {Colors.WHITE}{value}{Colors.RESET}")

    @staticmethod
    def cmd(command: str) -> None:
        print(f"    {Colors.GRAY}$ {command}{Colors.RESET}")

    @staticmethod
    def ai_block(content: str, title: str = "AI Analysis") -> None:
        """Render AI-generated text inside a visually distinct bordered block.

        The provider is passed in rather than hardcoded: the advisor runs on
        Claude while the interactive report module runs on Gemini, so a fixed
        label here would be wrong for one of them.
        """
        border = "─" * 60
        header = f"┌─ {title} "
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}{header}{'─' * max(0, 62 - len(header))}{Colors.RESET}")
        for line in content.strip().split("\n"):
            # Highlight Markdown headers inline for readability
            if line.startswith("## "):
                print(f"{Colors.MAGENTA}│{Colors.RESET}  {Colors.CYAN}{Colors.BOLD}{line}{Colors.RESET}")
            elif line.startswith("### "):
                print(f"{Colors.MAGENTA}│{Colors.RESET}  {Colors.YELLOW}{line}{Colors.RESET}")
            elif line.startswith("**") and line.endswith("**"):
                print(f"{Colors.MAGENTA}│{Colors.RESET}  {Colors.WHITE}{Colors.BOLD}{line}{Colors.RESET}")
            elif line.startswith("```"):
                print(f"{Colors.MAGENTA}│{Colors.RESET}  {Colors.GRAY}{line}{Colors.RESET}")
            else:
                print(f"{Colors.MAGENTA}│{Colors.RESET}  {line}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}└{border}{Colors.RESET}\n")


# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

class Config:
    # ── API ───────────────────────────────────────────────────────────────
    GEMINI_API_KEY: Optional[str] = os.environ.get("GEMINI_API_KEY")
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # ── Required/Optional System Binaries ─────────────────────────────────
    # Absolute path to ProjectDiscovery's httpx. Leave None to auto-detect.
    # Set this when BountyHub runs as a service/container/other user, where
    # $PATH is not the operator's interactive shell PATH. The env var makes it
    # settable from a systemd unit or Dockerfile without editing Python.
    # A value set here is validated like any other candidate and is NEVER
    # silently ignored: if it is not real ProjectDiscovery httpx, recon fails
    # loud rather than falling back to autodetect.
    HTTPX_BINARY: Optional[str] = os.environ.get("BOUNTYHUB_HTTPX_BINARY") or None

    RECON_TOOLS       = ["subfinder", "httpx"]
    FINGERPRINT_TOOLS = ["nmap", "whatweb"]
    OPTIONAL_TOOLS    = ["nuclei", "ffuf", "sqlmap", "dalfox"]

    # ── Stealth / Polite Mode ─────────────────────────────────────────────
    # These values govern OPSEC-safe scanning used by both the CLI and the
    # web integration.  They are deliberately conservative so BountyHub
    # never floods a target or trips rate-limiting defences.
    #
    # httpx (env-overridable so the --polite preset and strict programs can lower them)
    HTTPX_THREADS:      int = _env_int("BOUNTYHUB_HTTPX_THREADS", 5)   # concurrent probing threads (-threads)
    HTTPX_RL:           int = _env_int("BOUNTYHUB_HTTPX_RL", 30)       # requests/second hard cap (-rl)
    HTTPX_TIMEOUT:      int = 10     # per-probe timeout in seconds  (-timeout)
    # NOTE: HTTPX_CONCURRENCY was removed. It only ever fed httpx's -c flag,
    # which upstream deleted in httpx v1.9 (passing it aborts the run). The
    # RoE concurrency ceiling is carried by HTTPX_THREADS + HTTPX_RL.
    #
    # nmap
    NMAP_TOP_PORTS:     int = 50     # only scan the 50 most common ports
    NMAP_TIMING:        str = "2"    # T2 = polite (slow, low noise)
    NMAP_MAX_RATE:      int = _env_int("BOUNTYHUB_NMAP_MAX_RATE", 10)  # max packets/second
    #
    # whatweb
    WHATWEB_AGGRESSION: int = 1      # 1 = stealthy passive-only requests
    #
    # subfinder
    SUBFINDER_TIMEOUT:  int = 30     # per-source DNS query timeout

    # ── Active Recon & Fuzzing (Module 2.5) ───────────────────────────────
    # Every value below is env-overridable (BOUNTYHUB_ACTIVE_* prefix). Defaults
    # are "aggressive but bounded" — louder than passive recon, never a flood.
    # ACTIVE_RECON_ENABLED is a global kill-switch; the per-scan Fast/Deep choice
    # is a separate flag passed in from the API.
    ACTIVE_RECON_ENABLED: bool = _env_bool("BOUNTYHUB_ACTIVE_RECON_ENABLED", True)
    ACTIVE_MAX_HOSTS:     int  = _env_int("BOUNTYHUB_ACTIVE_MAX_HOSTS", 5)
    ACTIVE_TOTAL_BUDGET:  int  = _env_int("BOUNTYHUB_ACTIVE_TOTAL_BUDGET", 900)

    # katana (crawling)
    ACTIVE_KATANA_DEPTH:         int = _env_int("BOUNTYHUB_ACTIVE_KATANA_DEPTH", 3)
    ACTIVE_KATANA_RL:           int = _env_int("BOUNTYHUB_ACTIVE_KATANA_RL", 100)
    ACTIVE_KATANA_CONC:         int = _env_int("BOUNTYHUB_ACTIVE_KATANA_CONC", 10)
    ACTIVE_KATANA_TIMEOUT:      int = _env_int("BOUNTYHUB_ACTIVE_KATANA_TIMEOUT", 300)
    ACTIVE_KATANA_MAX_ENDPOINTS:int = _env_int("BOUNTYHUB_ACTIVE_KATANA_MAX_ENDPOINTS", 3000)
    # katana crawl field-scope: dn | rdn | fqdn. Default "rdn" (root domain) so an
    # apex->www redirect (e.g. example.com -> www.example.com) is still crawled;
    # "fqdn" restricts to the exact host and silently misses the www redirect
    # target — the bug that made JS discovery return nothing on WordPress sites.
    ACTIVE_KATANA_SCOPE:        str = _env_str("BOUNTYHUB_ACTIVE_KATANA_SCOPE", "rdn")

    # ffuf (directory / file fuzzing)
    ACTIVE_FFUF_RATE:        int = _env_int("BOUNTYHUB_ACTIVE_FFUF_RATE", 60)
    ACTIVE_FFUF_THREADS:     int = _env_int("BOUNTYHUB_ACTIVE_FFUF_THREADS", 40)
    ACTIVE_FFUF_TIMEOUT:     int = _env_int("BOUNTYHUB_ACTIVE_FFUF_TIMEOUT", 10)
    ACTIVE_FFUF_MAXTIME:     int = _env_int("BOUNTYHUB_ACTIVE_FFUF_MAXTIME", 240)
    ACTIVE_FFUF_MATCH_CODES: str = _env_str("BOUNTYHUB_ACTIVE_FFUF_MATCH_CODES",
                                            "200,204,301,302,307,401,403,405,500")

    # arjun (hidden parameter discovery)
    ACTIVE_ARJUN_MAX_ENDPOINTS: int = _env_int("BOUNTYHUB_ACTIVE_ARJUN_MAX_ENDPOINTS", 15)
    ACTIVE_ARJUN_THREADS:       int = _env_int("BOUNTYHUB_ACTIVE_ARJUN_THREADS", 10)
    ACTIVE_ARJUN_TIMEOUT:       int = _env_int("BOUNTYHUB_ACTIVE_ARJUN_TIMEOUT", 300)

    # naabu (comprehensive port scanning)
    ACTIVE_NAABU_TOP_PORTS: int  = _env_int("BOUNTYHUB_ACTIVE_NAABU_TOP_PORTS", 1000)
    ACTIVE_NAABU_ALL_PORTS: bool = _env_bool("BOUNTYHUB_ACTIVE_NAABU_ALL_PORTS", False)
    ACTIVE_NAABU_RATE:      int  = _env_int("BOUNTYHUB_ACTIVE_NAABU_RATE", 1000)
    ACTIVE_NAABU_TIMEOUT:   int  = _env_int("BOUNTYHUB_ACTIVE_NAABU_TIMEOUT", 480)

    # nuclei (template-based vulnerability scanning)
    ACTIVE_NUCLEI_RL:           int = _env_int("BOUNTYHUB_ACTIVE_NUCLEI_RL", 100)
    ACTIVE_NUCLEI_CONC:         int = _env_int("BOUNTYHUB_ACTIVE_NUCLEI_CONC", 25)
    ACTIVE_NUCLEI_TIMEOUT:      int = _env_int("BOUNTYHUB_ACTIVE_NUCLEI_TIMEOUT", 480)
    ACTIVE_NUCLEI_MAX_TARGETS:  int = _env_int("BOUNTYHUB_ACTIVE_NUCLEI_MAX_TARGETS", 200)
    ACTIVE_NUCLEI_SEVERITY:     str = _env_str("BOUNTYHUB_ACTIVE_NUCLEI_SEVERITY",
                                               "low,medium,high,critical")
    ACTIVE_NUCLEI_EXCLUDE_TAGS: str = _env_str("BOUNTYHUB_ACTIVE_NUCLEI_EXCLUDE_TAGS",
                                               "dos,fuzz,intrusive,brute-force")

    # Optional explicit directory wordlist override (else SecLists autodetect).
    ACTIVE_DIR_WORDLIST: Optional[str] = os.environ.get("BOUNTYHUB_ACTIVE_DIR_WORDLIST") or None

    # ── Output File Names ─────────────────────────────────────────────────
    FILE_SUBDOMAINS  = "subdomains.txt"
    FILE_LIVE_HOSTS  = "live_hosts.txt"
    FILE_FINGERPRINT = "fingerprint.json"
    FILE_AI_ADVICE   = "ai_advice.txt"
    # Anchored to the project root so results always land in
    # <scan-engine>/bountyhub_output/ no matter which directory the CLI is run
    # from. Override with BOUNTYHUB_OUTPUT_BASE (absolute or relative to cwd).
    OUTPUT_BASE      = _env_str(
        "BOUNTYHUB_OUTPUT_BASE",
        str(Path(__file__).resolve().parent.parent / "bountyhub_output"),
    )

    @classmethod
    def engagement_dir(cls, target: str) -> Path:
        safe = re.sub(r"[^\w\-.]", "_", target)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(cls.OUTPUT_BASE) / f"{safe}_{ts}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @classmethod
    def api_key_present(cls) -> bool:
        return bool(cls.GEMINI_API_KEY and cls.GEMINI_API_KEY.strip())


# ═════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECKER
# ═════════════════════════════════════════════════════════════════════════════

# Expected `-version` output per tool, so a pre-flight check can prove it found
# the RIGHT binary rather than merely *a* binary with the right filename.
#
# This exists because /usr/bin/httpx is Debian's python3-httpx package — an
# unrelated HTTP-client CLI. A blind shutil.which() greenlights it while the
# recon layer correctly refuses it, so the pre-flight would report all-clear
# for a scan that cannot possibly work.
#
# {tool: (version_argv, compiled signature regex)}
TOOL_SIGNATURES: dict = {
    "httpx":     (["-version"], re.compile(r"Current Version:\s*v?\d+(?:\.\d+)*", re.I)),
    "subfinder": (["-version"], re.compile(r"Current Version:\s*v?\d+(?:\.\d+)*", re.I)),
    "nuclei":    (["-version"], re.compile(r"Current Version:\s*v?\d+(?:\.\d+)*", re.I)),
    "nmap":      (["--version"], re.compile(r"\bNmap version\s+\d+(?:\.\d+)*", re.I)),
    "whatweb":   (["--version"], re.compile(r"\bWhatWeb version\s+\d+(?:\.\d+)*", re.I)),
    "openssl":   (["version"],   re.compile(r"\bOpenSSL\s+\d+(?:\.\d+)*", re.I)),
    "ffuf":      (["-V"],        re.compile(r"\bffuf version:?\s*\S+", re.I)),
    "sqlmap":    (["--version"], re.compile(r"\d+\.\d+")),
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def identify_tool(name: str, path: str) -> tuple:
    """
    Confirm `path` really is the tool called `name`.

    Returns (True, detail) or (False, reason). Tools with no registered
    signature are accepted with a note — absence of a signature must not be
    reported as a failure, only as unverified.
    """
    sig = TOOL_SIGNATURES.get(name)
    if not sig:
        return True, "no signature registered (unverified)"

    argv, pattern = sig
    try:
        proc = subprocess.run([path, *argv], capture_output=True,
                              text=True, timeout=20)
    except FileNotFoundError:
        return False, "not present"
    except PermissionError:
        return False, "not executable"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, exc.__class__.__name__

    blob  = _ANSI_RE.sub("", f"{proc.stdout}\n{proc.stderr}")
    match = pattern.search(blob)
    if match:
        return True, match.group(0).strip()

    if "No such option" in blob or "Usage: httpx [OPTIONS] URL" in blob:
        return False, ("python3-httpx impostor — Debian's python3-httpx package "
                       "installs an unrelated CLI under this name")
    return False, f"signature not found (exit {proc.returncode}) — wrong tool?"


def resolve_tool(name: str) -> tuple:
    """
    Locate a validated binary for `name`.

    Delegates to the recon layer's dedicated resolver where one exists, so the
    pre-flight can never disagree with the module that actually runs the tool.
    Returns (path, None) or (None, reason).
    """
    if name == "httpx":
        # Single source of truth — PATH-independent and impostor-aware.
        from core.recon import _resolve_httpx      # local: avoids a cycle
        return _resolve_httpx()

    path = shutil.which(name)
    if not path:
        return None, "not found on $PATH"
    ok, detail = identify_tool(name, path)
    return (path, None) if ok else (None, f"{path} — {detail}")


class DependencyChecker:
    @staticmethod
    def tool_exists(name: str) -> bool:
        """True only when a VALIDATED binary for `name` is available."""
        return resolve_tool(name)[0] is not None

    @classmethod
    def verify(cls, tool_list: list, label: str) -> bool:
        Logger.info(f"Pre-flight check: {label}")
        all_ok = True
        for tool in tool_list:
            path, reason = resolve_tool(tool)
            if path:
                _, detail = identify_tool(tool, path)
                Logger.success(
                    f"  {tool:<18} {Colors.GRAY}→ {path}  [{detail}]{Colors.RESET}")
            else:
                Logger.error(f"  {tool:<18} UNUSABLE — {reason}")
                Logger.warning(
                    f"    Install: sudo apt install {tool} -y"
                    f"  OR  go install github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest"
                )
                all_ok = False
        return all_ok

    @classmethod
    def check_optional(cls) -> None:
        Logger.info("Optional tools:")
        for tool in Config.OPTIONAL_TOOLS:
            path, reason = resolve_tool(tool)
            if path:
                _, detail = identify_tool(tool, path)
                status = (f"{Colors.SUCCESS}found{Colors.RESET} → "
                          f"{Colors.GRAY}{path}  [{detail}]{Colors.RESET}")
            else:
                status = (f"{Colors.WARNING}unusable{Colors.RESET} "
                          f"{Colors.GRAY}({reason}){Colors.RESET} (AI may reference it)")
            print(f"    {tool:<18} {status}")
