"""Scope enforcement — the guard that keeps the engine on authorised targets.

Recon (Module 1) discovers subdomains with subfinder and validates them with
httpx. Some of what it surfaces can be **out of the bounty program's scope** — a
subdomain hosted by a third party, a shared-service host, or one the program
explicitly excludes. Sending active traffic (katana, ffuf, naabu, nuclei) at
those is a scope violation: against the platform's rules and, depending on the
host, illegal. This module is the single place that decides what is allowed.

Usage::

    guard = ScopeGuard.from_target("example.com")          # apex + all subdomains
    guard = ScopeGuard.from_files("scope.txt", "oos.txt")  # explicit rules
    kept, dropped = guard.filter(live_hosts)

Pattern rules (one per line in a scope file; ``#`` comments and blanks ignored):

  * ``example.com``      → the apex **and** every subdomain (``*.example.com``).
    This matches how most bounty programs phrase "example.com and all subdomains".
  * ``*.example.com``    → the apex and every subdomain (same, explicit wildcard).
  * ``app.example.com``  → that exact host only.
  * ``!admin.example.com`` in a scope file → an inline exclusion (same as putting
    it in the out-of-scope file). Out-of-scope always wins over in-scope.
  * ``1.2.3.4``          → that exact IP.

If no in-scope rule is given, :meth:`from_target` derives the conservative
default (the target apex and its subdomains) so behaviour matches the pre-guard
engine — only now it is explicit and enforced.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit


def _host_of(value: str) -> str:
    """Reduce a URL / host[:port] / bare host to a lowercased bare hostname."""
    t = (value or "").strip()
    if not t:
        return ""
    if "://" in t:
        t = urlsplit(t).hostname or ""
    else:
        # Strip any path/query/fragment and userinfo, then the port.
        t = t.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in t:
            t = t.rsplit("@", 1)[1]
        # Keep IPv6 literals ("[::1]") intact; strip a trailing :port otherwise.
        if not t.startswith("[") and t.count(":") == 1:
            t = t.split(":", 1)[0]
    return t.rstrip(".").lower()


def _normalize_pattern(pat: str) -> str:
    """Normalize a scope pattern to a comparable form (drops a leading ``*.``)."""
    p = (pat or "").strip().lower().rstrip(".")
    if p.startswith("*."):
        p = p[2:]
    return p


def _matches(host: str, pattern: str) -> bool:
    """Does ``host`` fall under ``pattern`` (apex-or-subdomain semantics)?"""
    if not host or not pattern:
        return False
    return host == pattern or host.endswith("." + pattern)


class ScopeGuard:
    def __init__(self, in_scope: list[str] | None, out_of_scope: list[str] | None = None):
        raw_in = list(in_scope or [])
        raw_out = list(out_of_scope or [])
        # A "!host" line inside the in-scope list is an inline exclusion.
        for p in raw_in:
            if p.strip().startswith("!"):
                raw_out.append(p.strip()[1:])
        self.in_scope = [_normalize_pattern(p) for p in raw_in
                         if p.strip() and not p.strip().startswith(("#", "!"))]
        self.out_of_scope = [_normalize_pattern(p) for p in raw_out
                             if p.strip() and not p.strip().startswith("#")]

    # ── constructors ─────────────────────────────────────────────────────────
    @classmethod
    def from_target(cls, target: str, out_of_scope: list[str] | None = None) -> "ScopeGuard":
        """Default guard: the target apex and all its subdomains are in scope."""
        apex = _host_of(target)
        return cls([apex] if apex else [], out_of_scope)

    @classmethod
    def _read_lines(cls, path: str | None) -> list[str]:
        if not path:
            return []
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Scope file not found: {path!r}")
        return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() and not ln.strip().startswith("#")]

    @classmethod
    def from_files(cls, scope_file: str | None, oos_file: str | None = None) -> "ScopeGuard":
        return cls(cls._read_lines(scope_file), cls._read_lines(oos_file))

    # ── decisions ────────────────────────────────────────────────────────────
    @property
    def is_empty(self) -> bool:
        """True when there is no in-scope rule (guard would drop everything)."""
        return not self.in_scope

    def is_in_scope(self, host_or_url: str) -> bool:
        host = _host_of(host_or_url)
        if not host:
            return False
        if any(_matches(host, p) for p in self.out_of_scope):
            return False  # exclusion always wins
        return any(_matches(host, p) for p in self.in_scope)

    def filter(self, items: list[str], key=None) -> tuple[list[str], list[str]]:
        """Split ``items`` into ``(kept, dropped)`` by scope.

        ``key`` extracts the host/URL from each item when items aren't plain
        strings; it defaults to the item itself.
        """
        kept, dropped = [], []
        for item in items:
            value = key(item) if key else item
            (kept if self.is_in_scope(value) else dropped).append(item)
        return kept, dropped

    def describe(self) -> str:
        inn = ", ".join(self.in_scope) or "(none)"
        out = ", ".join(self.out_of_scope) or "(none)"
        return f"in-scope: {inn} | out-of-scope: {out}"
