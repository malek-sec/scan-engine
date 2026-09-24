"""Optional robots.txt awareness for polite, low-footprint scanning.

Bug-bounty scope authorises the traffic, so honouring robots.txt is not
required — but under ``--respect-robots`` the engine will drop URLs a site asks
crawlers not to touch (login flows, logout links, print views, admin stubs).
That trims noise, avoids poking at deliberately fragile endpoints, and keeps the
scan's footprint closer to what the site expects.

Scope of enforcement (be honest about it): this filters the URL sets the engine
controls — discovered JS files and historical/seed endpoints handed to the
active phase. It does not reach inside katana's own crawl, which manages its
requests itself. Everything here is best-effort: a missing or unreachable
robots.txt means "nothing disallowed", never an error.
"""

from __future__ import annotations

import urllib.request
from urllib.parse import urlsplit

_UA = ("Mozilla/5.0 (compatible; scan-engine/1.0; +https://github.com/malek-sec/scan-engine)")


def _origin(url: str) -> str:
    parts = urlsplit(url if "://" in url else "https://" + url)
    if not parts.hostname:
        return ""
    scheme = parts.scheme or "https"
    netloc = parts.netloc or parts.hostname
    return f"{scheme}://{netloc}"


def parse_disallows(text: str, user_agent: str = "*") -> list[str]:
    """Return the Disallow path-prefixes that apply to ``user_agent``.

    Simplified robots grammar: records are grouped by ``User-agent`` lines; a
    group's ``Disallow`` rules apply if the group targets ``*`` or our UA. An
    empty ``Disallow:`` means "allow everything" and contributes no prefix.
    """
    disallows: list[str] = []
    applies = False
    ua = user_agent.lower()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            agent = value.lower()
            applies = agent in ("*", ua)
        elif field == "disallow" and applies:
            if value:  # empty Disallow = allow all -> skip
                disallows.append(value)
    # De-dup, preserve order.
    return list(dict.fromkeys(disallows))


class RobotsPolicy:
    def __init__(self, rules_by_origin: dict[str, list[str]]):
        # origin -> list of disallowed path prefixes.
        self._rules = rules_by_origin

    @classmethod
    def from_map(cls, rules_by_origin: dict[str, list[str]]) -> "RobotsPolicy":
        return cls(dict(rules_by_origin))

    @classmethod
    def fetch(cls, urls: list[str], timeout: int = 10) -> "RobotsPolicy":
        """Fetch and parse robots.txt for every distinct origin in ``urls``."""
        rules: dict[str, list[str]] = {}
        for origin in dict.fromkeys(_origin(u) for u in urls if _origin(u)):
            try:
                req = urllib.request.Request(origin + "/robots.txt", headers={"User-Agent": _UA})
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (http(s) only)
                    body = resp.read(512 * 1024).decode("utf-8", errors="replace")
                rules[origin] = parse_disallows(body)
            except Exception:
                rules[origin] = []  # unreachable robots -> nothing disallowed
        return cls(rules)

    def is_allowed(self, url: str) -> bool:
        origin = _origin(url)
        prefixes = self._rules.get(origin)
        if not prefixes:
            return True
        path = urlsplit(url if "://" in url else "https://" + url).path or "/"
        return not any(path.startswith(p) for p in prefixes)

    def filter(self, urls: list[str]) -> tuple[list[str], list[str]]:
        kept, dropped = [], []
        for u in urls:
            (kept if self.is_allowed(u) else dropped).append(u)
        return kept, dropped
