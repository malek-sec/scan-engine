# scan-engine

The reconnaissance pipeline behind [BountyHub](https://github.com/malek-sec/BountyHub).
It takes a domain and produces a structured picture of the attack surface:
subdomains, live hosts, open ports, technology stack, crawled endpoints,
JavaScript findings, and a written report.

It runs two ways: as a standalone CLI, or imported as a Python package by the
BountyHub web application, which drives the same modules and streams progress to
a browser. Both paths share one code base and one set of rate limits.

| Repository | Role |
|---|---|
| **scan-engine** (this repo) | Scanning pipeline and AI advisor |
| [BountyHub](https://github.com/malek-sec/BountyHub) | Web UI, findings database, reports |
| [JS-Oracle](https://github.com/malek-sec/JS-Oracle) | JavaScript analysis backend for Module 4 |

> Use this only against systems you have explicit written authorisation to test.
> The active recon phase sends real traffic — crawling, fuzzing, and template
> scanning. Running it outside an authorised scope is illegal in most
> jurisdictions and violates the terms of every bounty platform.

---

## Design

Two principles run through the whole engine.

**Nothing floods a target.** Every external tool is invoked with an explicit rate
cap, thread ceiling, and timeout. `nmap` runs at `-T2` with a 10 packet/second
ceiling over the top 50 ports. `httpx` probes at 30 requests/second across 5
threads. `whatweb` runs at aggression level 1. The active phase is louder by
design but still bounded, with a total time budget and a host cap. Every one of
these values is overridable from the environment, so a stricter program scope can
be enforced without editing Python — and `--polite` lowers all of them at once
for programs that are sensitive to automated traffic. Scope and rate are separate
concerns: the scope guard keeps you on authorised hosts, but staying within a
program's rules on automated scanning and request volume is still your call.

**Zero cost is the default path, not a fallback.** The deterministic offline
report produces a complete write-up from the scan artifacts with no model call
and no API key. AI synthesis is an upgrade you opt into, and a finished free scan
can be upgraded later from its saved output, without re-scanning the target.

**Nothing is scanned outside scope.** Recon discovers subdomains; a scope guard
decides which of them the engine may touch. It is enforced at one chokepoint —
right after live hosts are found, before any Stage 2+ traffic — so fingerprinting
and the entire active phase (katana/ffuf/naabu/nuclei) only ever reach in-scope
hosts. Without a scope file the guard defaults to the target apex and its
subdomains; `--scope`/`--out-of-scope` files let you match a program's exact
scope. Targets are validated too, so a malformed value can never be injected as a
flag into an external tool's arguments.

## Pipeline

| Module | Command | What it does | External tools |
|---|---|---|---|
| 1 | `recon` | Passive subdomain enumeration, live host validation, screenshots | subfinder, httpx |
| 2 | `fingerprint` | Port scanning, technology stack and TLS detection | nmap, whatweb |
| 2.5 | (part of `full`) | Active recon: crawling, directory fuzzing, hidden parameters, port sweep, template scanning | katana, ffuf, arjun, naabu, nuclei |
| 3 | `advise` | AI vulnerability analysis over the collected findings | Anthropic API |
| 4 | `jsoracle` | JavaScript analysis and token pre-filter | JS-Oracle |
| — | `report` | Report generation, offline or AI-synthesised | optional |

Findings never reach the model raw. A JS pre-filter scores every file
deterministically first and splits it into skip, cheap, and deep tiers, so vendor
libraries do not consume the analysis budget. Model output then passes through a
sanitiser before it is shown: suggested commands are rewritten to enforce the
rate caps, `sqlmap --os-shell` and `--dump-all` are stripped, `nuclei` gains
`-exclude-tags dos,destructive,fuzz`, and exploitation frameworks are blocked
outright. The engine never suggests a command it would not be willing to run
against a live scope.

## Requirements

- Python 3.10 or newer
- [subfinder](https://github.com/projectdiscovery/subfinder) and
  [httpx](https://github.com/projectdiscovery/httpx) — required for Module 1
- `nmap` and `whatweb` — required for Module 2
- [katana](https://github.com/projectdiscovery/katana),
  [ffuf](https://github.com/ffuf/ffuf),
  [arjun](https://github.com/s0md3v/Arjun),
  [naabu](https://github.com/projectdiscovery/naabu),
  [nuclei](https://github.com/projectdiscovery/nuclei) — optional, for the active phase
- [JS-Oracle](https://github.com/malek-sec/JS-Oracle) cloned as a sibling
  directory — optional, for Module 4
- An `ANTHROPIC_API_KEY` — optional, only for AI analysis and AI reports

`httpx` here means ProjectDiscovery's HTTP probe, not the Python library of the
same name. The engine validates the binary it finds and fails loudly rather than
running the wrong one.

## Install

```bash
git clone https://github.com/malek-sec/scan-engine.git
git clone https://github.com/malek-sec/JS-Oracle.git js-oracle   # sibling, optional

cd scan-engine
python3 -m venv .venv
source .venv/bin/activate
```

Module 4 resolves the JS-Oracle install by looking for a `js-oracle` directory
next to this checkout, or at `$JS_ORACLE_ROOT` if you set it. No path is
hardcoded to a particular machine.

## Usage

```bash
# Full deep scan, free — every stage, deterministic report, no API cost
python3 cli/main.py full --target example.com --offline

# Full deep scan with the Claude advisor
python3 cli/main.py full --target example.com

# Passive only — skips the active recon and fuzzing phase
python3 cli/main.py full --target example.com --fast

# Individual modules
python3 cli/main.py recon       --target example.com
python3 cli/main.py fingerprint --target example.com --hosts-file live_hosts.txt
python3 cli/main.py advise      --target example.com --fingerprint-file fingerprint.json
python3 cli/main.py jsoracle    --target example.com --offline
python3 cli/main.py report      --target example.com
```

`--fast` is worth understanding. The deep scan is the default because on a
single-page application the active crawl is what finds the JavaScript at all —
passive recon alone will report nothing to analyse. Reach for `--fast` when you
want a quiet first look, not as the normal mode.

### Options

| Command | Flag | Effect |
|---|---|---|
| `full` | `--target`, `-t` | Target domain (required) |
| `full` | `--offline` | Free mode: deterministic JS pass and offline report, no model call |
| `full` | `--fast` | Passive only, skip the active recon phase |
| `full`, `recon`, `fingerprint` | `--scope FILE` | In-scope host patterns (`example.com`, `*.example.com`, `app.example.com`, `!excluded`). Defaults to the target + subdomains |
| `full`, `recon`, `fingerprint` | `--out-of-scope FILE` | Host patterns always excluded, even if in-scope |
| `full`, `recon`, `fingerprint` | `--respect-robots` | Drop robots.txt-disallowed JS/endpoint URLs (off by default) |
| `full`, `recon`, `fingerprint` | `--polite` | Lower request rates across every tool for strict programs. Only lowers; an explicit `BOUNTYHUB_*` env var still wins |
| `recon` | `--target`, `-t` | Target domain (required) |
| `fingerprint` | `--hosts-file` | Read `live_hosts.txt` instead of re-running Module 1 |
| `advise` | `--fingerprint-file`, `-f` | Read `fingerprint.json` instead of re-running Modules 1 and 2 |
| `jsoracle` | `--js-file` | `js_files.json` or a newline-separated list of JS URLs |
| `jsoracle` | `--offline` | Free mode: deterministic regex pass only |

## Output

Each run writes to `bountyhub_output/<target>_<timestamp>/`:

```
subdomains.txt       Enumerated subdomains
live_hosts.txt       Hosts that answered, one URL per line
fingerprint.json     Ports, technologies, TLS details
js_files.json        Discovered JavaScript, with pre-filter tiers
ai_advice.txt        AI analysis, when the advisor ran
offline_report.md    Deterministic report, always available
summary.json         Machine-readable rollup of the whole run (counts, scope, JS)
```

Reports are evidence-first. Confirmed findings and unverified leads are kept
apart, CVSS scores are not attached to guesses, and out-of-scope noise is
suppressed rather than padded into the output.

## Configuration

Every tunable is an environment variable, so a systemd unit, container, or `.env`
can override it without touching the source.

**AI**

| Variable | Default | Effect |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | Required for `advise` and AI reports |
| `ANTHROPIC_MODEL` | profile-dependent | Model for advisor and pre-filter |
| `BOUNTYHUB_ADVISOR_MODEL` | Opus | Report model, pinned independently of the cost profile |
| `BOUNTYHUB_ADVISOR_MAX_TOKENS` | engine default | Output cap for the advisor |

**Rate limits and budgets**

| Variable | Default | Effect |
|---|---|---|
| `BOUNTYHUB_ACTIVE_RECON_ENABLED` | `true` | Global kill switch for the active phase |
| `BOUNTYHUB_ACTIVE_MAX_HOSTS` | `5` | Hosts the active phase will touch |
| `BOUNTYHUB_ACTIVE_TOTAL_BUDGET` | `900` | Total active-phase seconds |
| `BOUNTYHUB_ACTIVE_KATANA_DEPTH` | `3` | Crawl depth |
| `BOUNTYHUB_ACTIVE_KATANA_SCOPE` | `rdn` | Crawl scope; `rdn` follows apex-to-www redirects |
| `BOUNTYHUB_ACTIVE_FFUF_RATE` | `60` | Fuzzing requests per second |
| `BOUNTYHUB_ACTIVE_NUCLEI_RL` | `100` | Nuclei rate limit |
| `BOUNTYHUB_ACTIVE_NUCLEI_SEVERITY` | `low,medium,high,critical` | Severities scanned |
| `BOUNTYHUB_ACTIVE_NUCLEI_EXCLUDE_TAGS` | `dos,fuzz,intrusive,brute-force` | Templates never run |
| `BOUNTYHUB_ACTIVE_DIR_WORDLIST` | SecLists autodetect | Directory fuzzing wordlist |

The full set follows the `BOUNTYHUB_ACTIVE_*` prefix; see `core/__init__.py` for
every value and its default.

**Paths and backends**

| Variable | Default | Effect |
|---|---|---|
| `BOUNTYHUB_HTTPX_BINARY` | autodetect | Absolute path to ProjectDiscovery httpx |
| `JS_ORACLE_ROOT` | sibling `js-oracle/` | JS-Oracle install location |
| `JS_ORACLE_MODE` | `subprocess` | `subprocess` or `http` |
| `JS_ORACLE_URL` | `http://127.0.0.1:8787` | JS-Oracle service endpoint in `http` mode |

Set `BOUNTYHUB_HTTPX_BINARY` when the engine runs as a service or in a container,
where `$PATH` is not your interactive shell's.

## Tools

```bash
# Upgrade a finished free scan to a full AI report — one call, no re-scan
python3 tools/advise_from_dir.py <scan_output_dir>

# Rebuild the deterministic report from saved artifacts, no API cost
python3 tools/offline_report.py <scan_output_dir>

# Tune the JS pre-filter threshold on real files before spending any tokens
python3 tools/prefilter_tune.py <path_or_url_list>

# Point all three repos at one cost profile and key (cheap | balanced | strong)
source tools/setup-ai.sh balanced sk-ant-...
```

`setup-ai.sh` must be sourced, not executed, so the variables enter your shell.

## Layout

```
cli/main.py            Argument parsing, orchestration, all terminal rendering
core/__init__.py       Config, rate limits, dependency checking, logging
core/recon.py          Module 1
core/fingerprint.py    Module 2
core/active_recon.py   Module 2.5
core/ai_advisor.py     Module 3 and the command sanitiser
core/js_oracle.py      Module 4 bridge
core/js_prefilter.py   Deterministic JS scorer
core/offline_report.py Zero-cost report generator
tools/                 Standalone helper scripts
tests/                 Unit tests
```

The `core/` modules are pure data libraries — they return structured result
envelopes and never print. `cli/main.py` is the only module that renders.

## Tests

```bash
python3 -m pytest tests/
```

## Security notes

- No subprocess in this repo uses a shell. Every external tool is invoked with an
  argument list, so a target string can never be interpreted as a command.
- Model-suggested commands pass through `CommandSanitizer` before display:
  destructive flags are stripped, rate caps are enforced, and exploitation
  frameworks are blocked.
- Secret values discovered in JavaScript are masked in reports, never printed in
  full.
- Analysed JavaScript is treated as untrusted input and delimited before it
  reaches the model, so code that embeds instructions cannot steer the analysis.

## License

MIT - see [LICENSE](LICENSE).
