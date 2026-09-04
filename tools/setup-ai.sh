#!/usr/bin/env bash
# setup-ai.sh — point ALL THREE BountyHub tools at one AI profile + API key.
#
# Usage (SOURCE it so the vars also enter your current shell):
#     source /home/kali/scan-engine/tools/setup-ai.sh [profile] [sk-ant-KEY]
#
#   profile = cheap | balanced | strong   (default: cheap)
#     cheap     Haiku for everything, effort=low       — lowest cost
#     balanced  Opus for advisor + deep(signal) files, Haiku for cheap-tier, effort=medium
#     strong    Opus for everything, effort=high        — best reasoning, highest cost
#
#   The API key is optional after the first run: it is reused from the existing
#   .env if you don't pass one (so `source setup-ai.sh balanced` just switches
#   models). Order of args doesn't matter; the key is whatever starts with sk-.
#
# The key is READ from the arg / $ANTHROPIC_API_KEY / existing .env — never
# written into this script. Every .env it touches is git-ignored and chmod 600.
# Requires the model-aware builds (js-oracle analyzer, scan-engine ai_advisor +
# js_prefilter all honour ANTHROPIC_MODEL).

ROOT="${SETUP_AI_ROOT:-/home/kali}"     # dir holding js-oracle / scan-engine / bountyhub

# ── parse args (profile and/or key, any order) ──────────────────────────────
PROFILE=""; KEY=""
for a in "$@"; do
  case "$a" in
    cheap|balanced|strong) PROFILE="$a" ;;
    sk-*)                  KEY="$a" ;;
    *) echo "warn: ignoring unrecognized argument '$a' (want cheap|balanced|strong and/or sk-...)" >&2 ;;
  esac
done
PROFILE="${PROFILE:-cheap}"

# ── key: arg -> environment -> reuse the one already saved in a .env ─────────
[ -z "$KEY" ] && KEY="${ANTHROPIC_API_KEY:-}"
if [ -z "$KEY" ]; then
  for d in scan-engine js-oracle bountyhub; do
    if [ -f "$ROOT/$d/.env" ]; then
      KEY="$(grep -E '^ANTHROPIC_API_KEY=' "$ROOT/$d/.env" | head -1 | cut -d= -f2-)"
      [ -n "$KEY" ] && break
    fi
  done
fi
if [ -z "$KEY" ]; then
  echo "No API key found (arg, \$ANTHROPIC_API_KEY, or existing .env)." >&2
  echo "First run:  source $ROOT/scan-engine/tools/setup-ai.sh $PROFILE sk-ant-..." >&2
  return 2 2>/dev/null || exit 2
fi

# ── profile -> models + effort ──────────────────────────────────────────────
#   ADV   = ANTHROPIC_MODEL  (advisor + js-oracle default)
#   DEEP  = pre-filter model for signal-rich files
#   CHEAP = pre-filter model for low-signal files
case "$PROFILE" in
  cheap)    ADV="claude-haiku-4-5"; DEEP="claude-haiku-4-5"; CHEAP="claude-haiku-4-5"; EFFORT="low" ;;
  balanced) ADV="claude-opus-4-8";  DEEP="claude-opus-4-8";  CHEAP="claude-haiku-4-5"; EFFORT="medium" ;;
  strong)   ADV="claude-opus-4-8";  DEEP="claude-opus-4-8";  CHEAP="claude-opus-4-8";  EFFORT="high" ;;
esac

_set_env() {   # <file> <KEY> <VALUE> — replace the line for KEY, or append it
  local f="$1" k="$2" v="$3"
  touch "$f"
  grep -v -E "^${k}=" "$f" 2>/dev/null > "${f}.tmp" || true
  mv "${f}.tmp" "$f"
  printf '%s=%s\n' "$k" "$v" >> "$f"
}

for tool in js-oracle scan-engine bountyhub; do
  d="$ROOT/$tool"
  if [ ! -d "$d" ]; then echo "skip: $d not found"; continue; fi
  f="$d/.env"
  _set_env "$f" AI_PROVIDER      "anthropic"
  _set_env "$f" ANTHROPIC_API_KEY "$KEY"
  _set_env "$f" ANTHROPIC_MODEL   "$ADV"
  _set_env "$f" ANTHROPIC_EFFORT  "$EFFORT"
  if [ "$tool" != "js-oracle" ]; then     # pre-filter tiers live in engine/web only
    _set_env "$f" BOUNTYHUB_PREFILTER_DEEP_MODEL  "$DEEP"
    _set_env "$f" BOUNTYHUB_PREFILTER_CHEAP_MODEL "$CHEAP"
  fi
  chmod 600 "$f"
  echo "wrote  $f"
done

# Export into THIS shell too — bulletproof for the scan-engine CLI.
export AI_PROVIDER="anthropic"
export ANTHROPIC_API_KEY="$KEY"
export ANTHROPIC_MODEL="$ADV"
export ANTHROPIC_EFFORT="$EFFORT"
export BOUNTYHUB_PREFILTER_DEEP_MODEL="$DEEP"
export BOUNTYHUB_PREFILTER_CHEAP_MODEL="$CHEAP"

echo ""
echo "profile = $PROFILE"
echo "  advisor + js-oracle default : $ADV   (effort=$EFFORT)"
echo "  pre-filter deep / cheap     : $DEEP / $CHEAP"
echo "  key=${KEY:0:8}*** (masked)  |  .env updated (chmod 600) + exported to this shell."
echo "Switch anytime:  source $ROOT/scan-engine/tools/setup-ai.sh {cheap|balanced|strong}"
echo "Web change? restart bountyhub:  cd $ROOT/bountyhub && venv/bin/python app.py"
