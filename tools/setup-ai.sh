#!/usr/bin/env bash
# setup-ai.sh — point ALL THREE BountyHub tools at one Claude model + API key.
#
# Usage (recommended — SOURCE it, so the vars also enter your current shell):
#     source /home/kali/scan-engine/tools/setup-ai.sh  sk-ant-YOURKEY
#   or, if ANTHROPIC_API_KEY is already exported:
#     source /home/kali/scan-engine/tools/setup-ai.sh
#
# What it does:
#   * upserts the AI settings into the .env of js-oracle, scan-engine and
#     bountyhub (other keys in those files are preserved), and
#   * exports the same vars into the current shell.
#
# The API key is READ from $1 or $ANTHROPIC_API_KEY — it is NEVER written into
# this script, and every .env it touches is git-ignored and chmod 600.
#
# Requires the model-aware builds: js-oracle analyzer, scan-engine ai_advisor,
# and js_prefilter all honour ANTHROPIC_MODEL (pull the latest before running).

# ── change these if you want a different model / effort / layout ─────────────
MODEL="claude-haiku-4-5"       # cheap. dated-id fallback: claude-haiku-4-5-20251001
EFFORT="low"                   # low = cheapest thinking budget (js-oracle)
ROOT="/home/kali"              # dir holding js-oracle / scan-engine / bountyhub

KEY="${1:-${ANTHROPIC_API_KEY:-}}"
if [ -z "$KEY" ]; then
  echo "No API key given. Usage:  source $ROOT/scan-engine/tools/setup-ai.sh sk-ant-..." >&2
  return 2 2>/dev/null || exit 2
fi

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
  _set_env "$f" ANTHROPIC_MODEL   "$MODEL"
  _set_env "$f" ANTHROPIC_EFFORT  "$EFFORT"
  # The token pre-filter's per-tier models live in the engine / web only.
  if [ "$tool" != "js-oracle" ]; then
    _set_env "$f" BOUNTYHUB_PREFILTER_DEEP_MODEL  "$MODEL"
    _set_env "$f" BOUNTYHUB_PREFILTER_CHEAP_MODEL "$MODEL"
  fi
  chmod 600 "$f"
  echo "wrote  $f"
done

# Export into THIS shell too — bulletproof for the scan-engine CLI regardless of
# .env load order.
export AI_PROVIDER="anthropic"
export ANTHROPIC_API_KEY="$KEY"
export ANTHROPIC_MODEL="$MODEL"
export ANTHROPIC_EFFORT="$EFFORT"
export BOUNTYHUB_PREFILTER_DEEP_MODEL="$MODEL"
export BOUNTYHUB_PREFILTER_CHEAP_MODEL="$MODEL"

echo ""
echo "All three tools set to  model=$MODEL  effort=$EFFORT"
echo "key=${KEY:0:8}*** (masked)  |  .env files updated (chmod 600) + exported to this shell."
echo "Verify:  cd $ROOT/scan-engine && python cli/main.py full --target <authorized-target>"
echo "         (the JS-ORACLE + advisor log lines should name $MODEL)"
