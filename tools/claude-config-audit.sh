#!/usr/bin/env bash
# claude-config-audit.sh -- find where Claude Code is being pointed at a custom API.
#
# Read-only. Prints every place Claude Code can pick up an API override, in the
# order Claude Code itself resolves them. Secrets are redacted, so the output is
# safe to paste into a chat.
#
# Usage:  bash tools/claude-config-audit.sh
#         bash tools/claude-config-audit.sh /path/to/other/project

set -uo pipefail

PROJECT_DIR="${1:-$PWD}"

# Env vars that change WHICH endpoint / provider / credentials Claude Code uses.
API_VARS=(
  ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL ANTHROPIC_API_URL
  ANTHROPIC_CUSTOM_HEADERS ANTHROPIC_MODEL ANTHROPIC_SMALL_FAST_MODEL
  ANTHROPIC_DEFAULT_OPUS_MODEL ANTHROPIC_DEFAULT_SONNET_MODEL ANTHROPIC_DEFAULT_HAIKU_MODEL
  CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX CLAUDE_CODE_SKIP_BEDROCK_AUTH
  CLAUDE_CODE_SKIP_VERTEX_AUTH ANTHROPIC_BEDROCK_BASE_URL ANTHROPIC_VERTEX_BASE_URL
  ANTHROPIC_VERTEX_PROJECT_ID CLOUD_ML_REGION AWS_BEARER_TOKEN_BEDROCK AWS_PROFILE AWS_REGION
  HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy
  NODE_EXTRA_CA_CERTS CLAUDE_CODE_API_KEY_HELPER_TTL_MS
)
# Substrings that mean "this value is a credential" -> show shape only, never the value.
SECRETISH='(API_KEY|AUTH_TOKEN|BEARER|CUSTOM_HEADERS)'

hdr() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }

# Print "NAME=<value>", redacting anything credential-shaped.
show_kv() {
  local name="$1" val="$2"
  if [[ "$name" =~ $SECRETISH ]]; then
    printf '   %-34s = <set, %d chars, starts %s…>\n' "$name" "${#val}" "${val:0:8}"
  else
    printf '   %-34s = %s\n' "$name" "$val"
  fi
}

# Grep a file for any of the interesting names and echo matching lines, redacted.
scan_file() {
  local f="$1" found=0 line
  [ -r "$f" ] || return 0
  while IFS= read -r line; do
    found=1
    # Redact only the value bound to a credential-named key, leaving the rest
    # of the line (including which key it was) readable. Handles JSON
    # ("KEY": "val"), shell (export KEY=val / KEY='val') and bare assignments.
    line="$(printf '%s' "$line" | sed -E \
      's/((API_KEY|AUTH_TOKEN|BEARER_TOKEN[A-Z_]*|CUSTOM_HEADERS)"?[[:space:]]*[:=][[:space:]]*)("[^"]*"|'"'"'[^'"'"']*'"'"'|[^,[:space:]}]+)/\1<redacted>/g')"
    printf '   %s: %s\n' "$f" "$(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
  done < <(grep -nE 'ANTHROPIC_|CLAUDE_CODE_USE_|apiKeyHelper|awsAuthRefresh|awsCredentialExport|CLAUDE_CODE_SKIP_|AWS_BEARER_TOKEN_BEDROCK|CLOUD_ML_REGION' "$f" 2>/dev/null)
  # 0 = something was printed, 1 = nothing matched (so callers can use `|| note ...`)
  [ "$found" -eq 1 ]
}

echo "Claude Code API-config audit"
echo "project: $PROJECT_DIR"
echo "host:    $(uname -s) $(uname -r)"
command -v claude >/dev/null && echo "claude:  $(command -v claude) ($(claude --version 2>/dev/null | head -1))"

# ---------------------------------------------------------------------------
hdr "1. Live environment (highest practical precedence)"
any=0
for v in "${API_VARS[@]}"; do
  if [ -n "${!v:-}" ]; then show_kv "$v" "${!v}"; any=1; fi
done
[ $any -eq 0 ] && note "(none set in this shell)"
note ""
note "If ANTHROPIC_BASE_URL or ANTHROPIC_API_KEY/AUTH_TOKEN appear above, that is"
note "almost certainly your culprit: they force API billing / a custom endpoint."

# ---------------------------------------------------------------------------
hdr "2. Settings files, in Claude Code's precedence order"
case "$(uname -s)" in
  Darwin) MANAGED="/Library/Application Support/ClaudeCode/managed-settings.json" ;;
  *)      MANAGED="/etc/claude-code/managed-settings.json" ;;
esac
SETTINGS_FILES=(
  "$MANAGED"                                   # enterprise policy -- overrides everything
  "$PROJECT_DIR/.claude/settings.local.json"   # project, personal
  "$PROJECT_DIR/.claude/settings.json"         # project, shared/committed
  "$HOME/.claude/settings.json"                # user global
)
for f in "${SETTINGS_FILES[@]}"; do
  if [ -f "$f" ]; then
    echo "   [found] $f"
    scan_file "$f" || note "         (no API-related keys)"
  else
    echo "   [none ] $f"
  fi
done
note ""
note "Look for an \"env\": { ... } block or an \"apiKeyHelper\" entry. Claude Code"
note "injects the env block into every session, so it survives shell restarts."

# ---------------------------------------------------------------------------
hdr "3. ~/.claude.json (account + per-project state)"
CJ="$HOME/.claude.json"
if [ -f "$CJ" ]; then
  echo "   [found] $CJ"
  if command -v python3 >/dev/null; then
    python3 - "$CJ" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"   (could not parse: {e})"); raise SystemExit
for k in ("primaryApiKey", "customApiKeyResponses", "oauthAccount", "hasCompletedOnboarding"):
    if k in d:
        v = d[k]
        if k == "primaryApiKey" and v:
            v = f"<set, {len(str(v))} chars>"
        if k == "oauthAccount" and isinstance(v, dict):
            v = {kk: v.get(kk) for kk in ("emailAddress", "organizationName")}
        print(f"   {k} = {v}")
PY
  else
    scan_file "$CJ" || note "   (python3 unavailable; grepped only)"
  fi
  note ""
  note "A non-empty primaryApiKey / customApiKeyResponses means you pasted an API"
  note "key into Claude Code at some point and it was remembered."
else
  echo "   [none ] $CJ"
fi

# ---------------------------------------------------------------------------
hdr "4. Shell startup files (the usual 'I set it once and forgot' spot)"
RC_FILES=(
  "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.zshrc"
  "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"
  "$HOME/.config/fish/config.fish"
  "/etc/environment" "/etc/profile"
)
for f in "${RC_FILES[@]}"; do scan_file "$f"; done
for d in "$HOME/.config/fish/conf.d" /etc/profile.d "$HOME/.zshrc.d" "$HOME/.bashrc.d"; do
  [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && scan_file "$f"; done
done
# direnv / mise / asdf style per-directory env
for f in "$PROJECT_DIR/.envrc" "$PROJECT_DIR/.env" "$PROJECT_DIR/mise.toml" "$PROJECT_DIR/.mise.toml"; do
  scan_file "$f"
done
note "(only matching lines are printed; silence here means nothing found)"

# ---------------------------------------------------------------------------
hdr "5. Shell wrappers around the 'claude' command"
if alias claude >/dev/null 2>&1; then alias claude; else note "no 'claude' alias in this shell"; fi
if declare -f claude >/dev/null 2>&1; then declare -f claude; fi
grep -rnE '^[[:space:]]*(alias|function)[[:space:]]+claude\b' "${RC_FILES[@]}" 2>/dev/null \
  || note "no claude alias/function defined in shell rc files"

# ---------------------------------------------------------------------------
hdr "6. macOS launchd / GUI-app environment"
if [ "$(uname -s)" = "Darwin" ]; then
  for v in ANTHROPIC_BASE_URL ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN; do
    out="$(launchctl getenv "$v" 2>/dev/null)"
    [ -n "$out" ] && show_kv "launchctl:$v" "$out"
  done
  note "launchd vars leak into GUI-launched apps (VS Code, iTerm from Dock)."
  ls "$HOME/Library/LaunchAgents" 2>/dev/null | grep -i -E 'anthropic|claude' \
    && note "^ launch agent(s) referencing claude/anthropic" || true
else
  note "(skipped: not macOS)"
fi

# ---------------------------------------------------------------------------
hdr "7. Editor terminal env (VS Code injects these into its integrated terminal)"
for f in "$HOME/Library/Application Support/Code/User/settings.json" \
         "$HOME/.config/Code/User/settings.json" \
         "$PROJECT_DIR/.vscode/settings.json"; do
  scan_file "$f"
done
note "(look for terminal.integrated.env.* entries)"

# ---------------------------------------------------------------------------
hdr "Next steps"
cat <<'EOF'
   Inside Claude Code, run  /status  -- it names the auth method and endpoint
   actually in use, which confirms whichever source above is winning.

   To clear an override for one session:
     unset ANTHROPIC_BASE_URL ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
     claude          # then run /login to re-attach your subscription

   To clear it permanently, delete the line from whichever file section 1-7
   flagged, then restart your terminal.
EOF
