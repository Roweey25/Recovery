#!/usr/bin/env bash
# claude-config-repair.sh -- undo a stale custom-API configuration for Claude Code.
#
# Reverts Claude Code to plain subscription auth against api.anthropic.com by
# neutralising API overrides wherever they live: shell rc files, settings.json,
# and the remembered key in ~/.claude.json. Also tests whether the endpoint is
# reachable at all, since a dead gateway and a blocked network look identical
# from the outside.
#
# DRY RUN BY DEFAULT -- prints what it would change and touches nothing.
#   bash tools/claude-config-repair.sh            # show planned changes
#   bash tools/claude-config-repair.sh --apply     # make them, after backing up
#
# Everything modified is copied to ~/.claude-config-backup-<timestamp>/ first,
# and the script prints the exact command to roll back.

set -uo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$HOME/.claude-config-backup-$STAMP"
CHANGES=0

hdr()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
plan() { printf '   \033[33m[would change]\033[0m %s\n' "$*"; CHANGES=$((CHANGES+1)); }
did()  { printf '   \033[32m[changed]\033[0m %s\n' "$*"; CHANGES=$((CHANGES+1)); }

backup_file() {
  [ $APPLY -eq 1 ] || return 0
  mkdir -p "$BACKUP"
  # Flatten the full path into the name, with a leading tag so dotfiles like
  # .bashrc don't land as hidden files inside the backup directory.
  cp -p "$1" "$BACKUP/bak$(printf '%s' "$1" | tr '/' '_')" 2>/dev/null
}

# Env vars whose presence redirects Claude Code away from normal subscription auth.
OVERRIDE_RE='ANTHROPIC_(API_KEY|AUTH_TOKEN|BASE_URL|API_URL|CUSTOM_HEADERS|MODEL|SMALL_FAST_MODEL)|CLAUDE_CODE_USE_(BEDROCK|VERTEX)|CLAUDE_CODE_SKIP_(BEDROCK|VERTEX)_AUTH'

if [ $APPLY -eq 0 ]; then
  printf '\033[1mDRY RUN\033[0m -- nothing will be modified. Re-run with --apply to act.\n'
else
  printf '\033[1mAPPLYING\033[0m -- backups go to %s\n' "$BACKUP"
fi

# ---------------------------------------------------------------------------
hdr "0. Is the endpoint even reachable?"
# An unauthenticated POST should come back 401 fast. A hang means the network or
# a proxy is eating the request; a 000 means DNS/TLS/connection failure.
probe() {
  local url="$1" code
  code="$(curl -sS -m 12 -o /dev/null -w '%{http_code}' \
          -X POST "$url/v1/messages" -H 'content-type: application/json' \
          -d '{}' 2>/dev/null)"
  printf '   %-42s -> HTTP %s\n' "$url" "${code:-000}"
  [ "$code" = "401" ] || [ "$code" = "400" ] || [ "$code" = "403" ]
}
if command -v curl >/dev/null; then
  if probe "https://api.anthropic.com"; then
    note "api.anthropic.com is reachable (401/400 = server answered, auth just absent)."
  else
    note "api.anthropic.com did NOT answer normally."
    note "That points at network/proxy/DNS/VPN rather than Claude Code config."
    note "Check: VPN on? corporate proxy? \$HTTPS_PROXY set? firewall/DNS filtering?"
  fi
  if [ -n "${ANTHROPIC_BASE_URL:-}" ] && [ "${ANTHROPIC_BASE_URL}" != "https://api.anthropic.com" ]; then
    note ""
    note "You have a custom base URL configured. Probing it too:"
    probe "${ANTHROPIC_BASE_URL%/}" \
      || note "^ your custom endpoint is not answering. This is very likely the whole problem."
  fi
else
  note "(curl not installed; skipping reachability probe)"
fi

# ---------------------------------------------------------------------------
hdr "1. Shell startup files"
for f in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" \
         "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile"; do
  [ -f "$f" ] || continue
  hits="$(grep -cE "^[[:space:]]*(export[[:space:]]+)?($OVERRIDE_RE)=" "$f" 2>/dev/null)"
  [ "${hits:-0}" -gt 0 ] || continue
  if [ $APPLY -eq 1 ]; then
    backup_file "$f"
    # Comment the line out rather than deleting it, so the old value stays
    # recoverable. Delimiter must NOT be '|' -- $OVERRIDE_RE is full of them.
    if sed -i -E "s@^([[:space:]]*(export[[:space:]]+)?($OVERRIDE_RE)=)@# disabled by claude-config-repair $STAMP: \1@" "$f" \
       && ! grep -qE "^[[:space:]]*(export[[:space:]]+)?($OVERRIDE_RE)=" "$f"; then
      did "$f -- commented out $hits override line(s)"
    else
      printf '   \033[31m[FAILED]\033[0m %s -- could not edit; fix by hand\n' "$f"
    fi
  else
    plan "$f -- would comment out $hits override line(s):"
    grep -nE "^[[:space:]]*(export[[:space:]]+)?($OVERRIDE_RE)=" "$f" \
      | sed -E 's/((API_KEY|AUTH_TOKEN|CUSTOM_HEADERS)=).*/\1<REDACTED>/' \
      | sed 's/^/        /'
  fi
done
[ $CHANGES -eq 0 ] && note "no override lines found in shell startup files"

# ---------------------------------------------------------------------------
hdr "2. settings.json env block / apiKeyHelper"
for f in "$HOME/.claude/settings.json" "$HOME/.claude/settings.local.json" \
         "$PWD/.claude/settings.json" "$PWD/.claude/settings.local.json"; do
  [ -f "$f" ] || continue
  command -v python3 >/dev/null || { note "python3 missing; edit $f by hand"; continue; }
  [ $APPLY -eq 1 ] && backup_file "$f"
  APPLY=$APPLY python3 - "$f" <<'PY'
import json, os, re, sys
path = sys.argv[1]
apply_ = os.environ.get("APPLY") == "1"
pat = re.compile(r'^(ANTHROPIC_(API_KEY|AUTH_TOKEN|BASE_URL|API_URL|CUSTOM_HEADERS|MODEL|SMALL_FAST_MODEL)|CLAUDE_CODE_USE_(BEDROCK|VERTEX))$')
try:
    d = json.load(open(path))
except Exception as e:
    print(f"   (skipping {path}: unparseable -- {e})"); raise SystemExit
removed = []
env = d.get("env")
if isinstance(env, dict):
    for k in [k for k in env if pat.match(k)]:
        removed.append(f"env.{k}")
        if apply_: env.pop(k)
    if apply_ and not env: d.pop("env", None)
for k in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport"):
    if k in d:
        removed.append(k)
        if apply_: d.pop(k)
if not removed:
    print(f"   {path} -- no API overrides"); raise SystemExit
if apply_:
    json.dump(d, open(path, "w"), indent=2)
    open(path, "a").write("\n")
    print(f"   \033[32m[changed]\033[0m {path} -- removed: {', '.join(removed)}")
else:
    print(f"   \033[33m[would change]\033[0m {path} -- would remove: {', '.join(removed)}")
PY
done

# ---------------------------------------------------------------------------
hdr "3. Remembered API key in ~/.claude.json"
CJ="$HOME/.claude.json"
if [ -f "$CJ" ] && command -v python3 >/dev/null; then
  [ $APPLY -eq 1 ] && backup_file "$CJ"
  APPLY=$APPLY python3 - "$CJ" <<'PY'
import json, os, sys
path = sys.argv[1]
apply_ = os.environ.get("APPLY") == "1"
try:
    d = json.load(open(path))
except Exception as e:
    print(f"   (skipping: unparseable -- {e})"); raise SystemExit
hits = [k for k in ("primaryApiKey", "customApiKeyResponses") if d.get(k)]
if not hits:
    print("   no remembered API key -- nothing to clear"); raise SystemExit
if apply_:
    for k in hits: d.pop(k, None)
    json.dump(d, open(path, "w"), indent=2)
    print(f"   \033[32m[changed]\033[0m cleared: {', '.join(hits)}")
else:
    print(f"   \033[33m[would change]\033[0m would clear: {', '.join(hits)}  (values never printed)")
PY
else
  note "(no ~/.claude.json, or python3 unavailable)"
fi

# ---------------------------------------------------------------------------
hdr "Next steps"
if [ $APPLY -eq 0 ]; then
  cat <<'EOF'
   This was a dry run. To apply:
       bash tools/claude-config-repair.sh --apply

   Then, in a BRAND NEW terminal (so the old exports are gone):
       claude
       /login       # re-attach your subscription
       /status      # confirm endpoint + auth method
EOF
else
  cat <<EOF
   Backups: $BACKUP
   Roll back with:  cp $BACKUP/<file> <original-path>

   Now open a BRAND NEW terminal so the stale exports are out of your shell:
       claude
       /login       # re-attach your subscription
       /status      # confirm endpoint + auth method

   Still stuck? Run with debug output to see the real error instead of a hang:
       claude --debug
EOF
fi
