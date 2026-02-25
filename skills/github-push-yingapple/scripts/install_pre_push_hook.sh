#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[install-pre-push-hook] %s\n' "$1"
}

fail() {
  printf '[install-pre-push-hook] ERROR: %s\n' "$1" >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[[ -n "$repo_root" ]] || fail "Run this script inside the target git repository."

guard_script="$repo_root/skills/github-push-yingapple/scripts/pre_push_guard.sh"
hook_path="$repo_root/.git/hooks/pre-push"
timestamp="$(date +%Y%m%d%H%M%S)"

[[ -f "$guard_script" ]] || fail "Guard script not found: $guard_script"
chmod +x "$guard_script"

if [[ -f "$hook_path" ]] && ! grep -q "github-push-yingapple/scripts/pre_push_guard.sh" "$hook_path"; then
  backup_path="${hook_path}.backup.${timestamp}"
  cp "$hook_path" "$backup_path"
  log "Backed up existing pre-push hook to $backup_path"
fi

cat >"$hook_path" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
"$repo_root/skills/github-push-yingapple/scripts/pre_push_guard.sh" "$@"
EOF

chmod +x "$hook_path"
log "Installed pre-push hook: $hook_path"
