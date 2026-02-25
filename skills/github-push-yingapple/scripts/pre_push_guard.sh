#!/usr/bin/env bash
set -euo pipefail

EXPECTED_GIT_USER_NAME="${EXPECTED_GIT_USER_NAME:-yingapple}"
EXPECTED_GIT_USER_EMAIL="${EXPECTED_GIT_USER_EMAIL:-yingxiang835@gmail.com}"
EXPECTED_GITHUB_HOST_ALIAS="${EXPECTED_GITHUB_HOST_ALIAS:-github.com-yingapple}"
DISALLOWED_GITHUB_HOST_ALIAS="${DISALLOWED_GITHUB_HOST_ALIAS:-github.com-mind-ying}"

log() {
  printf '[pre-push-guard] %s\n' "$1"
}

fail() {
  printf '[pre-push-guard] ERROR: %s\n' "$1" >&2
  exit 1
}

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"
}

suggest_remote_url() {
  local url="$1"
  if [[ "$url" =~ ^git@[^:]+:(.+)$ ]]; then
    printf 'git@%s:%s' "$EXPECTED_GITHUB_HOST_ALIAS" "${BASH_REMATCH[1]}"
    return
  fi

  if [[ "$url" =~ ^ssh://git@[^/]+/(.+)$ ]]; then
    printf 'git@%s:%s' "$EXPECTED_GITHUB_HOST_ALIAS" "${BASH_REMATCH[1]}"
    return
  fi

  if [[ "$url" =~ ^https://github.com/(.+)$ ]]; then
    printf 'git@%s:%s' "$EXPECTED_GITHUB_HOST_ALIAS" "${BASH_REMATCH[1]}"
    return
  fi

  printf ''
}

verify_remote_identity() {
  local remote_name="$1"
  local remote_url="$2"
  local suggested

  [[ -n "$remote_url" ]] || fail "Cannot resolve push URL for remote '$remote_name'."

  if [[ "$remote_url" == *"$DISALLOWED_GITHUB_HOST_ALIAS"* ]]; then
    fail "Push URL points to disallowed host alias '$DISALLOWED_GITHUB_HOST_ALIAS': $remote_url"
  fi

  if [[ ! "$remote_url" =~ ^git@${EXPECTED_GITHUB_HOST_ALIAS}:.+$ ]]; then
    suggested="$(suggest_remote_url "$remote_url")"
    if [[ -n "$suggested" ]]; then
      fail "Push URL must use host alias '$EXPECTED_GITHUB_HOST_ALIAS'. Run: git remote set-url $remote_name $suggested"
    fi
    fail "Push URL format is unsupported for automatic suggestion: $remote_url"
  fi

  log "Remote identity check passed ($remote_url)."
}

verify_git_author() {
  local current_name
  local current_email

  current_name="$(git config --local --get user.name || true)"
  current_email="$(git config --local --get user.email || true)"

  [[ "$current_name" == "$EXPECTED_GIT_USER_NAME" ]] || fail "git user.name must be '$EXPECTED_GIT_USER_NAME'. Current: '${current_name:-<empty>}'"
  [[ "$current_email" == "$EXPECTED_GIT_USER_EMAIL" ]] || fail "git user.email must be '$EXPECTED_GIT_USER_EMAIL'. Current: '${current_email:-<empty>}'"

  log "Local git author check passed ($current_name <$current_email>)."
}

verify_ssh_alias() {
  local ssh_config
  local ssh_output

  ssh_config="${HOME}/.ssh/config"
  [[ -f "$ssh_config" ]] || fail "Missing SSH config: $ssh_config"

  if ! grep -Eq "^[[:space:]]*Host[[:space:]]+${EXPECTED_GITHUB_HOST_ALIAS}([[:space:]]|\$)" "$ssh_config"; then
    fail "SSH host alias '$EXPECTED_GITHUB_HOST_ALIAS' is missing in $ssh_config"
  fi

  # GitHub returns non-zero for ssh -T even on success; parse output instead.
  ssh_output="$(ssh -T -o BatchMode=yes -o StrictHostKeyChecking=accept-new "git@${EXPECTED_GITHUB_HOST_ALIAS}" 2>&1 || true)"

  if [[ "$ssh_output" != *"Hi ${EXPECTED_GIT_USER_NAME}!"* ]]; then
    fail "SSH auth identity mismatch. Expected '${EXPECTED_GIT_USER_NAME}'. ssh output: ${ssh_output//$'\n'/ }"
  fi

  log "SSH identity check passed (Hi ${EXPECTED_GIT_USER_NAME}!)."
}

run_quality_gates() {
  require_command npm

  log "Running quality gate: npm test"
  npm test

  log "Running quality gate: npm run smoke:adapters"
  npm run smoke:adapters

  log "Running quality gate: npm run replay:drift"
  npm run replay:drift

  log "Running quality gate: npm run spec:check"
  npm run spec:check
}

maybe_sign_manifests() {
  local diff_names
  local upstream_ref

  upstream_ref="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
  if [[ -n "$upstream_ref" ]]; then
    diff_names="$(git diff --name-only "${upstream_ref}...HEAD")"
  else
    diff_names="$(git show --name-only --pretty='' HEAD 2>/dev/null || true)"
  fi

  if printf '%s\n' "$diff_names" | grep -Eq '^connectors/manifests/.*\.connector\.json$'; then
    log "Connector manifest changed; running npm run manifest:sign"
    npm run manifest:sign
  else
    log "No connector manifest change detected; skip manifest signing."
  fi
}

main() {
  local repo_root
  local remote_name
  local remote_url

  require_command git
  require_command ssh

  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  [[ -n "$repo_root" ]] || fail "Run this script inside a git repository."
  cd "$repo_root"

  remote_name="${1:-origin}"
  remote_url="${2:-$(git remote get-url --push "$remote_name" 2>/dev/null || true)}"

  verify_remote_identity "$remote_name" "$remote_url"
  verify_git_author
  verify_ssh_alias
  run_quality_gates
  maybe_sign_manifests

  log "All pre-push checks passed."
}

main "$@"
