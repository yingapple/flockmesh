---
name: github-push-yingapple
description: Enforce GitHub push safety for this workspace by requiring the `yingapple` identity (never `mind-ying`), validating remote/SSH/local git author config, and running project quality gates before any push. Use when preparing to push, fixing push identity problems, installing pre-push guardrails, or validating that a branch meets FlockMesh development checks.
---

# Github Push Yingapple

## Workflow

1. Resolve the git repository root and current push target.
2. Enforce push identity:
- Require origin push URL host alias `github.com-yingapple`.
- Reject any URL containing `github.com-mind-ying`.
- If needed, rewrite remote to `git@github.com-yingapple:<owner>/<repo>.git`.
3. Enforce local commit identity:
- Require `git config --local user.name` to equal `yingapple`.
- Require `git config --local user.email` to equal `yingxiang835@gmail.com` (or explicit override).
4. Verify SSH identity:
- Require `~/.ssh/config` to include host `github.com-yingapple`.
- Run `ssh -T git@github.com-yingapple` and confirm authenticated username is `yingapple`.
5. Enforce FlockMesh development gates before push:
- `npm test`
- `npm run smoke:adapters`
- `npm run replay:drift`
- `npm run spec:check`
6. If connector manifests changed, re-sign attestations with `npm run manifest:sign`.
7. Push only after all checks pass.

## Scripts

- `scripts/pre_push_guard.sh`: Run identity validation and development gate checks.
- `scripts/install_pre_push_hook.sh`: Install git `pre-push` hook to enforce the guard script automatically.

## References

- `references/flockmesh-push-rules.md`: Remote URL patterns, SSH host config template, and project gate rationale.
