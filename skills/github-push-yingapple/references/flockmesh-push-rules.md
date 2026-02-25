# FlockMesh Push Rules

## Mandatory identity rules

1. Use GitHub account `yingapple` for push authentication.
2. Do not use host alias `github.com-mind-ying`.
3. Use remote URL format `git@github.com-yingapple:<owner>/<repo>.git`.
4. Keep local git author as:
- `user.name=yingapple`
- `user.email=yingxiang835@gmail.com` (or explicit override requested by user)

## SSH config template

Use a dedicated host alias in `~/.ssh/config`:

```sshconfig
Host github.com-yingapple
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_rsa
  AddKeysToAgent yes
  UseKeychain yes
```

Validate with:

```bash
ssh -T git@github.com-yingapple
```

Expected identity line should contain `Hi yingapple!`.

## Mandatory quality gates before push

Run in repository root:

```bash
npm test
npm run smoke:adapters
npm run replay:drift
npm run spec:check
```

If any file in `connectors/manifests/*.connector.json` changed since upstream, also run:

```bash
npm run manifest:sign
```
