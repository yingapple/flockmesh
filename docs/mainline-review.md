# Mainline Review (Agent-Centric)

Last updated: `2026-02-24`

## Review Goal

Validate that FlockMesh stays on the core track:

1. AI/Agent-native execution center
2. Governance-first runtime (`policy -> approval -> audit`)
3. Ecosystem-rooted interoperability (office systems + agent protocols)
4. Occam kernel discipline (no product sprawl into chat replacement)

## Findings (Ordered By Severity)

1. `P1 (fixed)`: Policy apply path could be used without strict optimistic concurrency from control plane.
- Impact: stale writer risk on policy governance operations.
- Resolution in current checkpoint:
  - API now requires `expected_profile_hash` when `mode=apply` for both patch and rollback.
  - Control-plane Policy Patch console now loads profile version hash and auto-sends it on apply.
  - `409` hash conflict is surfaced with current hash refresh hint.

2. `P1 (fixed)`: Control plane previously had patch flow but no first-class rollback console.
- Impact: rollback existed in API, but operator friction was high.
- Resolution in current checkpoint:
  - Added Policy Rollback Console with profile history preview, `Draft Latest`, `dry_run/apply`, and hash-guarded apply flow.
  - Added rollback-side hash conflict refresh hint (`409`).

3. `P2 (fixed)`: Demo bootstrap path was connector-preset to `con_feishu_official`.
- Impact: default demo narrative could bias toward channel-first interpretation.
- Resolution in current checkpoint:
  - Switched control-plane demo preset to system-first (`con_office_calendar`, scheduler trigger source).
  - Channel compatibility remains available but no longer dominates bootstrap defaults.

4. `P2 (fixed)`: API policy integration tests previously wrote files into repo `policies/`.
- Impact: workspace noise and residual test artifacts risk.
- Resolution in current checkpoint:
  - Policy API integration tests now run against isolated temp-root fixtures (`spec/public/connectors/kits/policies` copied per sandbox).
  - Test cleanup removes the entire sandbox root instead of deleting individual repo files.

## Mainline Status

- Agent-centered core: `Pass`
- Governance kernel: `Pass` (mandatory apply hash guard + patch/rollback control-plane flow)
- Ecosystem bridge (MCP/A2A + office connectors): `Pass`
- Kernel discipline (avoid chat-product drift): `Pass` with noted UI/UX guardrails above
