# Changelog — Pilot App Store + Wallet

Release notes for the Pilot app-store plugin (`web4/app-store/`),
the `io.pilot.wallet` reference app (`web4-apps/wallet/`), and the
`pilotctl appstore` CLI surface (in `web4/cmd/pilotctl/`).

For the upstream daemon release notes see `web4/CHANGELOG.md`.

## [1.0.0-rc1] — UNRELEASED

First release candidate. Surface is end-to-end working for the
"local-bundle install, single-host development + CTF use" target.
Production deployment against an untrusted publisher requires the
catalog-signing chain landed in a follow-up RC (see "Known gaps").

### Added — pilotctl

`pilotctl appstore` is the operator surface for the app store.
All subcommands accept `--json` for scriptable output.

- `list` — enumerate installed apps with version + methods + state.
  State elevates `INVALID` (manifest fails Validate) or `SUSPENDED`
  (crash-loop budget spent — sentinel file detected) above `stopped`
  with the matching recovery hint inline.
- `status <id>` — deep-dive on one app: binary path + size + sha256
  pin (with `actual` hash surfaced on mismatch), socket readiness,
  identity/db presence, audit log path + size, manifest validation
  status with errors listed if invalid, grants, structured spend
  caps with sign-purpose target, hook extensions.
- `audit <id> [--tail N] [--event NAME] [--since DURATION]` — show
  the supervisor lifecycle log; reads both the active `supervisor.log`
  and the rotated `supervisor.log.1` so history survives rotation.
  `--since` accepts Go duration syntax (`10m`, `1h`, `24h`).
- `verify <bundle-dir>` — runs the sha256 trust check AND the
  manifest's semantic Validate against a pre-install bundle, so an
  invalid manifest can't slip past install only to be silently
  skipped by the supervisor later.
- `install <bundle-dir> [--force]` — stage + atomic-rename a verified
  bundle into the install root; daemon picks it up on next rescan
  (no daemon restart needed). Also runs Validate before placing.
- `uninstall <id> --yes` — race-aware removal (manifest-first, then
  retry-RemoveAll) so the live supervisor's audit writes don't fight
  the deletion.
- `restart <id>` — drop a `.resume` sentinel that asks the supervisor
  to clear crash-loop suspension and respawn the app.
- `caps <id>` — show the manifest's declared spend caps with live
  rolling-window usage from `cap-state.jsonl`. Reports per-cap
  `used/limit`, target (sign-purpose), and `first drop in <duration>`
  hint for when headroom returns.
- `actions [--tail N] [--event NAME]` — read the durable
  install-root-level pilotctl-audit log (`.pilotctl-audit.log`)
  showing `installed`/`uninstalled`/`restart-requested` events with
  actor + sha256 + bundle source. Survives uninstall.
- `call <id> <method> [args-json]` — dispatch an IPC call into a
  running app. `method-not-found` errors carry a hint listing the
  app's actually-exposed methods.

JSON shape is consistent across subcommands: arrays for list-shaped
responses (`list`, `audit`), objects for single-thing responses
(`status`, `install`, `uninstall`, `restart`). Errors always emit
the `{code,error,hint,message,status}` envelope.

### Added — app-store plugin

- **Supervisor lifecycle audit log.** Per-app `supervisor.log`
  (0600, JSONL) records `supervise-start`, `spawn`, `spawn-fail`,
  `exit`, `verify-fail`, `suspend`, `resume`, `supervise-stop`. SHA256
  pins are recorded on every spawn for forensic binary-version pinning.
- **Crash-loop cap.** 5 crashes in 60s suspends an app until
  operator-requested restart (no permanent runaway respawns).
- **Periodic install-root rescan** (default 30s, configurable).
  Discovers apps installed mid-run (no daemon restart needed),
  detects apps whose dir disappeared (cancels their supervise
  goroutine cleanly), consumes `.resume` markers to lift suspension.
- **Atomic install + binary sha256 re-verify.** Staging dir +
  `os.Rename` swap means a daemon scanning the install root never
  sees a partially-written app. The supervisor sha256-checks the
  binary against the manifest pin on every spawn.
- **Audit log rotation** (10MB default, configurable via
  `Config.AuditLogMaxBytes`). Single-step rotation:
  `supervisor.log` → `supervisor.log.1` bounds worst-case footprint
  at `2 × max` per app.
- **Operator-action audit log.** Install / uninstall / restart-requested
  pilotctl actions land in a durable `<install_root>/.pilotctl-audit.log`
  (JSONL, 0600) that survives app removal — closes the forensic
  question "who installed this and when, who removed it later?"
  Readable via `pilotctl appstore actions`.
- **Per-app resource limits (Linux).** `prlimit64(2)` sets
  `RLIMIT_NOFILE=256` on every spawn; macOS no-ops with a
  documented log line. Linux+macOS only.
- **Broker IPC surface.** `Service.Call(ctx, appID, method, args, out)`
  + `Service.Apps()` lets other daemon plugins and `pilotctl`
  dispatch into running apps without dialing the socket directly.
- **Startup warning** when `EmbeddedCatalogPubkey` is the all-zeros
  placeholder, so dev-mode trust state can't be silently shipped.

### Added — wallet

- **`wallet.balances` IPC method** (plural) — snapshot of every
  non-zero asset balance in one call.
- **`wallet.spend_caps` IPC method** — live introspection of
  configured caps + their rolling-window usage. Lets UIs/agents
  query cap headroom without reading `cap-state.jsonl` off disk.
- **Receipt UX layer** on `ReceiptIntent`: `Decimals`, `TokenSymbol`,
  `FormattedAmount` (`"1.500000 USDC"`), `ChainName` (`"Base Sepolia"`),
  `ExpiresIn(now)`, `Expired(now)`, single-line `String()` summary.
- **Multi-token recognition.** Chain-aware token registry in
  `pkg/evm/chains.go` recognises USDC + USDT on Ethereum mainnet,
  Base mainnet, Base Sepolia (where deployed). UIs render
  non-USDC receipts cleanly.
- **History pagination cursor.** `HistoryFilter.Before time.Time`
  enables newest-first walking through older entries.
- **Spend caps enforced end-to-end.**
  - Caps declared in the manifest's `grants` block
    (`key.sign:cap` conditions) are parsed by
    `wallet.ParseSpendCapsFromManifest`.
  - The wallet binary auto-applies them at startup via `--manifest`
    (passed by the supervisor on spawn).
  - Enforced inside both `Wallet.Pay` (IPC ledger) and
    `Wallet.SatisfyEVM` (on-chain EIP-3009) against a shared spend
    log — switching surfaces does NOT bypass caps.
  - Persisted to `cap-state.jsonl` (0600, append-only) via
    `--cap-state` (also passed by the supervisor) so rolling-window
    state survives daemon/wallet restart. Without persistence, a
    restart was a cap bypass.

### Security

- **Identity files refuse to load** with permissions broader than 0600
  (OpenSSH-style check). Applies to both `LoadLocalSigner`
  (ed25519 pilot identity) and `LoadEVMSigner` (secp256k1 chain
  identity). A `chmod 644` is now refused with a clear hint.
- **Cap-state file refuses to load** when world-readable (same
  threat model — spend history leaks payment patterns).
- **Audit log permissions** locked at 0600, preserved across rotation.
- **Unknown chain ID errors include the offending id** so operators
  can see "which chain" was rejected.

### Tested

- Per-package unit tests: 100+ across `pkg/wallet`, `pkg/evm`,
  `pkg/walletipc`, `plugin/appstore`.
- Integration suite (`web4/app-store/integration/`) spawns the real
  wallet binary under the real supervisor. Includes the full-chain
  smoke `TestFullChainInstallRescanCallRestartUninstall`.
- Race-clean: `go test -race ./...` green across all four scopes
  (wallet, app-store, integration, pilotctl).
- Stress: 20× repeat on time-sensitive supervisor tests
  (rescan, audit rotation, crash-loop) — no flakes.

### Known gaps (deferred to RC2 / scoped out of RC1)

- **No catalog fetch + Merkle proof.** RC1 ships with the
  all-zeros `EmbeddedCatalogPubkey` placeholder — fail-closed by
  design, surfaced as a startup WARNING. Production installs MUST
  build with a real catalog trust anchor; without it, signed
  catalogs cannot be authenticated. RC1's install path takes only
  local bundles via `pilotctl appstore install <dir>`.
- **Partial per-app resource limits.** Linux sets RLIMIT_NOFILE=256
  via `prlimit64(2)` on every spawn; macOS is no-op (logs "not
  enforced for pid=N on this platform"). Memory caps (RLIMIT_AS) and
  cgroup-based isolation deferred to RC2. Apps can still OOM the
  host on either platform.
- **No encrypted-at-rest identity.** The 0600 perm refusal is the
  only fence against local-user theft of the wallet's signing
  seed. A passphrase + KDF wrap is deferred.
- **macOS + Linux only.** Windows is untested.
- **Wallet manifest's `store.publisher` is the placeholder
  AAA…AAA pubkey.** Replace before tagging a non-dev build.

### Migration notes

The Pilot Go module paths are unchanged in RC1. The repos will move
under the `pilot-protocol` GitHub org post-RC; no source changes
required at that time beyond `go mod edit -module` + sed.

The wallet's `manifest_version` is unchanged at `2`. Apps installed
under earlier wallet manifest versions auto-re-consent only on a
manifest_version bump.

The supervisor passes two new standard lifecycle flags to spawned
apps: `--manifest <path>` (for cap parsing) and `--cap-state <path>`
(for cap persistence). Apps that don't recognise them will refuse to
start with a Go-stdlib `flag provided but not defined` error —
update any custom app binaries accordingly.
