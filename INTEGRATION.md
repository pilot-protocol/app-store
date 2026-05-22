# Integrating the app store into pilot (web4)

This document is the read-before-edit plan for wiring the app store into the
pilot daemon. **No web4 files have been modified yet** — the changes below are
proposed.

## What's shipped today

Across `~/Development/web4/app-store/` and `~/Development/web4-apps/wallet/`,
the following components are built and tested (210+ tests, all green):

- **Hook/extension protocol** (`pkg/extend/`) — open-namespace pre/post hooks
  on any command, runtime registration gated by manifest declarations,
  provenance metadata (`WireMeta`) that follows every hooked message so
  recipients without the right apps installed see a clean "install X" message
  rather than a decode failure.

- **Payment-capability framework** (`pkg/payment/`) — `Method`, `Escrow`, `Seal`
  interfaces with chacha20-poly1305 default seal. Wallets implement these
  slots; other apps can plug their own implementations alongside.

- **Real x402 wallet** (`web4-apps/wallet/`):
  - `pkg/evm/` — secp256k1 keys, EIP-712 typed-data hashing for EIP-3009
    transferWithAuthorization, on-chain-verifiable signatures (validated
    against the canonical Vitalik test vector), JSON-RPC client for
    `balanceOf` + `sendRawTransaction`, broadcast helper that emits
    transferWithAuthorization calldata for relayer / recipient submission.
  - Method id `io.pilot.wallet/v1` produces real USDC-on-Base receipts.
  - Method id `io.pilot.wallet-mock/v1` is the offline Ed25519 internal-ledger
    test wallet (lives alongside the EVM one, no collision).
  - Hooks `wallet.hookPreSendMessage` (adds `--paywall` to `send-message`)
    and `wallet.hookPostRecvMessage` (detects sealed envelopes on receive).
  - IPC surface: `wallet.balance/address/request/pay/verify/settle/topup/history`
    plus `wallet.evm.address/balance/satisfy/verify` when EVM is enabled.

- **Plugin shim + integration adapter** (`app-store/plugin/appstore/`,
  `app-store/integration/`) — `*Service` implements the daemon's
  `coreapi.Service` interface via a compile-time-checked Adapter; supervisor
  spawns child app processes with sha256 verification; tested end-to-end
  spawning the real wallet binary.

## Goal

After integration, a user can:

```
pilotctl appstore install io.pilot.wallet     # fetch + verify + pin manifest, place binary, ask user for grants
pilotctl appstore list                        # see installed apps + their state
pilotctl appstore uninstall io.pilot.wallet
```

…and the daemon, on start, automatically supervises every installed app
(spawns its binary, brokers `ipc.call:<app>.<method>` from peer apps,
handles graceful shutdown).

## Web4 changes — total: ~8 lines

### 1. Register the plugin (`cmd/daemon/main.go:226`, before `rt.StartPlugins`)

```go
rt.Register(integration.New(appstore.NewService(appstore.Config{
    InstallRoot:   cfg.AppStoreInstallRoot,   // default: ~/.pilot/apps
    CatalogPubkey: appstore.EmbeddedCatalogPubkey,
})))
```

The `integration.Adapter` wrapper is what actually satisfies `coreapi.Service`
— it maps the real `coreapi.Deps` into the shim's structurally-typed bag.
A compile-time assertion in `app-store/integration/adapter.go` guarantees
the wrapper still satisfies the interface; if you see a build break in web4
after a coreapi rev, the assertion will tell you exactly which field drifted.

### 2. Add the imports (`cmd/daemon/main.go`, with the other plugin imports)

```go
"github.com/pilot-protocol/app-store/integration"
"github.com/pilot-protocol/app-store/plugin/appstore"
```

### 3. Pilotctl subcommands (`cmd/pilotctl/main.go`, in the big switch)

```go
case "appstore":
    cmdAppStore(cmdArgs)
```

…with a new file `cmd/pilotctl/appstore.go` that implements the subcommands.
Sketch in `app-store/plugin/pilotctl/`.

### 4. Config (`pkg/config/config.go`, optional fields)

```go
AppStoreInstallRoot string // default ~/.pilot/apps
EVMRPCEndpoint      string // optional, used by io.pilot.wallet for x402
EVMChainID          uint64 // default 8453 (Base mainnet); 84532 for Base Sepolia dev
```

The EVM fields are forwarded to the wallet's per-install config (via
`<InstallRoot>/io.pilot.wallet/config.json` at install time) so the wallet
binary doesn't need them on its CLI in production.

That is the complete web4 footprint. Everything else lives in app-store/ and
in the wallet's own module.

## What the plugin does

`appstore.Service` implements `coreapi.Service`:

| Method | Behavior |
|---|---|
| `Name()` | `"appstore"` |
| `Order()` | `120` (application-layer; after trust at 50, before sidecars at 200) |
| `Start(ctx, deps)` | Scan `InstallRoot/*/manifest.json`, verify sha256s, spawn each app's binary under a child supervisor, register their methods in a `deps.Streams` listener so peer-app calls route correctly |
| `Stop(ctx)` | SIGTERM every child, wait `5s`, SIGKILL stragglers, close all sockets |

### Per-app supervisor

For each installed app the supervisor maintains:

```
~/.pilot/apps/<app_id>/
├── manifest.json    # pinned manifest the user consented to
├── binary           # pinned executable, sha256-checked at every start
├── data.db          # the app's own sqlite (wallet ledger / memories index / ...)
├── identity.json    # the app's signing key (ed25519 seed, 0600)
├── app.sock         # unix socket the daemon dials to talk to the app
└── audit.log        # signed event log per the prim_audit primitive
```

The supervisor:

1. Verifies `sha256(binary) == manifest.binary.sha256`. Mismatch → abort, log, do not start.
2. Spawns the binary with flags: `--addr=<daemon's pilot addr>`, `--db=<data.db>`, `--socket=<app.sock>`, `--identity=<identity.json>`.
3. Waits for the socket to appear (poll up to 2s).
4. Dials the socket and parks a long-lived IPC conn — used to forward `ipc.call:<app>.<method>` requests from other apps.
5. Restarts the process on crash (exponential backoff, capped at 30s) unless explicitly suspended.

### Trust chain enforcement at install time

`appstore install <app_id>` flow:

1. Fetch `catalog.head.json` from `catalog_repo`.
2. Verify the signature against `EmbeddedCatalogPubkey`.
3. Fetch `manifests/<app_id>.json` and the binary URL listed in it.
4. Re-compute canonical-JSON sha256 of the manifest; verify Merkle proof from
   leaf to signed root.
5. Compute `sha256(binary)` and check it matches `manifest.binary.sha256`.
6. Show the user the grant list and the depends list; require explicit accept.
7. Pin `(manifest, binary, manifest_version, manifest_hash)` to disk under
   `<InstallRoot>/<app_id>/`.

That's the literal "pilotctl embeds store pubkey → store signs manifest →
manifest pins binary.sha256 → daemon re-verifies on every launch" trust chain
the architecture graph asserts.

### Grant model

Grants live in `<InstallRoot>/<app_id>/grants.db` (separate sqlite from the
app's own data). The daemon's broker checks this file on every `ipc.call`
into the app. Manifest_version bump on the publisher's side triggers re-consent
via pilotctl before the new manifest activates.

## Open questions for the user

1. **Catalog pubkey source.** Compile-time-embedded constant in app-store
   (`EmbeddedCatalogPubkey`), or read from `~/.pilot/config.json`? Compile-time
   is the architecture's stated trust anchor; config-file is easier for
   testing. Recommend compile-time, override only with a `-dev-catalog-key`
   debug flag.

2. **Wallet auto-install for dev.** Should the first daemon start auto-install
   `io.pilot.wallet` from a local catalog under `~/Development/web4-apps/` so
   we can iterate without pushing to a real catalog? Recommend yes, gated by
   a `-dev-apps` flag.

3. **Crash-loop policy.** A misbehaving app could spin its restart budget
   forever. Cap at N restarts in M seconds, then mark suspended; user
   resurrects with `pilotctl appstore restart <id>`.

## Test plan (before any web4 edit)

- `app-store/plugin/appstore/` shim implements `coreapi.Service` against a
  fake `coreapi.Deps` (defined in app-store, mirrors the real one). Unit
  tests cover Start/Stop, sha256 verification, spawn/respawn.
- A second test crate `app-store/integration/` adds `replace
  github.com/web4/pilot => ../../web4` so the shim compiles against the real
  `coreapi.Service` interface. CI runs both.
- Once both pass, the web4 edit is the eight lines above — no risk surface.

## Files to add in app-store (this tick scope)

- `app-store/INTEGRATION.md` (this file)
- `app-store/plugin/appstore/service.go` — the shim
- `app-store/plugin/appstore/supervisor.go` — child-process supervisor (sketch)
- `app-store/plugin/appstore/install.go` — install-flow stubs

## Files to add in web4 (deferred to next tick, awaiting user approval)

- `cmd/daemon/main.go` — one import, three lines in the register block
- `cmd/pilotctl/appstore.go` — pilotctl subcommands (new file)
- `cmd/pilotctl/main.go` — one case in the switch
- `pkg/config/config.go` — three optional fields (install root + EVM RPC + chain id)

## x402 settlement: how a recipient takes a wallet receipt on-chain

When agent A's wallet produces a `wallet.evm.satisfy` receipt for a `payment.Contract`,
the receipt is a self-contained EIP-3009 transferWithAuthorization signed by A.
Agent B (the recipient / payee) takes it on-chain in one of three ways:

1. **Direct submission via the wallet's broadcast helper.** B's daemon calls
   `evm.Broadcaster.CalldataForReceipt(receipt)` to get `(token_addr, calldata_hex)`,
   builds a transaction (B sets the from-address to B's own EVM key, sets to=token_addr,
   sets data=calldata_hex, sets gas/nonce/fees), signs it with B's wallet, and
   broadcasts via `SubmitTransferWithAuthorization`. B pays the gas; the USDC contract
   moves `value` USDC from A's address to B's address. This is the simplest path
   for a recipient that wants direct settlement.

2. **Meta-transaction relayer.** B forwards (token_addr, calldata, signature) to
   a relayer service (Gelato, ERC-4337 bundler, internal infra). The relayer
   pays gas and either bills B off-chain or takes a cut of the transfer. B
   receives the USDC without ever paying gas.

3. **Hold for later batched settlement.** B accumulates receipts and submits
   them in a batch when gas is cheap or volume justifies a single tx with
   multiple authorizations. This is a niche path; the wallet's receipt format
   is the same.

All three paths use the same receipt payload — the only difference is who
calls `transferWithAuthorization` and when. The wallet's signature is valid
on-chain regardless of who submits it.

## The two registered methods at a glance

| Method ID | Backend | Use |
|---|---|---|
| `io.pilot.wallet/v1` | EVM secp256k1 + EIP-3009 | Real x402 USDC payments; signatures verifiable on Base / Ethereum |
| `io.pilot.wallet-mock/v1` | Ed25519 internal ledger | Offline tests, dev mode, contract-shape verification without touching a chain |

Both coexist on a single wallet instance. The contract's `accepted_methods`
field decides which one runs. For real-world send: list only the EVM id.
For testing: list the mock id. For interop between agents at different
trust levels: list both, and whichever the payer has installed satisfies.
