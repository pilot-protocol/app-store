# app-store

[![ci](https://github.com/pilot-protocol/app-store/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/app-store/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/app-store/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/app-store)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Extension framework for the Pilot Protocol. Defines the manifest schema,
grant policy engine, and IPC contract that let third-party apps plug
into a Pilot daemon with capability-scoped access to peer messaging,
identity, and storage primitives.

## Install

```go
import "github.com/pilot-protocol/app-store"
```

## Usage

```go
import (
    "github.com/pilot-protocol/app-store/pkg/manifest"
    "github.com/pilot-protocol/app-store/plugin/appstore"
)

// Load + validate an app manifest.
m, err := manifest.Load("examples/wallet.manifest.json")
if err != nil { return err }
if err := manifest.Validate(m); err != nil { return err }

// Construct the appstore plugin for the daemon's runtime registry.
svc := appstore.NewService(appstore.Config{
    InstallRoot:   "~/.pilot/apps",
    CatalogPubkey: appstore.EmbeddedCatalogPubkey,
})
```

Run the tests:

```bash
go test ./...
```

## Layout

| Package | What it does |
|---|---|
| `pkg/manifest` | Typed manifest schema + validator. |
| `pkg/extend`   | Open-namespace pre/post hooks on any command; runtime registration gated by manifest declarations. |
| `pkg/ipc`      | IPC commands (`CmdAppHello`, `CmdAppSign`, …) and framing. |
| `pkg/payment`  | `Method`, `Escrow`, `Seal` interfaces; default chacha20-poly1305 seal. |
| `plugin/appstore` | The `coreapi.Service` plugin: scans install root, verifies sha256, supervises child app processes, brokers peer-app IPC calls. |
| `integration`  | Adapter that pins `*Service` against the daemon's plugin interface at compile time. |

## Trust chain

The daemon embeds a catalog public key; the catalog signs each manifest;
each manifest pins its binary's sha256; the daemon re-verifies the
binary on every launch and brokers IPC calls only when the user has
explicitly accepted the app's declared grants.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
