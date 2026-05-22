# pilot-app-store

Isolated implementation of the Pilot app store. Independent module, independent tests, designed to be pulled into pilot as a plugin via `git subtree` (or merged) once it stabilizes.

## What lives here

```
pkg/
  manifest/    typed manifest schema + validator
  grants/      grant policy engine (cap conditions: rate, cap, allowlist, ...)
  derive/      HKDF-based per-app key derivation
  ipc/         the new IPC commands (CmdAppHello, CmdAppSign, ...)
  runtime/     app supervisor — spawns app processes, brokers their calls
  store/       store.pilot client + catalog types
plugin/
  plugin.go    pilot.Service implementation (the bridge into pilot's plugin registry)
examples/
  *.manifest.json  real-shaped manifests for the launch apps
cmd/
  pilotctl-app/    standalone CLI for app management (eventually merged into pilotctl)
```

The architecture model this implements lives in `../docs/architecture/graph.json`. Anything that disagrees between code and that graph is a bug in one of the two — they should be kept in sync.

## How to test

```bash
cd app-store
go test ./...
```

## Why isolated?

- Build the runtime against mocks of pilot's primitives (root identity, send-message, peer discovery) so the inner loop is fast.
- The plugin bridge (`plugin/plugin.go`) is the only file that touches real pilot types; everything else is testable without bringing pilot in.
- When the runtime is solid, the bridge gets wired into `pilots`/daemon's plugin registry — a single integration commit.

## Status

Phase 1 of the dev plan (per `docs/architecture/graph.json` → development plan view): foundation. Building manifest, grants, derive, ipc, runtime in that order.
