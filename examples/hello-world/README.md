# hello-world

The smallest end-to-end Pilot app — single IPC method, sideload-safe
manifest, build → install → call in three commands. Read alongside
[`cmd/hello/main.go`](cmd/hello/main.go) and
[`manifest.json`](manifest.json); together they're the reference for
what an app needs to do to be supervisable by a Pilot daemon.

## Try it

```sh
# from this directory:
make bundle                 # builds ./bundle/bin/hello and ./bundle/manifest.json with the binary sha pinned
make install-local          # pilotctl appstore install ./bundle --local

# wait ~30s for the supervisor to spawn it (or check progress):
pilotctl appstore list      # expect: io.example.hello … state: ready [sideloaded]

# call the one IPC method this app exposes:
pilotctl appstore call io.example.hello hello.echo '{"message":"hi"}'
# → {"echo":"hi","sideloaded":true}
```

The committed `manifest.json` is the template; `make bundle` copies
it into `bundle/manifest.json` and pins the binary's sha256 there,
so re-running the build never rewrites the committed file.

## What the manifest declares

| Field | Why it matters |
|---|---|
| `id` | Reverse-DNS unique identifier. Reuses are install conflicts. |
| `binary.path` + `binary.sha256` | Supervisor sha-verifies the binary at every spawn; mismatch → refuse. |
| `exposes` | Method names the daemon will route to this app. Must match what `cmd/hello/main.go` registers on its dispatcher. |
| `grants` | The *only* source of authority. The runtime brokers every privileged op against this list. |
| `store.publisher` / `store.signature` | Catalogue-signed apps must verify here. Sideloaded apps skip this check (see below). |

The grants in this example are deliberately minimal — `fs.read`/`fs.write`
limited to `$APP/data.db` and `audit.log` for forensics. This is
exactly the surface a sideloaded app is permitted; the manifest will
install without modification under `pilotctl appstore install . --local`.

## Catalogue vs sideload

Two trust regimes exist for installed apps. They affect what grants
your manifest is allowed to declare and how the supervisor verifies
its provenance:

| | Catalogue | Sideloaded (`--local`) |
|---|---|---|
| Install command | `pilotctl appstore install <id>` | `pilotctl appstore install <dir> --local` |
| Provenance check | `store.signature` must verify against `store.publisher` | None (publisher key is honour-system) |
| Grants allowed | Whatever the publisher signed for | `audit.log`, `fs.read $APP/*`, `fs.write $APP/*` only |
| `extends` / `dynamic_extends` hooks | Yes | No |
| Cross-app `ipc.call` | Yes | No |
| `net.dial` / `key.sign` | Yes | No |
| Sentinel on disk | (none) | `.sideloaded` (mode `0o400`) in install dir |

If your manifest declares a grant outside the sideload allow-list,
`pilotctl appstore install --local` refuses up-front with a message
naming the offending cap. Strip it and re-run, or take the manifest
through publishing (signed catalogue entry) if the cap is necessary.

The sideload regime is a **manifest gate**. It guarantees no
sideloaded app's *declared* surface escapes the allow-list. It does
NOT prevent a hostile binary from ignoring its declarations at the
syscall level — OS-level sandbox work is a follow-up
(landlock/seccomp on Linux, sandbox-exec on macOS). Only install
paths from sources you'd trust on the host shell.

## The supervisor lifecycle contract

The daemon's supervisor passes every app the same six flags at spawn
time. `cmd/hello/main.go` shows the minimal handling — declare them
even if your app ignores most:

| Flag | Purpose |
|---|---|
| `--addr` | The pilot address the daemon assigned this app. |
| `--db` | Default path for app-local sqlite (`$APP/data.db`). |
| `--socket` | Unix socket the app must listen on. Supervisor watches for this file to mark the app `ready`. |
| `--identity` | Per-app ed25519 keypair (`$APP/identity.json`). Auto-created on first start by apps that use it. |
| `--manifest` | Path to the pinned manifest. Used by spend-cap-aware apps to activate their declared `key.sign`-cap limits. |
| `--cap-state` | JSONL spend-log path for rolling-window cap state. |

Beyond these, you may add your own flags. `os.Getenv("PILOT_SIDELOAD")`
is set to `"1"` for sideloaded apps — surface it in your replies the
way `echoResp.Sideloaded` does, or use it to refuse high-privilege
operations even when your manifest authorises them.

## Releasing as a catalogue app

For internal testing the sideload path is fine. To publish via the
public catalogue:

1. Generate a publisher keypair: `pilotctl appstore gen-key publisher.key`.
2. Sign the manifest: `pilotctl appstore sign --key publisher.key manifest.json`.
3. Build platform tarballs (linux/amd64, linux/arm64, darwin/amd64,
   darwin/arm64), pin per-arch `binary.sha256` in their respective
   manifests, host the tarballs at stable URLs.
4. Open a PR to add the app to `web4/catalogue/catalogue.json`.

The wallet (`io.pilot.wallet`) is the working example — see its
manifest in `pilot-protocol/wallet` for what a published catalogue
app looks like at production scale.
