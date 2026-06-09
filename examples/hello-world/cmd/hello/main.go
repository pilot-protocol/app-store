// Hello-world Pilot app.
//
// Demonstrates the smallest possible app that the daemon's supervisor
// can spawn and route IPC calls into. Sideload-safe by design: it
// declares only audit.log + fs.read/fs.write under $APP, so a user
// can install it via `pilotctl appstore install ./examples/hello-world --local`
// without tripping any sideload-policy refusal.
//
// Read alongside ../manifest.json — the manifest is the only thing that
// authorises this binary to do anything privileged. Every flag below is
// part of the standard lifecycle contract the supervisor passes to every
// app at spawn time:
//
//   --addr, --db, --socket, --identity, --manifest, --cap-state
//
// An app may add its own flags on top, but these six are guaranteed by
// the supervisor and should not error if unrecognised by future tooling.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

const (
	// methodEcho is the only IPC entrypoint this app exposes. The
	// manifest's "exposes" array must mirror this — see manifest.json.
	methodEcho = "hello.echo"

	// envSideloaded is the supervisor's hint that the app was installed
	// via `--local` rather than from the signed catalogue. Cap-aware
	// apps can use this to refuse high-privilege operations even when
	// their own manifest authorises them — defence in depth on top of
	// the supervisor's manifest gate.
	envSideloaded = "PILOT_SIDELOAD"
)

type echoReq struct {
	Message string `json:"message"`
}

type echoResp struct {
	Echo       string `json:"echo"`
	Sideloaded bool   `json:"sideloaded"`
}

func main() {
	fs := flag.NewFlagSet("hello", flag.ExitOnError)
	var (
		// Pilot address the daemon assigned this app — opaque to the app
		// itself in the hello-world case, but real apps use it for
		// identity in peer-facing messages.
		_         = fs.String("addr", "", "pilot address (e.g. 0:0001.HHHH.LLLL)")
		_         = fs.String("db", "", "sqlite path (unused by hello-world; declared for lifecycle parity)")
		sockPath  = fs.String("socket", "", "unix socket to listen on; supervisor sets this")
		_         = fs.String("identity", "", "ed25519 identity file (unused by hello-world)")
		_         = fs.String("manifest", "", "path to manifest.json (unused by hello-world)")
		_         = fs.String("cap-state", "", "spend-cap state log (unused by hello-world)")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatalf("flag parse: %v", err)
	}
	if *sockPath == "" {
		log.Fatalf("supervisor did not pass --socket; refusing to start")
	}

	sideloaded := os.Getenv(envSideloaded) == "1"
	logger := log.New(os.Stderr, "hello-world: ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("starting (sideloaded=%v) listening on %s", sideloaded, *sockPath)

	// Unix-domain socket sat exactly where the supervisor told us to
	// put it. The supervisor watches for this file's appearance to mark
	// the app "ready"; if we listen anywhere else, the supervisor will
	// time out and the app stays "stopped" from its perspective.
	if err := os.Remove(*sockPath); err != nil && !os.IsNotExist(err) {
		logger.Fatalf("remove stale socket: %v", err)
	}
	ln, err := net.Listen("unix", *sockPath)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	d := ipc.NewDispatcher()
	d.Register(methodEcho, echoHandler(sideloaded))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Clean shutdown on SIGTERM: the supervisor sends SIGTERM to the
	// whole process group when uninstalling, restarting, or stopping
	// the daemon. Ignoring it would let the supervisor wait the full
	// grace period before SIGKILLing — slower restarts.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		logger.Printf("shutdown signal received")
		cancel()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("accept: %v", err)
			continue
		}
		// One Serve loop per connection, on its own goroutine. The
		// daemon may open multiple connections in parallel — this is
		// the standard concurrency model for every app.
		go func(c net.Conn) {
			defer c.Close()
			if err := ipc.Serve(ctx, c, d); err != nil {
				logger.Printf("serve: %v", err)
			}
		}(conn)
	}
}

// echoHandler is the entire business logic of this app: take a
// message, return it back. The sideloaded flag is surfaced in the
// reply so callers can confirm at runtime which trust regime the
// supervisor put the app in.
func echoHandler(sideloaded bool) ipc.Handler {
	return func(_ context.Context, req *ipc.Envelope) (json.RawMessage, error) {
		var args echoReq
		if len(req.Payload) > 0 {
			if err := json.Unmarshal(req.Payload, &args); err != nil {
				return nil, fmt.Errorf("decode echo args: %w", err)
			}
		}
		resp := echoResp{Echo: args.Message, Sideloaded: sideloaded}
		body, err := json.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("marshal echo resp: %w", err)
		}
		return body, nil
	}
}
