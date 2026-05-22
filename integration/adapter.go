// Package integration is the glue layer between the app-store shim and
// the pilot daemon. It imports both modules and provides an Adapter that
// satisfies github.com/TeoSlayer/pilotprotocol/pkg/coreapi.Service by
// forwarding to *appstore.Service.
//
// This package is intentionally *not* part of the main app-store module's
// go.mod — app-store stays self-buildable. The whole point: compile-time
// proof that *appstore.Service satisfies the daemon's plugin contract.
// If coreapi.Service ever drifts from the shim, `go build` here breaks
// loudly.
package integration

import (
	"context"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/pilot-protocol/app-store/plugin/appstore"
)

// Adapter wraps an *appstore.Service so it implements coreapi.Service.
// Name / Order / Stop pass through unchanged; Start has to translate
// coreapi.Deps into the shim's local Deps shape.
type Adapter struct {
	svc *appstore.Service
}

// New returns an Adapter ready to register with the daemon's runtime.
//
// Typical usage (cmd/daemon/main.go):
//
//	rt.Register(integration.New(appstore.NewService(appstore.Config{
//	    InstallRoot:   ...,
//	    CatalogPubkey: appstore.EmbeddedCatalogPubkey,
//	})))
func New(svc *appstore.Service) *Adapter { return &Adapter{svc: svc} }

// Name forwards to the underlying service.
func (a *Adapter) Name() string { return a.svc.Name() }

// Order forwards to the underlying service.
func (a *Adapter) Order() int { return a.svc.Order() }

// Start maps real coreapi.Deps into the shim's structurally-typed Deps
// bag, then delegates. The shim treats the fields as `any`, so it can
// type-assert back to coreapi.Streams / Identity / etc. when it needs
// them at supervise time.
func (a *Adapter) Start(ctx context.Context, deps coreapi.Deps) error {
	return a.svc.Start(ctx, appstore.Deps{
		Streams:  deps.Streams,
		Identity: deps.Identity,
		Resolver: deps.Resolver,
		Events:   deps.Events,
		Logger:   deps.Logger,
		Trust:    deps.Trust,
	})
}

// Stop forwards to the underlying service.
func (a *Adapter) Stop(ctx context.Context) error { return a.svc.Stop(ctx) }

// Compile-time assertion that *Adapter satisfies coreapi.Service. If
// the interface ever changes shape this line is the first thing that
// breaks the build — surfacing the drift early.
var _ coreapi.Service = (*Adapter)(nil)
