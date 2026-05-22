package extend

import (
	"context"
	"errors"
)

// Core is the type a command's baseline logic takes. Wrap calls it
// between the pre-hook chain and the post-hook chain; the args it
// receives are the pre-transformed args, and whatever it returns flows
// into the post chain.
type Core func(ctx context.Context, args HookArgs) (HookArgs, error)

// Wrap is the single generic wrapper that gives every command pre and
// post hooks. The daemon (and pilotctl) dispatch every command through
// Wrap; the command author never opts in or out — the wrapping is
// uniform across the platform.
//
// Hooks extend the command's functionality, they never replace it.
// Pre-hooks may transform args or refuse (return error → abort, core
// does not run). Post-hooks see the core's output. Neither can bypass
// the core.
func Wrap(ctx context.Context, r *Registry, cmd string, args HookArgs, core Core) (HookArgs, error) {
	if r == nil {
		return nil, errors.New("extend.Wrap: nil registry")
	}
	if core == nil {
		return nil, errors.New("extend.Wrap: nil core")
	}
	if cmd == "" {
		return nil, errors.New("extend.Wrap: empty command name")
	}
	if args == nil {
		args = HookArgs{}
	}

	transformed, err := r.Run(ctx, HookPoint(cmd+".pre"), args)
	if err != nil {
		return nil, err
	}
	result, err := core(ctx, transformed)
	if err != nil {
		return result, err
	}
	if result == nil {
		result = transformed
	}
	return r.Run(ctx, HookPoint(cmd+".post"), result)
}
