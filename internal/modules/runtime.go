// Package modules implements the plugin-based Module Runtime (ТЗ §4.2, ТЗ-0).
//
// The platform invariant: modules M1..M4 are plugins over a shared event bus
// and asset store. A module (a) declares event subscriptions, (b) handles
// events, (c) publishes findings/events through the API — and never touches
// core internals. If a future module needs a core change, the architecture
// contract is violated (ТЗ §6, "проверка платформенности").
package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/oleg-vdv/autogov/internal/bus"
	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/store"
)

// Module is the plugin contract (ТЗ-0).
type Module interface {
	// Name is a unique module id, e.g. "m1-discovery".
	Name() string
	// Subscriptions returns event type patterns this module consumes.
	Subscriptions() []string
	// Handle processes one matching event.
	Handle(ctx context.Context, ev model.Event, api *API) error
}

// API is the only surface a module may use to interact with the platform.
type API struct {
	Store  *store.Store
	Bus    *bus.Bus
	Logger *slog.Logger
}

// PublishFinding stores a finding idempotently and emits finding.created /
// finding.updated events for notifiers and downstream modules.
func (a *API) PublishFinding(module string, f *model.Finding) {
	f.Module = module
	if f.UpdatedAt.IsZero() {
		f.UpdatedAt = time.Now().UTC()
	}
	stored, changed := a.Store.UpsertFinding(f)
	if !changed {
		return
	}
	payload, _ := json.Marshal(stored)
	a.Bus.Publish(model.Event{
		ID:      model.StableID("finding-ev", stored.ID, stored.UpdatedAt.String()),
		Type:    "finding.created",
		Source:  module,
		HostID:  stored.HostID,
		Time:    stored.UpdatedAt,
		Payload: payload,
	})
}

// PublishEvent lets a module emit its own event type (e.g. M2 honey triggers).
func (a *API) PublishEvent(module, evType string, hostID string, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		a.Logger.Error("module event marshal failed", "module", module, "type", evType, "err", err)
		return
	}
	now := time.Now().UTC()
	a.Bus.Publish(model.Event{
		ID:      model.StableID("mod-ev", module, evType, now.String(), string(raw)),
		Type:    evType,
		Source:  module,
		HostID:  hostID,
		Time:    now,
		Payload: raw,
	})
}

// Runtime hosts registered modules and routes bus events to them.
type Runtime struct {
	api     *API
	modules []Module
	logger  *slog.Logger
}

// NewRuntime wires the runtime to the shared bus and store.
func NewRuntime(st *store.Store, b *bus.Bus, logger *slog.Logger) *Runtime {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runtime{
		api:    &API{Store: st, Bus: b, Logger: logger},
		logger: logger,
	}
}

// Register adds a module. Duplicate names are rejected.
func (r *Runtime) Register(m Module) error {
	for _, ex := range r.modules {
		if ex.Name() == m.Name() {
			return fmt.Errorf("module %q already registered", m.Name())
		}
	}
	r.modules = append(r.modules, m)
	for _, pattern := range m.Subscriptions() {
		mod, pat := m, pattern
		r.api.Bus.Subscribe(pat, func(ctx context.Context, ev model.Event) {
			if err := mod.Handle(ctx, ev, r.api); err != nil {
				r.logger.Error("module handler failed",
					"module", mod.Name(), "event", ev.Type, "err", err)
			}
		})
	}
	r.logger.Info("module registered", "module", m.Name(), "subscriptions", m.Subscriptions())
	return nil
}

// Modules returns names of registered modules (for /api/v1/modules).
func (r *Runtime) Modules() []string {
	out := make([]string, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m.Name())
	}
	return out
}

// API exposes the module API (used by server wiring, e.g. autodoc generation).
func (r *Runtime) API() *API { return r.api }
