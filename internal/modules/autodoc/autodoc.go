// Package autodoc is module M4 «Автодокументация» (ТЗ §6, идея №29) —
// architectural stub proving the plugin contract (ТЗ-0).
//
// Contract: reads the Asset Store, publishes document artifacts. The MVP
// version generates an always-up-to-date Markdown map of instances,
// credentials and reachability on demand (exposed via the public API).
package autodoc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules"
	"github.com/oleg-vdv/autogov/internal/version"
)

const ModuleName = "m4-autodoc"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return ModuleName }

// The stub consumes nothing periodically yet; documentation is generated on
// demand. Subscribing to asset events is reserved for the streaming version.
func (m *Module) Subscriptions() []string { return []string{"asset.instance.created"} }

func (m *Module) Handle(_ context.Context, _ model.Event, _ *modules.API) error {
	return nil // streaming re-generation lands with the full M4
}

// Generate builds the Markdown infrastructure map from the Asset Store.
func Generate(api *modules.API) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Карта автоматизаций (%s v%s)\n\nСгенерировано: %s\n\n",
		version.Product, version.Version, time.Now().UTC().Format(time.RFC3339))

	hosts := api.Store.Hosts()
	instances := api.Store.Instances()
	fmt.Fprintf(&b, "Хостов: %d, инстансов: %d\n\n", len(hosts), len(instances))

	for _, h := range hosts {
		fmt.Fprintf(&b, "## Хост %s (%s)\n\n", h.Hostname, h.OS)
		for _, in := range instances {
			if in.HostID != h.ID {
				continue
			}
			fmt.Fprintf(&b, "### %s — %s\n\n", in.Engine, in.Identity)
			fmt.Fprintf(&b, "- Запуск: %s, статус: %s, доступность: %s\n", in.RunMode, in.Status, in.Exposure)
			if in.Version != "" {
				fmt.Fprintf(&b, "- Версия: %s\n", in.Version)
			}
			for _, wf := range api.Store.WorkflowsByInstance(in.ID) {
				fmt.Fprintf(&b, "- Воркфлоу «%s» (active=%v), ноды: %s\n", wf.Name, wf.Active, strings.Join(wf.Nodes, ", "))
			}
			for _, r := range api.Store.ReachabilityByInstance(in.ID) {
				fmt.Fprintf(&b, "- Доступ → %s [%s] через %s\n", r.TargetSystem, r.TargetCategory, r.Via)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
