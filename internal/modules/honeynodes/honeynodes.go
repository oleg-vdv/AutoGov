// Package honeynodes is module M2 «HoneyNodes» (ТЗ §6, идея №21) —
// architectural stub proving the plugin contract (ТЗ-0).
//
// Contract: the module publishes honey triggers (fake nodes / API keys /
// decoy tables) and consumes access events. In the MVP it already handles
// "honeynode.access" events end-to-end: any touch of a decoy produces a
// critical "probable instance compromise" finding routed to SIEM via the
// standard notifier chain — no core changes were required to add it, which
// is exactly the platform invariant being demonstrated.
package honeynodes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules"
)

const ModuleName = "m2-honeynodes"

// AccessEvent is the payload of "honeynode.access".
type AccessEvent struct {
	InstanceID string `json:"instance_id,omitempty"`
	HoneyID    string `json:"honey_id"`
	Kind       string `json:"kind"` // node | api-key | decoy-table
	SourceIP   string `json:"source_ip,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return ModuleName }

func (m *Module) Subscriptions() []string { return []string{"honeynode.access"} }

func (m *Module) Handle(_ context.Context, ev model.Event, api *modules.API) error {
	var a AccessEvent
	if err := json.Unmarshal(ev.Payload, &a); err != nil {
		return fmt.Errorf("honeynode payload: %w", err)
	}
	now := time.Now().UTC()
	api.PublishFinding(ModuleName, &model.Finding{
		ID:         model.StableID("finding", ModuleName, a.HoneyID, a.SourceIP, now.Format(time.RFC3339)),
		InstanceID: a.InstanceID,
		HostID:     ev.HostID,
		Title:      fmt.Sprintf("Обращение к приманке %s (%s) — вероятная компрометация", a.HoneyID, a.Kind),
		Score:      95,
		Severity:   model.SeverityCritical,
		Explanation: fmt.Sprintf(
			"Зафиксировано обращение к honey-объекту «%s» типа %s с адреса %s. "+
				"Легитимные процессы никогда не обращаются к приманкам: вероятна компрометация инстанса. %s",
			a.HoneyID, a.Kind, a.SourceIP, a.Detail),
		ExplanationEN: fmt.Sprintf("Decoy %q (%s) was accessed from %s: probable instance compromise.",
			a.HoneyID, a.Kind, a.SourceIP),
		UpdatedAt: now,
	})
	return nil
}
