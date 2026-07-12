// Package selfhealing is module M3 «Self-healing» (ТЗ §6, идея №27) —
// architectural stub proving the plugin contract (ТЗ-0).
//
// Contract: consumes workflow error events ("workflow.error", produced later
// via n8n Error Trigger integration), publishes "suggested fix" findings.
// Per ТЗ §6 the default mode is strictly "предлагаю, применяет человек":
// the module never applies patches itself.
package selfhealing

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules"
)

const ModuleName = "m3-selfhealing"

// ErrorEvent is the payload of "workflow.error".
type ErrorEvent struct {
	InstanceID   string `json:"instance_id"`
	WorkflowID   string `json:"workflow_id"`
	WorkflowName string `json:"workflow_name,omitempty"`
	Node         string `json:"node,omitempty"`
	Message      string `json:"message,omitempty"`
}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return ModuleName }

func (m *Module) Subscriptions() []string { return []string{"workflow.error"} }

func (m *Module) Handle(_ context.Context, ev model.Event, api *modules.API) error {
	var e ErrorEvent
	if err := json.Unmarshal(ev.Payload, &e); err != nil {
		return fmt.Errorf("workflow.error payload: %w", err)
	}
	api.PublishFinding(ModuleName, &model.Finding{
		ID:         model.StableID("finding", ModuleName, e.InstanceID, e.WorkflowID, e.Node),
		InstanceID: e.InstanceID,
		HostID:     ev.HostID,
		Title:      fmt.Sprintf("Сбой воркфлоу «%s» (нода %s)", e.WorkflowName, e.Node),
		Score:      40,
		Severity:   model.SeverityMedium,
		Explanation: fmt.Sprintf(
			"Воркфлоу «%s» упал на ноде «%s»: %s. Модуль self-healing подготовит предложение патча; "+
				"применение — только вручную инженером (режим «предлагаю, применяет человек»).",
			e.WorkflowName, e.Node, e.Message),
		ExplanationEN: fmt.Sprintf("Workflow %q failed at node %q: %s. A patch proposal ticket will be prepared; human applies.",
			e.WorkflowName, e.Node, e.Message),
		UpdatedAt: ev.Time,
	})
	return nil
}
