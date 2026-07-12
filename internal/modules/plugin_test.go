package modules_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oleg-vdv/autogov/internal/bus"
	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules"
	"github.com/oleg-vdv/autogov/internal/modules/honeynodes"
	"github.com/oleg-vdv/autogov/internal/store"
)

// TestPluginContract proves ТЗ-0: M2 (HoneyNodes) plugs into the SAME bus +
// store + runtime as M1, with no core changes — it only subscribes to an
// event type and publishes a finding. If this compiles and passes, the
// platform invariant "M2–M4 встают как плагины" holds for the MVP core.
func TestHoneyNodesPluginProducesFinding(t *testing.T) {
	st, _ := store.Open("")
	b := bus.New(64, nil)
	rt := modules.NewRuntime(st, b, nil)
	if err := rt.Register(honeynodes.New()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	raw, _ := json.Marshal(honeynodes.AccessEvent{
		InstanceID: "inst1", HoneyID: "decoy-crm-key", Kind: "api-key", SourceIP: "10.0.0.9",
	})
	b.Publish(model.Event{ID: "e1", Type: "honeynode.access", HostID: "host1", Time: time.Now(), Payload: raw})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(st.Findings()) == 1 {
			f := st.Findings()[0]
			if f.Severity != model.SeverityCritical {
				t.Fatalf("honeynode access must be critical, got %s", f.Severity)
			}
			if f.Module != honeynodes.ModuleName {
				t.Fatalf("finding module = %s", f.Module)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("honeynodes module did not produce a finding")
}

// TestDuplicateModuleRejected: the runtime enforces unique module names.
func TestDuplicateModuleRejected(t *testing.T) {
	st, _ := store.Open("")
	b := bus.New(8, nil)
	rt := modules.NewRuntime(st, b, nil)
	if err := rt.Register(honeynodes.New()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Register(honeynodes.New()); err == nil {
		t.Fatal("expected duplicate module registration to fail")
	}
}
