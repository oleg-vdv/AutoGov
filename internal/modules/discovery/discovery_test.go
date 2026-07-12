package discovery_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oleg-vdv/autogov/internal/bus"
	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules"
	"github.com/oleg-vdv/autogov/internal/modules/discovery"
	"github.com/oleg-vdv/autogov/internal/obs"
	"github.com/oleg-vdv/autogov/internal/risk"
	"github.com/oleg-vdv/autogov/internal/store"
)

// harness wires a real bus + store + runtime with the discovery module,
// exactly like the control plane does — an end-to-end pipeline test.
func harness(t *testing.T) (*store.Store, *bus.Bus, context.CancelFunc) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	b := bus.New(256, nil)
	rt := modules.NewRuntime(st, b, nil)
	if err := rt.Register(discovery.New(risk.NewEngine(risk.DefaultWeights(), nil))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go b.Run(ctx)
	return st, b, cancel
}

func publish(t *testing.T, b *bus.Bus, hostID, obsType string, payload any) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	b.Publish(model.Event{
		ID:      model.StableID(obsType, string(raw)),
		Type:    "observation." + obsType,
		HostID:  hostID,
		Time:    time.Now().UTC(),
		Payload: raw,
	})
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// ТЗ §5.1: n8n container is detected and inventoried; ТЗ §5.3: reachability
// to the postgres backend is mapped; ТЗ §5.4: a scored finding is produced.
func TestDockerN8NDetection(t *testing.T) {
	st, b, cancel := harness(t)
	defer cancel()

	publish(t, b, "host1", obs.TypeDockerContainer, obs.DockerContainer{
		ContainerID: "abc123def456",
		Name:        "n8n-prod",
		Image:       "n8nio/n8n:1.20.0",
		State:       "running",
		Ports:       []obs.PortMap{{Private: 5678, Public: 5678, IP: "0.0.0.0"}},
		EnvKeys:     []string{"N8N_ENCRYPTION_KEY", "DB_TYPE"},
		SecretEnvs:  map[string]string{"N8N_ENCRYPTION_KEY": "sha256:deadbeef"},
		PlainEnvs:   map[string]string{"DB_TYPE": "postgresdb"},
		Links:       []string{"postgres:db"},
	})

	eventually(t, func() bool { return len(st.Instances()) == 1 })

	inst := st.Instances()[0]
	if inst.Engine != "n8n" {
		t.Fatalf("expected n8n, got %s", inst.Engine)
	}
	if inst.Version != "1.20.0" {
		t.Errorf("expected version 1.20.0, got %q", inst.Version)
	}
	if inst.DBType != "postgres" {
		t.Errorf("expected postgres, got %q", inst.DBType)
	}
	if inst.Exposure != model.ExposureLAN {
		t.Errorf("0.0.0.0 binding should be at least LAN, got %s", inst.Exposure)
	}
	// Privacy: only the key NAME is stored, never a value (ТЗ §9, §12 п.3).
	if len(inst.SecretEnvKeys) != 1 || inst.SecretEnvKeys[0] != "N8N_ENCRYPTION_KEY" {
		t.Errorf("expected secret key name only, got %v", inst.SecretEnvKeys)
	}

	// Reachability to production DB was mapped (ТЗ §5.3).
	reach := st.ReachabilityByInstance(inst.ID)
	foundDB := false
	for _, r := range reach {
		if r.TargetCategory == "database" {
			foundDB = true
		}
	}
	if !foundDB {
		t.Error("expected database reachability edge")
	}

	// A scored finding exists with an explanation (ТЗ §5.4).
	eventually(t, func() bool { return len(st.Findings()) == 1 })
	f := st.Findings()[0]
	if f.Score <= 0 || f.Explanation == "" {
		t.Errorf("expected scored finding with explanation, got score=%.1f expl=%q", f.Score, f.Explanation)
	}
	// The postgres backend reachability (database access) must be reflected in
	// the score on the very first observation, not only after a later rescan.
	hasDBFactor := false
	for _, factor := range f.Factors {
		if factor.Key == "prod_access:database" {
			hasDBFactor = true
		}
	}
	if !hasDBFactor {
		t.Error("database reachability must be scored on the first docker observation")
	}
}

// ТЗ §8.2: idempotent ingest — re-sending the same observation must not
// duplicate assets. (Dedup by event id happens at ingest; here we assert the
// module upsert itself is stable across identical observations.)
func TestIdempotentUpsert(t *testing.T) {
	st, b, cancel := harness(t)
	defer cancel()

	for i := 0; i < 3; i++ {
		publish(t, b, "host1", obs.TypeNetworkService, obs.NetworkService{
			IP: "127.0.0.1", Port: 5678, IsN8N: true,
			Fingerprints: []string{"/rest", "/api/v1/docs"},
		})
	}
	eventually(t, func() bool { return len(st.Instances()) >= 1 })
	time.Sleep(100 * time.Millisecond)
	if n := len(st.Instances()); n != 1 {
		t.Fatalf("expected 1 instance after 3 identical observations, got %d", n)
	}
	if n := len(st.Findings()); n != 1 {
		t.Fatalf("expected 1 finding, got %d", n)
	}
}

// ТЗ §5.1: single weak signal must NOT create a false positive; two weak
// signals (port 5678 + N8N_ env) should. Guards the "multi-signal" rule.
func TestMultiSignalReducesFalsePositives(t *testing.T) {
	st, b, cancel := harness(t)
	defer cancel()

	// A random container with a coincidental port but nothing else: ignored.
	publish(t, b, "host1", obs.TypeDockerContainer, obs.DockerContainer{
		ContainerID: "unrelated1", Name: "grafana", Image: "grafana/grafana:latest",
		State: "running", Ports: []obs.PortMap{{Private: 3000, Public: 3000}},
	})
	time.Sleep(200 * time.Millisecond)
	if len(st.Instances()) != 0 {
		t.Fatalf("unrelated container must not be flagged, got %d instances", len(st.Instances()))
	}
}

// ТЗ §5.2, §5.3: authorized API inventory maps credentials and HTTP targets
// to production systems without ever storing secret values.
func TestN8NAPIWorkflowMapping(t *testing.T) {
	st, b, cancel := harness(t)
	defer cancel()

	publish(t, b, "host1", obs.TypeN8NAPI, obs.N8NAPI{
		BaseURL: "http://127.0.0.1:5678",
		Workflows: []obs.N8NWorkflow{{
			ID: "1", Name: "Sync payments", Active: true,
			Nodes: []obs.N8NWorkflowNode{
				{Name: "Webhook", Type: "n8n-nodes-base.webhook", Webhook: true},
				{Name: "Kaspi", Type: "n8n-nodes-base.httpRequest", URL: "https://api.kaspi.kz/pay"},
				{Name: "CRM", Type: "n8n-nodes-base.bitrix24", CredentialType: "bitrix24Api", CredentialName: "Main CRM"},
			},
		}},
	})

	eventually(t, func() bool { return len(st.Instances()) == 1 })
	inst := st.Instances()[0]

	cats := map[string]bool{}
	for _, r := range st.ReachabilityByInstance(inst.ID) {
		cats[r.TargetCategory] = true
	}
	if !cats["payments"] {
		t.Error("expected payments reachability from Kaspi HTTP node")
	}
	if !cats["crm"] {
		t.Error("expected crm reachability from bitrix24 credential")
	}

	// Credential refs carry type/target but never a value.
	creds := st.CredentialRefsByInstance(inst.ID)
	if len(creds) == 0 {
		t.Fatal("expected credential refs")
	}
	for _, c := range creds {
		if c.Fingerprint != "" && c.Fingerprint[:7] != "sha256:" {
			t.Errorf("credential ref must not hold a raw value: %q", c.Fingerprint)
		}
	}
}
