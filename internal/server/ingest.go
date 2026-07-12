package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/obs"
)

// handleIngest accepts observation batches from agents (ТЗ §4.1 Ingest API).
// Idempotent: observations carry agent-generated IDs; duplicates from retries
// are dropped (ТЗ §8.2).
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAgentAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var batch obs.Batch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&batch); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if batch.AgentID == "" || batch.Host.Hostname == "" {
		http.Error(w, "agent_id and host.hostname are required", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	hostID := model.StableID("host", batch.Host.Hostname, batch.AgentID)
	s.store.UpsertHost(&model.Host{
		ID:           hostID,
		Hostname:     batch.Host.Hostname,
		OS:           batch.Host.OS,
		Kernel:       batch.Host.Kernel,
		IPs:          batch.Host.IPs,
		Labels:       batch.Host.Labels,
		AgentID:      batch.AgentID,
		AgentVersion: batch.AgentVersion,
		LastSeen:     now,
	})

	accepted, duplicates := 0, 0
	for _, o := range batch.Observations {
		if o.ID == "" || o.Type == "" {
			continue
		}
		if !s.store.MarkEventSeen(o.ID, now) {
			duplicates++
			continue
		}
		ev := model.Event{
			ID:      o.ID,
			Type:    "observation." + o.Type,
			Source:  batch.AgentID,
			HostID:  hostID,
			Time:    orNow(o.Time, now),
			Payload: o.Data,
		}
		s.store.AppendEventLog(ev) // raw observation audit trail (ТЗ §7 Event)
		s.bus.Publish(ev)
		accepted++
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"accepted":%d,"duplicates":%d}`, accepted, duplicates)
}

func orNow(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}
