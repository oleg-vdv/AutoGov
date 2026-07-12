package store

import (
	"testing"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
)

func TestMarkEventSeenIdempotent(t *testing.T) {
	s, _ := Open("")
	now := time.Now()
	if !s.MarkEventSeen("e1", now) {
		t.Fatal("first sighting should return true")
	}
	if s.MarkEventSeen("e1", now) {
		t.Fatal("duplicate must return false (ТЗ §8.2)")
	}
}

func TestInstanceMergeAccumulatesSignals(t *testing.T) {
	s, _ := Open("")
	base := &model.Instance{
		ID: "i1", HostID: "h1", Engine: "n8n", Exposure: model.ExposureLocalhost,
		DetectedBy: []string{"process"}, Confidence: 0.6, LastSeen: time.Now(),
	}
	if _, created := s.UpsertInstance(base); !created {
		t.Fatal("first upsert should create")
	}
	// A second detector corroborates and raises exposure.
	second := &model.Instance{
		ID: "i1", HostID: "h1", Engine: "n8n", Exposure: model.ExposurePublic,
		DetectedBy: []string{"network"}, Confidence: 0.9, LastSeen: time.Now(),
	}
	merged, created := s.UpsertInstance(second)
	if created {
		t.Fatal("second upsert should merge, not create")
	}
	if len(merged.DetectedBy) != 2 {
		t.Errorf("expected 2 corroborating detectors, got %v", merged.DetectedBy)
	}
	if merged.Exposure != model.ExposurePublic {
		t.Errorf("exposure should escalate to public, got %s", merged.Exposure)
	}
	if merged.Confidence != 0.9 {
		t.Errorf("confidence should take the max, got %.2f", merged.Confidence)
	}
}

func TestWhitelistGlobMatch(t *testing.T) {
	s, _ := Open("")
	s.AddWhitelistRule(&model.WhitelistRule{
		ID: "w1", Kind: "image", Pattern: "ci/*", Reason: "sanctioned CI",
	})
	in := &model.Instance{Image: "ci/runner:latest", Engine: "n8n"}
	if _, ok := s.MatchWhitelist(in, nil); !ok {
		t.Error("ci/runner should match ci/* rule")
	}
	other := &model.Instance{Image: "prod/n8n:1.0", Engine: "n8n"}
	if _, ok := s.MatchWhitelist(other, nil); ok {
		t.Error("prod image should not match ci/* rule")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s1.UpsertInstance(&model.Instance{ID: "i1", Engine: "n8n", LastSeen: time.Now()})
	if err := s1.Flush(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Instance("i1"); !ok {
		t.Fatal("instance did not survive reload")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"ci/*", "ci/runner", true},
		{"ci/*", "prod/x", false},
		{"n8n-?", "n8n-1", true},
		{"n8n-?", "n8n-12", false},
		{"exact", "exact", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pattern, c.s, got, c.want)
		}
	}
}
