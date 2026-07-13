// Package store is the embedded asset/findings store of the control plane.
//
// Implementation note: pure stdlib, JSON snapshot with atomic writes plus an
// append-only JSONL audit/event log. No external DB is required, which keeps
// the on-prem / air-gapped install to a single container (ТЗ §8.4, §10).
// The Store interface surface is small so a SQL-backed implementation can be
// swapped in later without touching modules.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
)

type data struct {
	Hosts      map[string]*model.Host          `json:"hosts"`
	Instances  map[string]*model.Instance      `json:"instances"`
	Workflows  map[string]*model.Workflow      `json:"workflows"`
	Creds      map[string]*model.CredentialRef `json:"credential_refs"`
	Reach      map[string]*model.Reachability  `json:"reachability"`
	Findings   map[string]*model.Finding       `json:"findings"`
	Whitelist  map[string]*model.WhitelistRule `json:"whitelist"`
	SeenEvents map[string]time.Time            `json:"seen_events"`
}

func newData() data {
	return data{
		Hosts:      map[string]*model.Host{},
		Instances:  map[string]*model.Instance{},
		Workflows:  map[string]*model.Workflow{},
		Creds:      map[string]*model.CredentialRef{},
		Reach:      map[string]*model.Reachability{},
		Findings:   map[string]*model.Finding{},
		Whitelist:  map[string]*model.WhitelistRule{},
		SeenEvents: map[string]time.Time{},
	}
}

// Store is a concurrency-safe persistent store.
type Store struct {
	mu    sync.RWMutex
	d     data
	path  string // snapshot file; empty = in-memory (tests)
	dirty bool

	auditMu   sync.Mutex
	auditPath string
	eventPath string
}

// Open loads (or initializes) a store in dir. Empty dir = in-memory.
func Open(dir string) (*Store, error) {
	s := &Store{d: newData()}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s.path = filepath.Join(dir, "state.json")
	s.auditPath = filepath.Join(dir, "audit.jsonl")
	s.eventPath = filepath.Join(dir, "events.jsonl")
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.d); err != nil {
		return nil, fmt.Errorf("corrupt state file %s: %w", s.path, err)
	}
	return s, nil
}

// Flush persists the snapshot atomically if dirty.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" || !s.dirty {
		return nil
	}
	raw, err := json.MarshalIndent(&s.d, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// RunAutoFlush periodically flushes until stop is closed.
func (s *Store) RunAutoFlush(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			s.Flush() //nolint:errcheck // best effort on shutdown
			return
		case <-t.C:
			s.Flush() //nolint:errcheck // logged by caller on final flush
		}
	}
}

// --- Idempotency (ТЗ §8.2) ---

// MarkEventSeen returns false if the event id was already ingested.
func (s *Store) MarkEventSeen(id string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.d.SeenEvents[id]; ok {
		return false
	}
	s.d.SeenEvents[id] = at
	s.dirty = true
	// Cheap pruning: keep the dedup window bounded.
	if len(s.d.SeenEvents) > 200000 {
		cutoff := at.Add(-24 * time.Hour)
		for k, v := range s.d.SeenEvents {
			if v.Before(cutoff) {
				delete(s.d.SeenEvents, k)
			}
		}
	}
	return true
}

// --- Hosts ---

func (s *Store) UpsertHost(h *model.Host) *model.Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.d.Hosts[h.ID]
	if ok {
		existing.Hostname = h.Hostname
		existing.OS = h.OS
		existing.Kernel = h.Kernel
		existing.IPs = h.IPs
		existing.AgentID = h.AgentID
		existing.AgentVersion = h.AgentVersion
		existing.LastSeen = h.LastSeen
		if h.Labels != nil {
			existing.Labels = h.Labels
		}
		s.dirty = true
		return existing
	}
	if h.FirstSeen.IsZero() {
		h.FirstSeen = h.LastSeen
	}
	cp := *h
	s.d.Hosts[h.ID] = &cp
	s.dirty = true
	return &cp
}

func (s *Store) Host(id string) (*model.Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.d.Hosts[id]
	if !ok {
		return nil, false
	}
	cp := *h
	return &cp, true
}

func (s *Store) Hosts() []*model.Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Host, 0, len(s.d.Hosts))
	for _, h := range s.d.Hosts {
		cp := *h
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// --- Instances ---

// UpsertInstance merges by ID and reports whether the asset is new.
func (s *Store) UpsertInstance(in *model.Instance) (merged *model.Instance, created bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.d.Instances[in.ID]
	if !ok {
		if in.FirstSeen.IsZero() {
			in.FirstSeen = in.LastSeen
		}
		cp := *in
		s.d.Instances[in.ID] = &cp
		s.dirty = true
		out := cp
		return &out, true
	}
	// Merge: new observation refreshes state, corroborating detectors accumulate.
	existing.LastSeen = in.LastSeen
	if in.Version != "" {
		existing.Version = in.Version
	}
	if in.Status != "" {
		existing.Status = in.Status
	}
	if in.Exposure != model.ExposureUnknown && in.Exposure != "" {
		existing.Exposure = maxExposure(existing.Exposure, in.Exposure)
	}
	if in.DBType != "" {
		existing.DBType = in.DBType
	}
	if in.QueueMode {
		existing.QueueMode = true
	}
	if in.Owner != "" {
		existing.Owner = in.Owner
	}
	if in.Image != "" {
		existing.Image = in.Image
	}
	if in.RunMode != "" {
		existing.RunMode = in.RunMode
	}
	existing.Ports = unionInts(existing.Ports, in.Ports)
	existing.PublicPorts = unionInts(existing.PublicPorts, in.PublicPorts)
	existing.SecretEnvKeys = unionStrs(existing.SecretEnvKeys, in.SecretEnvKeys)
	existing.DetectedBy = unionStrs(existing.DetectedBy, in.DetectedBy)
	if in.Confidence > existing.Confidence {
		existing.Confidence = in.Confidence
	}
	s.dirty = true
	out := *existing
	return &out, false
}

func (s *Store) Instance(id string) (*model.Instance, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	in, ok := s.d.Instances[id]
	if !ok {
		return nil, false
	}
	cp := *in
	return &cp, true
}

func (s *Store) Instances() []*model.Instance {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Instance, 0, len(s.d.Instances))
	for _, in := range s.d.Instances {
		cp := *in
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.After(out[j].FirstSeen) })
	return out
}

// SetInstanceWhitelisted flips the flag and returns the updated instance.
func (s *Store) SetInstanceWhitelisted(id string, wl bool, reason string) (*model.Instance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.d.Instances[id]
	if !ok {
		return nil, false
	}
	in.Whitelisted = wl
	in.WhitelistReason = reason
	s.dirty = true
	cp := *in
	return &cp, true
}

// --- Workflows / Credentials / Reachability ---

func (s *Store) UpsertWorkflow(w *model.Workflow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *w
	s.d.Workflows[w.ID] = &cp
	s.dirty = true
}

func (s *Store) WorkflowsByInstance(instanceID string) []*model.Workflow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*model.Workflow
	for _, w := range s.d.Workflows {
		if w.InstanceID == instanceID {
			cp := *w
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) UpsertCredentialRef(c *model.CredentialRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.d.Creds[c.ID] = &cp
	s.dirty = true
}

func (s *Store) CredentialRefsByInstance(instanceID string) []*model.CredentialRef {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*model.CredentialRef
	for _, c := range s.d.Creds {
		if c.InstanceID == instanceID {
			cp := *c
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) UpsertReachability(r *model.Reachability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *r
	s.d.Reach[r.ID] = &cp
	s.dirty = true
}

func (s *Store) Reachability() []*model.Reachability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Reachability, 0, len(s.d.Reach))
	for _, r := range s.d.Reach {
		cp := *r
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) ReachabilityByInstance(instanceID string) []*model.Reachability {
	var out []*model.Reachability
	for _, r := range s.Reachability() {
		if r.InstanceID == instanceID {
			out = append(out, r)
		}
	}
	return out
}

// --- Findings ---

// UpsertFinding stores a finding; returns (stored, changed) where changed
// means new finding or severity/score materially updated (worth notifying).
func (s *Store) UpsertFinding(f *model.Finding) (*model.Finding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.d.Findings[f.ID]
	if !ok {
		if f.CreatedAt.IsZero() {
			f.CreatedAt = f.UpdatedAt
		}
		if f.Status == "" {
			f.Status = model.FindingNew
		}
		cp := *f
		s.d.Findings[f.ID] = &cp
		s.dirty = true
		out := cp
		return &out, true
	}
	changed := existing.Severity != f.Severity
	existing.Score = f.Score
	existing.Severity = f.Severity
	existing.Title = f.Title
	existing.TitleEN = f.TitleEN
	existing.Factors = f.Factors
	existing.Explanation = f.Explanation
	existing.ExplanationEN = f.ExplanationEN
	existing.UpdatedAt = f.UpdatedAt
	// Whitelisting downgrades notification but resolved findings can reopen.
	if f.Status == model.FindingWhitelisted || existing.Status == model.FindingWhitelisted {
		existing.Status = f.Status
		changed = false
	}
	s.dirty = true
	out := *existing
	return &out, changed
}

func (s *Store) Finding(id string) (*model.Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.d.Findings[id]
	if !ok {
		return nil, false
	}
	cp := *f
	return &cp, true
}

func (s *Store) SetFindingStatus(id string, st model.FindingStatus) (*model.Finding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.d.Findings[id]
	if !ok {
		return nil, false
	}
	f.Status = st
	f.UpdatedAt = time.Now().UTC()
	s.dirty = true
	cp := *f
	return &cp, true
}

func (s *Store) Findings() []*model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Finding, 0, len(s.d.Findings))
	for _, f := range s.d.Findings {
		cp := *f
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// --- Whitelist rules (ТЗ §5.6) ---

func (s *Store) AddWhitelistRule(r *model.WhitelistRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *r
	s.d.Whitelist[r.ID] = &cp
	s.dirty = true
}

func (s *Store) DeleteWhitelistRule(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.d.Whitelist[id]; !ok {
		return false
	}
	delete(s.d.Whitelist, id)
	s.dirty = true
	return true
}

func (s *Store) WhitelistRules() []*model.WhitelistRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.WhitelistRule, 0, len(s.d.Whitelist))
	for _, r := range s.d.Whitelist {
		cp := *r
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// MatchWhitelist checks an instance against all rules.
func (s *Store) MatchWhitelist(in *model.Instance, host *model.Host) (*model.WhitelistRule, bool) {
	for _, r := range s.WhitelistRules() {
		var subject string
		switch r.Kind {
		case "host":
			if host != nil {
				subject = host.Hostname
			}
		case "image":
			subject = in.Image
		case "instance":
			subject = in.ID
		case "engine":
			subject = in.Engine
		case "identity":
			subject = in.Identity
		default:
			continue
		}
		if subject != "" && globMatch(r.Pattern, subject) {
			return r, true
		}
	}
	return nil, false
}

// --- Audit & event log (append-only JSONL, ТЗ §9) ---

func (s *Store) AppendAudit(e model.AuditEntry) {
	s.appendJSONL(s.auditPath, e)
}

func (s *Store) AppendEventLog(ev model.Event) {
	s.appendJSONL(s.eventPath, ev)
}

func (s *Store) appendJSONL(path string, v any) {
	if path == "" {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	f.Write(append(raw, '\n')) //nolint:errcheck // best-effort audit trail
}

// TailAudit returns up to n last audit entries.
func (s *Store) TailAudit(n int) []model.AuditEntry {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	raw, err := os.ReadFile(s.auditPath)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]model.AuditEntry, 0, len(lines))
	for _, l := range lines {
		var e model.AuditEntry
		if json.Unmarshal([]byte(l), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// --- helpers ---

func maxExposure(a, b model.Exposure) model.Exposure {
	rank := map[model.Exposure]int{
		model.ExposureUnknown: 0, model.ExposureLocalhost: 1,
		model.ExposureLAN: 2, model.ExposurePublic: 3,
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func unionInts(a, b []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range append(a, b...) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

func unionStrs(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range append(a, b...) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// globMatch supports '*' (any run) and '?' (any char).
func globMatch(pattern, s string) bool {
	return globMatchImpl(pattern, s)
}

func globMatchImpl(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			p = strings.TrimLeft(p, "*")
			if p == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatchImpl(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if s == "" || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return s == ""
}
