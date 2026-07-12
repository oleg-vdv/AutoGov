package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules/autodoc"
	"github.com/oleg-vdv/autogov/internal/report"
)

// registerAPI wires the public REST API (ТЗ §4.1 Public API, §5.5).
// RBAC (ТЗ §9): viewer — inventory & findings; analyst — + reachability map
// (sensitive artifact) and finding status changes; admin — + whitelist,
// exports, audit log.
func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/summary", s.requireRole("viewer", s.apiSummary))
	mux.HandleFunc("/api/v1/hosts", s.requireRole("viewer", s.apiHosts))
	mux.HandleFunc("/api/v1/instances", s.requireRole("viewer", s.apiInstances))
	mux.HandleFunc("/api/v1/instances/", s.requireRole("viewer", s.apiInstanceDetail))
	mux.HandleFunc("/api/v1/findings", s.requireRole("viewer", s.apiFindings))
	mux.HandleFunc("/api/v1/findings/", s.requireRole("analyst", s.apiFindingAction))
	mux.HandleFunc("/api/v1/reachability", s.requireRole("analyst", s.apiReachability))
	mux.HandleFunc("/api/v1/whitelist", s.requireRole("admin", s.apiWhitelist))
	mux.HandleFunc("/api/v1/whitelist/", s.requireRole("admin", s.apiWhitelistDelete))
	mux.HandleFunc("/api/v1/reports/export", s.requireRole("admin", s.apiExport))
	mux.HandleFunc("/api/v1/audit", s.requireRole("admin", s.apiAudit))
	mux.HandleFunc("/api/v1/modules", s.requireRole("viewer", s.apiModules))
	mux.HandleFunc("/api/v1/docs/infra.md", s.requireRole("analyst", s.apiAutodoc))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	enc.Encode(v) //nolint:errcheck
}

func (s *Server) apiSummary(w http.ResponseWriter, _ *http.Request) {
	snap := report.Build(s.store)
	writeJSON(w, snap.Summary)
}

func (s *Server) apiHosts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.store.Hosts())
}

func (s *Server) apiInstances(w http.ResponseWriter, r *http.Request) {
	instances := s.store.Instances()
	if eng := r.URL.Query().Get("engine"); eng != "" {
		filtered := instances[:0]
		for _, in := range instances {
			if in.Engine == eng {
				filtered = append(filtered, in)
			}
		}
		instances = filtered
	}
	writeJSON(w, instances)
}

// apiInstanceDetail: GET /api/v1/instances/{id} — instance with workflows,
// credential refs and reachability edges (карта §5.3 per instance).
func (s *Server) apiInstanceDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/instances/")
	id = strings.TrimSuffix(id, "/")
	in, ok := s.store.Instance(id)
	if !ok {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}
	// Reachability inside the detail view is analyst+ (sensitive, ТЗ §9).
	_, role := s.roleOf(r)
	resp := map[string]any{
		"instance":  in,
		"workflows": s.store.WorkflowsByInstance(id),
	}
	if roleRank[role] >= roleRank["analyst"] {
		resp["credential_refs"] = s.store.CredentialRefsByInstance(id)
		resp["reachability"] = s.store.ReachabilityByInstance(id)
	}
	writeJSON(w, resp)
}

func (s *Server) apiFindings(w http.ResponseWriter, r *http.Request) {
	findings := s.store.Findings()
	if sev := r.URL.Query().Get("severity"); sev != "" {
		filtered := findings[:0]
		for _, f := range findings {
			if string(f.Severity) == sev {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	writeJSON(w, findings)
}

// apiFindingAction: POST /api/v1/findings/{id}/(ack|resolve|reopen)
func (s *Server) apiFindingAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/findings/")
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 {
		http.Error(w, "expected /api/v1/findings/{id}/{ack|resolve|reopen}", http.StatusBadRequest)
		return
	}
	id, action := parts[0], parts[1]
	var status model.FindingStatus
	switch action {
	case "ack":
		status = model.FindingAcked
	case "resolve":
		status = model.FindingResolved
	case "reopen":
		status = model.FindingNew
	default:
		http.Error(w, "unknown action "+action, http.StatusBadRequest)
		return
	}
	f, ok := s.store.SetFindingStatus(id, status)
	if !ok {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	writeJSON(w, f)
}

func (s *Server) apiReachability(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.store.Reachability())
}

// apiWhitelist: GET list, POST add rule (ТЗ §5.6).
func (s *Server) apiWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.store.WhitelistRules())
	case http.MethodPost:
		var rule model.WhitelistRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch rule.Kind {
		case "host", "image", "instance", "engine", "identity":
		default:
			http.Error(w, "kind must be one of host|image|instance|engine|identity", http.StatusBadRequest)
			return
		}
		if rule.Pattern == "" {
			http.Error(w, "pattern is required", http.StatusBadRequest)
			return
		}
		actor, _ := s.roleOf(r)
		rule.ID = model.StableID("wl", rule.Kind, rule.Pattern, time.Now().String())
		rule.CreatedBy = actor
		rule.CreatedAt = time.Now().UTC()
		s.store.AddWhitelistRule(&rule)
		s.applyWhitelist()
		writeJSON(w, rule)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiWhitelistDelete: DELETE /api/v1/whitelist/{id}
func (s *Server) apiWhitelistDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/whitelist/"), "/")
	if !s.store.DeleteWhitelistRule(id) {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	s.applyWhitelist()
	w.WriteHeader(http.StatusNoContent)
}

// applyWhitelist re-evaluates all instances against current rules so adding
// or removing a rule immediately mutes/unmutes findings (ТЗ §5.6).
func (s *Server) applyWhitelist() {
	for _, in := range s.store.Instances() {
		host, _ := s.store.Host(in.HostID)
		rule, matched := s.store.MatchWhitelist(in, host)
		if matched && !in.Whitelisted {
			s.store.SetInstanceWhitelisted(in.ID, true, rule.Reason)
			s.store.SetFindingStatus(model.StableID("finding", "m1-discovery", in.ID), model.FindingWhitelisted)
		} else if !matched && in.Whitelisted {
			s.store.SetInstanceWhitelisted(in.ID, false, "")
			s.store.SetFindingStatus(model.StableID("finding", "m1-discovery", in.ID), model.FindingNew)
		}
	}
}

// apiExport: GET /api/v1/reports/export?format=json|csv|pdf (ТЗ §5.5, §12 п.5).
func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	snap := report.Build(s.store)
	stamp := time.Now().UTC().Format("20060102-150405")
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="autogov-findings-%s.csv"`, stamp))
		report.WriteCSV(w, snap) //nolint:errcheck
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="autogov-report-%s.pdf"`, stamp))
		report.WritePDF(w, snap) //nolint:errcheck
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="autogov-report-%s.json"`, stamp))
		report.WriteJSON(w, snap) //nolint:errcheck
	}
}

func (s *Server) apiAudit(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.store.TailAudit(500))
}

func (s *Server) apiModules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.runtime.Modules())
}

// apiAutodoc serves the M4 stub's generated infrastructure map (ТЗ §6).
func (s *Server) apiAutodoc(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Write([]byte(autodoc.Generate(s.runtime.API()))) //nolint:errcheck
}
