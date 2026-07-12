// Package report builds inventory & risk reports (ТЗ §5.5, §12 п.5):
// JSON (full), CSV (findings) and a minimal self-contained PDF — generated
// entirely offline with no external services or libraries.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/store"
	"github.com/oleg-vdv/autogov/internal/version"
)

// Snapshot is the full report payload.
type Snapshot struct {
	Product      string                `json:"product"`
	Version      string                `json:"version"`
	GeneratedAt  time.Time             `json:"generated_at"`
	Summary      Summary               `json:"summary"`
	Hosts        []*model.Host         `json:"hosts"`
	Instances    []*model.Instance     `json:"instances"`
	Findings     []*model.Finding      `json:"findings"`
	Reachability []*model.Reachability `json:"reachability"`
}

// Summary is the dashboard header (ТЗ §5.5).
type Summary struct {
	Hosts       int            `json:"hosts"`
	Instances   int            `json:"instances"`
	Shadow      int            `json:"shadow_instances"` // non-whitelisted
	Whitelisted int            `json:"whitelisted"`
	BySeverity  map[string]int `json:"findings_by_severity"`
	NewLast24h  int            `json:"instances_new_last_24h"`
}

// Build assembles a snapshot from the store.
func Build(st *store.Store) Snapshot {
	now := time.Now().UTC()
	hosts := st.Hosts()
	instances := st.Instances()
	findings := st.Findings()

	sum := Summary{
		Hosts:      len(hosts),
		Instances:  len(instances),
		BySeverity: map[string]int{},
	}
	for _, in := range instances {
		if in.Whitelisted {
			sum.Whitelisted++
		} else {
			sum.Shadow++
		}
		if now.Sub(in.FirstSeen) < 24*time.Hour {
			sum.NewLast24h++
		}
	}
	for _, f := range findings {
		if f.Status == model.FindingWhitelisted || f.Status == model.FindingResolved {
			continue
		}
		sum.BySeverity[string(f.Severity)]++
	}
	return Snapshot{
		Product:      version.Product,
		Version:      version.Version,
		GeneratedAt:  now,
		Summary:      sum,
		Hosts:        hosts,
		Instances:    instances,
		Findings:     findings,
		Reachability: st.Reachability(),
	}
}

// WriteJSON emits the full snapshot.
func WriteJSON(w io.Writer, s Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// WriteCSV emits findings as CSV.
func WriteCSV(w io.Writer, s Snapshot) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"id", "module", "severity", "score", "status", "title", "instance_id", "host_id", "explanation"}); err != nil {
		return err
	}
	for _, f := range s.Findings {
		if err := cw.Write([]string{
			f.ID, f.Module, string(f.Severity), fmt.Sprintf("%.1f", f.Score),
			string(f.Status), f.Title, f.InstanceID, f.HostID, f.Explanation,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WritePDF emits a minimal PDF (Latin-1 text; Cyrillic is transliterated —
// the JSON report remains the machine-readable source of truth).
func WritePDF(w io.Writer, s Snapshot) error {
	var lines []string
	add := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	add("%s v%s — Shadow Automation Report", s.Product, s.Version)
	add("Generated: %s", s.GeneratedAt.Format(time.RFC3339))
	add("")
	add("Hosts: %d   Instances: %d   Shadow: %d   Whitelisted: %d",
		s.Summary.Hosts, s.Summary.Instances, s.Summary.Shadow, s.Summary.Whitelisted)
	add("Findings by severity: critical=%d high=%d medium=%d low=%d",
		s.Summary.BySeverity["critical"], s.Summary.BySeverity["high"],
		s.Summary.BySeverity["medium"], s.Summary.BySeverity["low"])
	add("")
	add("== Top findings ==")
	max := len(s.Findings)
	if max > 40 {
		max = 40
	}
	for _, f := range s.Findings[:max] {
		add("[%s %.0f] %s", strings.ToUpper(string(f.Severity)), f.Score, f.Title)
		for _, chunk := range wrap(f.ExplanationEN, 100) {
			add("    %s", chunk)
		}
	}
	add("")
	add("== Instances ==")
	for _, in := range s.Instances {
		wl := ""
		if in.Whitelisted {
			wl = " [whitelisted]"
		}
		add("%s | %s | run=%s | exposure=%s | v%s%s", in.Engine, in.Identity, in.RunMode, in.Exposure, orDash(in.Version), wl)
	}
	return writePDFLines(w, lines)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func wrap(s string, width int) []string {
	words := strings.Fields(s)
	var out []string
	cur := ""
	for _, w := range words {
		if len(cur)+len(w)+1 > width {
			out = append(out, cur)
			cur = w
			continue
		}
		if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
