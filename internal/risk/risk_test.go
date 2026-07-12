package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
)

func TestScoreProductionAccessIsCritical(t *testing.T) {
	e := NewEngine(DefaultWeights(), nil)
	res := e.Score(Input{
		Instance: &model.Instance{
			Engine: "n8n", Identity: "http://10.0.0.5:5678", Exposure: model.ExposurePublic,
			Owner: "accountant", SecretEnvKeys: []string{"N8N_ENCRYPTION_KEY"},
			Version: "1.20.0",
		},
		Reachability: []*model.Reachability{
			{TargetSystem: "Kaspi Pay", TargetCategory: "payments"},
			{TargetSystem: "1C:Enterprise", TargetCategory: "erp_1c"},
		},
	})
	// Public exposure + payments + 1C + non-IT owner → must be critical (ТЗ §5.4).
	if res.Severity != model.SeverityCritical {
		t.Fatalf("expected critical, got %s (score %.1f)", res.Severity, res.Score)
	}
	if res.Explanation == "" {
		t.Error("finding must carry a natural-language explanation (ТЗ §5.4)")
	}
	if !strings.Contains(res.Explanation, "платёжные") && !strings.Contains(res.Explanation, "1С") {
		t.Errorf("explanation should mention target systems: %q", res.Explanation)
	}
}

func TestScoreLocalhostOnlyLowerThanPublic(t *testing.T) {
	e := NewEngine(DefaultWeights(), nil)
	base := &model.Instance{Engine: "n8n", Owner: "root"}
	local := *base
	local.Exposure = model.ExposureLocalhost
	pub := *base
	pub.Exposure = model.ExposurePublic

	rl := e.Score(Input{Instance: &local})
	rp := e.Score(Input{Instance: &pub})
	if rp.Score <= rl.Score {
		t.Errorf("public (%.1f) must score higher than localhost (%.1f)", rp.Score, rl.Score)
	}
}

func TestOutdatedVersionMultiplier(t *testing.T) {
	vulns := []VulnRule{{Engine: "n8n", MaxVersion: "1.30.0", Advisory: "CVE-TEST"}}
	e := NewEngine(DefaultWeights(), vulns)
	old := e.Score(Input{Instance: &model.Instance{Engine: "n8n", Version: "1.10.0", Exposure: model.ExposureLAN}})
	newer := e.Score(Input{Instance: &model.Instance{Engine: "n8n", Version: "1.40.0", Exposure: model.ExposureLAN}})
	if old.Score <= newer.Score {
		t.Errorf("outdated version should raise score: old=%.1f new=%.1f", old.Score, newer.Score)
	}
	found := false
	for _, f := range old.Factors {
		if f.Key == "outdated_version" {
			found = true
		}
	}
	if !found {
		t.Error("expected outdated_version factor")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.10.0", -1},
		{"1.10.0", "1.2.0", 1},
		{"1.2.3", "1.2.3", 0},
		{"v1.0", "1.0.0", 0},
		{"1.30.0-rc1", "1.30.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSeverityBoundaries(t *testing.T) {
	_ = time.Now
	cases := []struct {
		score float64
		want  model.Severity
	}{
		{85, model.SeverityCritical},
		{60, model.SeverityHigh},
		{35, model.SeverityMedium},
		{10, model.SeverityLow},
		{0, model.SeverityInfo},
	}
	for _, c := range cases {
		if got := model.SeverityFromScore(c.score); got != c.want {
			t.Errorf("SeverityFromScore(%.0f)=%s want %s", c.score, got, c.want)
		}
	}
}
