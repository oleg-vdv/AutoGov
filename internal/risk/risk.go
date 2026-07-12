// Package risk implements the risk scoring engine (ТЗ §5.4).
//
// Every finding gets a numeric score, a category and a human-readable
// explanation in Russian and English. Explanations are template-based and
// generated fully locally: no external LLM calls, which keeps the on-prem
// mode free of cross-border transfers (ТЗ §3.3, §8.4).
package risk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/oleg-vdv/autogov/internal/model"
)

// Weights is the configurable scoring model (ТЗ §5.4 "пример весов, настраиваемый").
type Weights struct {
	// Base score for any shadow (non-whitelisted) automation instance.
	ShadowInstanceBase float64 `json:"shadow_instance_base"`
	// Access to production systems by target category.
	ProdAccess map[string]float64 `json:"prod_access"`
	// Network exposure of the instance.
	ExposurePublic    float64 `json:"exposure_public"`
	ExposureLAN       float64 `json:"exposure_lan"`
	ExposureLocalhost float64 `json:"exposure_localhost"`
	// Webhook triggers reachable from outside.
	WebhookExposed float64 `json:"webhook_exposed"`
	// Presence of live credentials (secret env keys / credential refs).
	CredentialPresent float64 `json:"credential_present"`
	// Multipliers.
	NonITOwnerMultiplier float64 `json:"non_it_owner_multiplier"`
	OutdatedMultiplier   float64 `json:"outdated_version_multiplier"`
}

// DefaultWeights per ТЗ §5.4.
func DefaultWeights() Weights {
	return Weights{
		ShadowInstanceBase: 15,
		ProdAccess: map[string]float64{
			"payments":  35,
			"erp_1c":    30,
			"database":  28,
			"crm":       20,
			"cloud":     15,
			"messaging": 8,
			"other":     5,
		},
		ExposurePublic:       25,
		ExposureLAN:          12,
		ExposureLocalhost:    0,
		WebhookExposed:       15,
		CredentialPresent:    10,
		NonITOwnerMultiplier: 1.3,
		OutdatedMultiplier:   1.25,
	}
}

// VulnRule is an offline vulnerability feed entry (no external calls; the
// feed file ships with the release and can be updated by the administrator).
type VulnRule struct {
	Engine     string `json:"engine"`
	MaxVersion string `json:"max_version_exclusive"` // versions below this are affected
	Advisory   string `json:"advisory"`
}

// Input collects everything the engine needs about one instance.
type Input struct {
	Instance     *model.Instance
	Host         *model.Host
	Reachability []*model.Reachability
	Credentials  []*model.CredentialRef
	Workflows    []*model.Workflow
}

// Result of scoring.
type Result struct {
	Score         float64
	Severity      model.Severity
	Factors       []model.RiskFactor
	Explanation   string // Russian, for the CISO report (ТЗ §5.4)
	ExplanationEN string
}

// Engine applies weights to inputs.
type Engine struct {
	W     Weights
	Vulns []VulnRule
}

func NewEngine(w Weights, vulns []VulnRule) *Engine {
	return &Engine{W: w, Vulns: vulns}
}

// Score evaluates one instance (the core M1 finding, ТЗ §5.4).
func (e *Engine) Score(in Input) Result {
	inst := in.Instance
	var factors []model.RiskFactor
	score := 0.0

	add := func(key string, w float64, detail string) {
		if w == 0 {
			return
		}
		score += w
		factors = append(factors, model.RiskFactor{Key: key, Weight: w, Detail: detail})
	}

	add("shadow_instance", e.W.ShadowInstanceBase,
		fmt.Sprintf("Неучтённый инстанс автоматизации (%s) вне ИТ-инвентаря", inst.Engine))

	// Production access via the reachability graph (ТЗ §5.3): highest value signal.
	seenCat := map[string]bool{}
	for _, r := range in.Reachability {
		if seenCat[r.TargetCategory] {
			continue
		}
		seenCat[r.TargetCategory] = true
		w := e.W.ProdAccess[r.TargetCategory]
		if w == 0 {
			w = e.W.ProdAccess["other"]
		}
		add("prod_access:"+r.TargetCategory, w,
			fmt.Sprintf("Доступ к системе категории «%s» (%s)", categoryRU(r.TargetCategory), r.TargetSystem))
	}

	switch inst.Exposure {
	case model.ExposurePublic:
		add("exposure_public", e.W.ExposurePublic, "Инстанс доступен из публичной сети")
	case model.ExposureLAN:
		add("exposure_lan", e.W.ExposureLAN, "Инстанс доступен из локальной сети (LAN)")
	case model.ExposureLocalhost:
		add("exposure_localhost", e.W.ExposureLocalhost, "Инстанс доступен только с localhost")
	}

	webhooks := 0
	for _, w := range in.Workflows {
		webhooks += len(w.WebhookTriggers)
	}
	if webhooks > 0 && inst.Exposure != model.ExposureLocalhost {
		add("webhook_exposed", e.W.WebhookExposed,
			fmt.Sprintf("Webhook-триггеры (%d), достижимые извне", webhooks))
	}

	if len(inst.SecretEnvKeys) > 0 || len(in.Credentials) > 0 {
		add("credential_present", e.W.CredentialPresent,
			fmt.Sprintf("Обнаружены боевые креды: %d env-секретов, %d credential-ссылок",
				len(inst.SecretEnvKeys), len(in.Credentials)))
	}

	// Multipliers (ТЗ §5.4 "повышающий коэффициент").
	if !inst.OwnerIsIT && inst.Owner != "" && inst.Owner != "root" {
		old := score
		score *= e.W.NonITOwnerMultiplier
		factors = append(factors, model.RiskFactor{
			Key: "non_it_owner", Weight: score - old,
			Detail: fmt.Sprintf("Владелец «%s» вне ИТ-инвентаря (коэффициент ×%.2f)", inst.Owner, e.W.NonITOwnerMultiplier),
		})
	}
	if adv := e.matchVuln(inst); adv != "" {
		old := score
		score *= e.W.OutdatedMultiplier
		factors = append(factors, model.RiskFactor{
			Key: "outdated_version", Weight: score - old,
			Detail: fmt.Sprintf("Устаревшая версия %s (%s): %s (коэффициент ×%.2f)",
				inst.Engine, inst.Version, adv, e.W.OutdatedMultiplier),
		})
	}

	if score > 100 {
		score = 100
	}
	sev := model.SeverityFromScore(score)

	return Result{
		Score:         round1(score),
		Severity:      sev,
		Factors:       factors,
		Explanation:   explainRU(inst, factors, score, sev),
		ExplanationEN: explainEN(inst, factors, score, sev),
	}
}

func (e *Engine) matchVuln(inst *model.Instance) string {
	if inst.Version == "" {
		return ""
	}
	for _, v := range e.Vulns {
		if v.Engine == inst.Engine && CompareVersions(inst.Version, v.MaxVersion) < 0 {
			return v.Advisory
		}
	}
	return ""
}

// explainRU builds the natural-language explanation required by ТЗ §5.4.
func explainRU(inst *model.Instance, factors []model.RiskFactor, score float64, sev model.Severity) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Риск %.0f/100 (%s). ", score, severityRU(sev))
	fmt.Fprintf(&b, "Обнаружен инстанс «%s» (%s, запуск: %s)", inst.Engine, inst.Identity, orUnknown(inst.RunMode))
	if inst.Version != "" {
		fmt.Fprintf(&b, " версии %s", inst.Version)
	}
	b.WriteString(". Почему такой скор: ")
	parts := make([]string, 0, len(factors))
	for _, f := range factors {
		parts = append(parts, fmt.Sprintf("%s (+%.0f)", f.Detail, f.Weight))
	}
	b.WriteString(strings.Join(parts, "; "))
	b.WriteString(".")
	if sev == model.SeverityCritical || sev == model.SeverityHigh {
		b.WriteString(" Рекомендация: подтвердить владельца, перевести инстанс под контроль ИТ или отключить, ротировать затронутые креды.")
	}
	return b.String()
}

func explainEN(inst *model.Instance, factors []model.RiskFactor, score float64, sev model.Severity) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Risk %.0f/100 (%s). Shadow automation instance %q (%s", score, sev, inst.Engine, inst.Identity)
	if inst.Version != "" {
		fmt.Fprintf(&b, ", v%s", inst.Version)
	}
	b.WriteString("). Factors: ")
	parts := make([]string, 0, len(factors))
	for _, f := range factors {
		parts = append(parts, fmt.Sprintf("%s (+%.0f)", f.Key, f.Weight))
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString(".")
	return b.String()
}

func severityRU(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "критический"
	case model.SeverityHigh:
		return "высокий"
	case model.SeverityMedium:
		return "средний"
	case model.SeverityLow:
		return "низкий"
	default:
		return "информационный"
	}
}

func categoryRU(c string) string {
	m := map[string]string{
		"erp_1c": "1С/ERP", "payments": "платёжные системы", "database": "базы данных",
		"crm": "CRM", "cloud": "облачные сервисы", "messaging": "мессенджеры", "other": "прочее",
	}
	if v, ok := m[c]; ok {
		return v
	}
	return c
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// CompareVersions compares dotted numeric versions: -1, 0, 1.
func CompareVersions(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVer(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n := 0
		for _, ch := range f {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		out = append(out, n)
	}
	return out
}

// SortFactors orders factors by weight descending (stable output for reports).
func SortFactors(fs []model.RiskFactor) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Weight > fs[j].Weight })
}
