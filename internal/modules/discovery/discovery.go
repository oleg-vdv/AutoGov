// Package discovery is module M1 «Обнаружение» (ТЗ §5) — the MVP vertical
// slice over the platform core. It consumes raw observations from agents,
// correlates multi-signal n8n detection (ТЗ §5.1: never a single signal),
// maintains the asset inventory (§5.2), builds the "instance → credentials →
// target systems" reachability map (§5.3) and publishes risk-scored findings
// with local natural-language explanations (§5.4).
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules"
	"github.com/oleg-vdv/autogov/internal/obs"
	"github.com/oleg-vdv/autogov/internal/risk"
)

const ModuleName = "m1-discovery"

// Module implements modules.Module.
type Module struct {
	engine *risk.Engine
}

func New(engine *risk.Engine) *Module { return &Module{engine: engine} }

func (m *Module) Name() string { return ModuleName }

// Subscriptions: all raw observations from agents.
func (m *Module) Subscriptions() []string { return []string{"observation.*"} }

func (m *Module) Handle(ctx context.Context, ev model.Event, api *modules.API) error {
	kind := strings.TrimPrefix(ev.Type, "observation.")
	switch kind {
	case obs.TypeDockerContainer:
		return m.handleDocker(ev, api)
	case obs.TypeProcess:
		return m.handleProcess(ev, api)
	case obs.TypeFSArtifact:
		return m.handleFS(ev, api)
	case obs.TypeCronEntry:
		return m.handleCron(ev, api)
	case obs.TypeNetworkService:
		return m.handleNetwork(ev, api)
	case obs.TypeN8NAPI:
		return m.handleN8NAPI(ev, api)
	default:
		return nil // unknown observation kinds are ignored, not errors
	}
}

// --- Docker (ТЗ §5.1 п.1) ---

func (m *Module) handleDocker(ev model.Event, api *modules.API) error {
	var c obs.DockerContainer
	if err := json.Unmarshal(ev.Payload, &c); err != nil {
		return fmt.Errorf("docker payload: %w", err)
	}

	// Multi-signal n8n detection: image is a strong signal; port 5678,
	// N8N_* env and postgres/redis links are weak signals needing >=2.
	strong := 0
	weak := 0
	img := strings.ToLower(c.Image)
	if strings.Contains(img, "n8nio/n8n") || strings.Contains(img, "docker.n8n.io") ||
		img == "n8n" || strings.HasPrefix(img, "n8n:") {
		strong++
	}
	hasPort5678 := false
	for _, p := range c.Ports {
		if p.Private == 5678 || p.Public == 5678 {
			hasPort5678 = true
		}
	}
	if hasPort5678 {
		weak++
	}
	n8nEnv := false
	for _, k := range c.EnvKeys {
		if strings.HasPrefix(k, "N8N_") || k == "WEBHOOK_URL" || k == "DB_TYPE" {
			n8nEnv = true
		}
	}
	if n8nEnv {
		weak++
	}
	queueMode := false
	for _, l := range c.Links {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "redis") {
			queueMode = true
			weak++
		}
		if strings.Contains(ll, "postgres") {
			weak++
		}
	}

	isN8N := strong >= 1 || weak >= 2
	engine := "unknown"
	confidence := 0.0
	switch {
	case strong >= 1 && weak >= 1:
		engine, confidence = "n8n", 0.99
	case strong >= 1:
		engine, confidence = "n8n", 0.9
	case weak >= 2:
		engine, confidence = "n8n", 0.7
	}
	if !isN8N {
		// Generic automation container heuristics (ТЗ §3.1): runner images.
		if looksLikeAutomationImage(img) {
			engine, confidence = "script-runner", 0.5
		} else {
			return nil // not an automation — no asset, keeps false positives down (§5.6)
		}
	}

	exposure := model.ExposureLocalhost
	var pubPorts []int
	for _, p := range c.Ports {
		if p.Public == 0 {
			continue
		}
		switch {
		case p.IP == "127.0.0.1" || p.IP == "::1":
			// stays localhost
		case p.IP == "" || p.IP == "0.0.0.0" || p.IP == "::":
			exposure = model.ExposureLAN // bound to all interfaces: at least LAN
			pubPorts = append(pubPorts, p.Public)
		default:
			exposure = model.ExposureLAN
			pubPorts = append(pubPorts, p.Public)
		}
	}

	dbType := "sqlite" // n8n default (ТЗ §5.1 п.4)
	if v := c.PlainEnvs["DB_TYPE"]; v != "" {
		if strings.Contains(v, "postgres") {
			dbType = "postgres"
		} else {
			dbType = v
		}
	}
	version := ""
	if i := strings.LastIndex(c.Image, ":"); i > 0 && !strings.Contains(c.Image[i+1:], "/") {
		if tag := c.Image[i+1:]; tag != "latest" {
			version = tag
		}
	}

	var secretKeys []string
	for k := range c.SecretEnvs {
		secretKeys = append(secretKeys, k)
	}

	inst := &model.Instance{
		ID:            model.StableID(ev.HostID, engine, c.ContainerID),
		HostID:        ev.HostID,
		Engine:        engine,
		Identity:      "container:" + shortID(c.ContainerID) + " (" + c.Name + ")",
		Version:       version,
		RunMode:       "docker",
		Status:        containerStatus(c.State),
		Exposure:      exposure,
		DBType:        dbType,
		QueueMode:     queueMode,
		Image:         c.Image,
		Ports:         privatePorts(c.Ports),
		PublicPorts:   pubPorts,
		SecretEnvKeys: secretKeys,
		DetectedBy:    []string{"docker"},
		Confidence:    confidence,
		LastSeen:      ev.Time,
	}

	// Reachability from env fingerprints must be recorded BEFORE scoring so the
	// finding reflects production access (§5.3). inst.ID is deterministic, so
	// the edges attach to the same instance the upsert will store.
	instID := inst.ID
	if dbType == "postgres" {
		m.addReachability(api, instID, "postgres (n8n backend)", "database", "env", ev.Time)
	}
	for _, k := range secretKeys {
		if sys, cat := classifyEnvTarget(k); cat != "" {
			m.addReachability(api, instID, sys, cat, "env", ev.Time)
			m.addCredentialRef(api, instID, "env:"+k, k, sys, cat, c.SecretEnvs[k], ev)
		}
	}

	m.upsertAndScore(api, inst)
	return nil
}

// --- Processes (ТЗ §5.1 п.2) ---

func (m *Module) handleProcess(ev model.Event, api *modules.API) error {
	var p obs.Process
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("process payload: %w", err)
	}
	engine := ""
	confidence := 0.6
	switch p.Signature {
	case "n8n":
		engine, confidence = "n8n", 0.85
	case "node-automation":
		engine = "node-script"
	case "python-runner":
		engine = "python-runner"
	default:
		return nil
	}
	inst := &model.Instance{
		ID:         model.StableID(ev.HostID, engine, "proc:"+p.Exe+":"+p.Cwd),
		HostID:     ev.HostID,
		Engine:     engine,
		Identity:   fmt.Sprintf("process pid=%d %s", p.PID, truncate(p.Cmdline, 120)),
		RunMode:    "process",
		Status:     "running",
		Exposure:   model.ExposureLocalhost, // network collector upgrades this if reachable
		Owner:      p.User,
		DetectedBy: []string{"process"},
		Confidence: confidence,
		LastSeen:   ev.Time,
	}
	m.upsertAndScore(api, inst)
	return nil
}

// --- Filesystem (ТЗ §5.1 п.4) ---

func (m *Module) handleFS(ev model.Event, api *modules.API) error {
	var a obs.FSArtifact
	if err := json.Unmarshal(ev.Payload, &a); err != nil {
		return fmt.Errorf("fs payload: %w", err)
	}
	engine, conf := "", 0.0
	switch a.Kind {
	case "n8n_dir":
		engine, conf = "n8n", 0.8
	case "compose_file", "env_file":
		engine, conf = "n8n", 0.6 // file references n8n but instance may be stopped
	default:
		return nil
	}
	dbType := a.Detail["db"]
	inst := &model.Instance{
		ID:         model.StableID(ev.HostID, engine, "fs:"+a.Path),
		HostID:     ev.HostID,
		Engine:     engine,
		Identity:   "fs:" + a.Path,
		RunMode:    "npm",
		Status:     "stopped", // running state comes from process/docker signals
		Exposure:   model.ExposureLocalhost,
		DBType:     dbType,
		Owner:      a.Owner,
		DetectedBy: []string{"filesystem"},
		Confidence: conf,
		LastSeen:   ev.Time,
	}
	if a.Detail["has_encryption_key"] == "true" {
		inst.SecretEnvKeys = []string{"N8N_ENCRYPTION_KEY"}
	}
	m.upsertAndScore(api, inst)
	return nil
}

// --- Cron / systemd timers (ТЗ §5.1 п.5) ---

func (m *Module) handleCron(ev model.Event, api *modules.API) error {
	var c obs.CronEntry
	if err := json.Unmarshal(ev.Payload, &c); err != nil {
		return fmt.Errorf("cron payload: %w", err)
	}
	engine := "cron"
	if c.Source == "systemd" {
		engine = "systemd-timer"
	}
	inst := &model.Instance{
		ID:         model.StableID(ev.HostID, engine, c.Source+"|"+c.Command),
		HostID:     ev.HostID,
		Engine:     engine,
		Identity:   fmt.Sprintf("%s: %s", c.Source, truncate(c.Command, 120)),
		RunMode:    "cron",
		Status:     "running",
		Exposure:   model.ExposureLocalhost,
		Owner:      c.User,
		DetectedBy: []string{"cron"},
		Confidence: 0.5,
		LastSeen:   ev.Time,
	}
	m.upsertAndScore(api, inst)
	return nil
}

// --- Network fingerprint (ТЗ §5.1 п.3) ---

func (m *Module) handleNetwork(ev model.Event, api *modules.API) error {
	var n obs.NetworkService
	if err := json.Unmarshal(ev.Payload, &n); err != nil {
		return fmt.Errorf("network payload: %w", err)
	}
	if !n.IsN8N {
		return nil
	}
	// Combination of /api/v1 + /rest + /api/v1/docs uniquely identifies n8n (§5.1 п.3).
	confidence := 0.5 + 0.15*float64(len(n.Fingerprints))
	if confidence > 0.95 {
		confidence = 0.95
	}
	exposure := model.ExposureLAN // reachable over the network by definition
	if isLoopback(n.IP) {
		exposure = model.ExposureLocalhost
	} else if isPublicIP(n.IP) {
		exposure = model.ExposurePublic
	}
	inst := &model.Instance{
		ID:         model.StableID(ev.HostID, "n8n", fmt.Sprintf("net:%s:%d", n.IP, n.Port)),
		HostID:     ev.HostID,
		Engine:     "n8n",
		Identity:   fmt.Sprintf("http://%s:%d", n.IP, n.Port),
		Version:    n.Version,
		RunMode:    "network",
		Status:     "running",
		Exposure:   exposure,
		Ports:      []int{n.Port},
		DetectedBy: []string{"network"},
		Confidence: confidence,
		LastSeen:   ev.Time,
	}
	m.upsertAndScore(api, inst)
	return nil
}

// --- n8n public API inventory (ТЗ §5.2: admin-provided key) ---

func (m *Module) handleN8NAPI(ev model.Event, api *modules.API) error {
	var d obs.N8NAPI
	if err := json.Unmarshal(ev.Payload, &d); err != nil {
		return fmt.Errorf("n8n api payload: %w", err)
	}
	host, port := splitHostPort(d.BaseURL)
	inst := &model.Instance{
		ID:         model.StableID(ev.HostID, "n8n", fmt.Sprintf("net:%s:%d", host, port)),
		HostID:     ev.HostID,
		Engine:     "n8n",
		Identity:   d.BaseURL,
		Version:    d.Version,
		RunMode:    "network",
		Status:     "running",
		Exposure:   model.ExposureUnknown,
		DetectedBy: []string{"n8n-api"},
		Confidence: 1.0,
		LastSeen:   ev.Time,
	}
	merged, _ := api.Store.UpsertInstance(inst)

	for _, w := range d.Workflows {
		wf := &model.Workflow{
			ID:         model.StableID(merged.ID, "wf", w.ID),
			InstanceID: merged.ID,
			Name:       w.Name,
			Active:     w.Active,
			UpdatedAt:  ev.Time,
		}
		for _, n := range w.Nodes {
			wf.Nodes = append(wf.Nodes, n.Type)
			if n.Webhook {
				wf.WebhookTriggers = append(wf.WebhookTriggers, n.Name)
			}
			// Credential refs and reachability map (§5.3): metadata only.
			if n.CredentialType != "" {
				sys, cat := classifyCredentialType(n.CredentialType, n.CredentialName)
				m.addCredentialRef(api, merged.ID, n.CredentialType, n.CredentialName, sys, cat, "", ev)
				m.addReachability(api, merged.ID, sys, cat, "credential", ev.Time)
				wf.Integrations = appendUnique(wf.Integrations, sys)
			}
			if n.URL != "" {
				sys, cat := classifyURLTarget(n.URL)
				m.addReachability(api, merged.ID, sys, cat, "http-node", ev.Time)
				wf.Integrations = appendUnique(wf.Integrations, sys)
			}
		}
		api.Store.UpsertWorkflow(wf)
	}
	m.rescore(api, merged.ID)
	return nil
}

// --- shared internals ---

// upsertAndScore merges the asset, applies whitelist rules (§5.6) and
// publishes/refreshes the risk finding.
func (m *Module) upsertAndScore(api *modules.API, inst *model.Instance) {
	host, _ := api.Store.Host(inst.HostID)
	if rule, ok := api.Store.MatchWhitelist(inst, host); ok {
		inst.Whitelisted = true
		inst.WhitelistReason = rule.Reason
	}
	merged, created := api.Store.UpsertInstance(inst)
	if created {
		payload, _ := json.Marshal(merged)
		api.PublishEvent(ModuleName, "asset.instance.created", merged.HostID, json.RawMessage(payload))
	}
	m.rescore(api, merged.ID)
}

// rescore recomputes the risk finding for an instance from current inventory.
func (m *Module) rescore(api *modules.API, instanceID string) {
	inst, ok := api.Store.Instance(instanceID)
	if !ok {
		return
	}
	host, _ := api.Store.Host(inst.HostID)
	res := m.engine.Score(risk.Input{
		Instance:     inst,
		Host:         host,
		Reachability: api.Store.ReachabilityByInstance(inst.ID),
		Credentials:  api.Store.CredentialRefsByInstance(inst.ID),
		Workflows:    api.Store.WorkflowsByInstance(inst.ID),
	})
	risk.SortFactors(res.Factors)
	f := &model.Finding{
		// One stable finding per instance: rescans update it in place (§8.2).
		ID:            model.StableID("finding", ModuleName, inst.ID),
		InstanceID:    inst.ID,
		HostID:        inst.HostID,
		Title:         fmt.Sprintf("Теневой инстанс %s: %s", inst.Engine, inst.Identity),
		TitleEN:       fmt.Sprintf("Shadow %s instance: %s", inst.Engine, inst.Identity),
		Score:         res.Score,
		Severity:      res.Severity,
		Factors:       res.Factors,
		Explanation:   res.Explanation,
		ExplanationEN: res.ExplanationEN,
		UpdatedAt:     inst.LastSeen,
	}
	if inst.Whitelisted {
		f.Status = model.FindingWhitelisted
		f.Severity = model.SeverityInfo
		f.Score = 0
		f.Explanation = "Инстанс в белом списке: " + inst.WhitelistReason
	}
	api.PublishFinding(ModuleName, f)
}

func (m *Module) addReachability(api *modules.API, instID, sys, cat, via string, t time.Time) {
	if sys == "" {
		return
	}
	api.Store.UpsertReachability(&model.Reachability{
		ID:             model.StableID("reach", instID, sys, via),
		InstanceID:     instID,
		TargetSystem:   sys,
		TargetCategory: cat,
		Via:            via,
		LastSeen:       t,
	})
}

func (m *Module) addCredentialRef(api *modules.API, instID, credType, name, sys, cat, fingerprint string, ev model.Event) {
	api.Store.UpsertCredentialRef(&model.CredentialRef{
		ID:             model.StableID("cred", instID, credType, name),
		InstanceID:     instID,
		Type:           credType,
		Name:           name,
		TargetSystem:   sys,
		TargetCategory: cat,
		Fingerprint:    fingerprint,
		LastSeen:       ev.Time,
	})
}
