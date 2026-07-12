// Package agent ties collectors, sanitizer and spool into the outbound-only
// sensor (ТЗ §4.2, §9). The agent initiates all connections to the control
// plane over mTLS/bearer; it never listens on any port, so it does not widen
// the attack surface of protected hosts.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/oleg-vdv/autogov/internal/agent/collect"
	"github.com/oleg-vdv/autogov/internal/agent/spool"
	"github.com/oleg-vdv/autogov/internal/obs"
	"github.com/oleg-vdv/autogov/internal/version"
)

// Config for the agent (JSON file).
type Config struct {
	AgentID         string `json:"agent_id"`
	ControlPlaneURL string `json:"control_plane_url"` // e.g. https://cp.internal:8443
	Token           string `json:"token"`             // bearer agent token
	IntervalSeconds int    `json:"interval_seconds"`  // full scan cadence
	SpoolDir        string `json:"spool_dir"`

	// Collector toggles (ТЗ §9: least privilege — operator enables only needed).
	DockerSocket string            `json:"docker_socket"` // "" → default; "off" disables
	ScanRoots    []string          `json:"scan_roots"`    // extra fs roots
	NetTargets   []string          `json:"net_targets"`   // host:port list to fingerprint
	Labels       map[string]string `json:"labels"`

	// Authorized n8n API inventory (client-provided key, ТЗ §5.2).
	N8NAPIBase string `json:"n8n_api_base"`
	N8NAPIKey  string `json:"n8n_api_key"`

	// mTLS client certificate (ТЗ §4.2, §9).
	TLS struct {
		ClientCertFile string `json:"client_cert_file"`
		ClientKeyFile  string `json:"client_key_file"`
		CAFile         string `json:"ca_file"`
		Insecure       bool   `json:"insecure_skip_verify"` // dev only
	} `json:"tls"`

	// Release integrity verification (ТЗ §9 «Подписанные артефакты»). When
	// set, the agent verifies its own binary against a signed manifest at
	// startup and refuses to run if tampered (Enforce=true).
	Release struct {
		ManifestPath string `json:"manifest_path"`
		PublicKey    string `json:"public_key"` // hex ed25519 public key
		Enforce      bool   `json:"enforce"`    // true = refuse to start on failure
	} `json:"release"`
}

// Agent runs collectors on a schedule and ships observations.
type Agent struct {
	cfg        Config
	collectors []collect.Collector
	spool      *spool.Spool
	client     *http.Client
	hostInfo   obs.HostInfo
	logger     *slog.Logger
}

// New builds an agent from config, enabling collectors per the config.
func New(cfg Config, logger *slog.Logger) (*Agent, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.AgentID == "" {
		host, _ := os.Hostname()
		cfg.AgentID = "agent-" + host
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 300
	}
	if cfg.SpoolDir == "" {
		cfg.SpoolDir = "/var/lib/autogov-agent/spool"
	}

	sp, err := spool.New(cfg.SpoolDir, 1000)
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}

	client, err := buildClient(cfg)
	if err != nil {
		return nil, err
	}

	// Verify release integrity before doing any privileged collection (§9).
	if err := verifyRelease(cfg, logger); err != nil {
		return nil, err
	}

	a := &Agent{cfg: cfg, spool: sp, client: client, logger: logger}

	// Enable collectors (each degrades gracefully if its subsystem is absent).
	if cfg.DockerSocket != "off" {
		a.collectors = append(a.collectors, collect.NewDocker(cfg.DockerSocket))
	}
	a.collectors = append(a.collectors,
		collect.NewProcess(),
		collect.NewFilesystem(cfg.ScanRoots),
		collect.NewCron(),
		collect.NewNetwork(cfg.NetTargets),
	)
	if cfg.N8NAPIBase != "" && cfg.N8NAPIKey != "" {
		a.collectors = append(a.collectors, collect.NewN8NAPI(cfg.N8NAPIBase, cfg.N8NAPIKey))
	}

	a.hostInfo = gatherHostInfo(cfg.Labels)
	return a, nil
}

// Run executes an initial scan then repeats on the configured interval until
// ctx is cancelled.
func (a *Agent) Run(ctx context.Context) {
	a.logger.Info("agent started", "agent_id", a.cfg.AgentID, "collectors", a.collectorNames(),
		"control_plane", a.cfg.ControlPlaneURL, "interval_s", a.cfg.IntervalSeconds)

	a.scanAndShip(ctx)
	ticker := time.NewTicker(time.Duration(a.cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("agent stopping")
			return
		case <-ticker.C:
			a.scanAndShip(ctx)
		}
	}
}

// RunOnce performs a single scan-and-ship cycle (for --once testing).
func (a *Agent) RunOnce(ctx context.Context) { a.scanAndShip(ctx) }

// scanAndShip runs all collectors, spools the batch, then flushes the spool.
func (a *Agent) scanAndShip(ctx context.Context) {
	start := time.Now()
	var observations []obs.Observation
	for _, c := range a.collectors {
		obsList, err := c.Collect(ctx)
		if err != nil {
			a.logger.Warn("collector error", "collector", c.Name(), "err", err)
			continue
		}
		observations = append(observations, obsList...)
	}
	a.logger.Info("scan complete", "observations", len(observations), "took", time.Since(start).String())

	if len(observations) > 0 {
		batch := obs.Batch{
			AgentID:      a.cfg.AgentID,
			AgentVersion: version.Version,
			Host:         a.hostInfo,
			Observations: observations,
		}
		if err := a.spool.Enqueue(batch); err != nil {
			a.logger.Error("spool enqueue failed", "err", err)
		}
	}
	a.flushSpool(ctx)
}

// flushSpool ships queued batches, stopping on the first delivery failure so
// order is preserved and the control plane isn't hammered while down.
func (a *Agent) flushSpool(ctx context.Context) {
	for _, name := range a.spool.Pending() {
		batch, err := a.spool.Load(name)
		if err != nil {
			a.spool.Remove(name) //nolint:errcheck // corrupt entry, drop it
			continue
		}
		if err := a.ship(ctx, batch); err != nil {
			a.logger.Warn("control plane unreachable, batch buffered", "err", err, "pending", len(a.spool.Pending()))
			return
		}
		a.spool.Remove(name) //nolint:errcheck
	}
}

func (a *Agent) ship(ctx context.Context, batch obs.Batch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.cfg.ControlPlaneURL+"/ingest/v1/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	req.Header.Set("User-Agent", version.Product+"-agent/"+version.Version)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ingest status %d", resp.StatusCode)
	}
	return nil
}

func (a *Agent) collectorNames() []string {
	out := make([]string, len(a.collectors))
	for i, c := range a.collectors {
		out[i] = c.Name()
	}
	return out
}

func buildClient(cfg Config) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TLS.Insecure} //nolint:gosec // insecure is dev-only, off by default
	if cfg.TLS.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("agent CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("agent CA %s: no certs", cfg.TLS.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.TLS.ClientCertFile != "" && cfg.TLS.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCertFile, cfg.TLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("agent client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func gatherHostInfo(labels map[string]string) obs.HostInfo {
	hostname, _ := os.Hostname()
	info := obs.HostInfo{Hostname: hostname, OS: osString(), Labels: labels}
	info.IPs = localIPs()
	return info
}
