// Package server implements the control-plane HTTP surface: the mTLS-capable
// Ingest API for agents (ТЗ §4.1), the public REST API with RBAC and audit
// logging (ТЗ §5.5, §9), and the embedded web dashboard.
package server

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/oleg-vdv/autogov/internal/notify"
	"github.com/oleg-vdv/autogov/internal/risk"
)

// Config is the control-plane configuration (JSON file).
type Config struct {
	Listen  string `json:"listen"`   // e.g. ":8443"
	DataDir string `json:"data_dir"` // store location

	// Mode: "onprem" (default; external egress denied, ТЗ §8.4) or "saas".
	Mode                string `json:"mode"`
	AllowExternalEgress bool   `json:"allow_external_egress"`

	TLS struct {
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
		// ClientCAFile enables mTLS for agents (ТЗ §4.2, §9).
		ClientCAFile string `json:"client_ca_file"`
	} `json:"tls"`

	// AgentTokens authenticate sensors on /ingest (bearer).
	AgentTokens []string `json:"agent_tokens"`

	// APITokens map bearer token → role: viewer | analyst | admin (ТЗ §9 RBAC).
	APITokens map[string]string `json:"api_tokens"`

	RiskWeights *risk.Weights `json:"risk_weights,omitempty"`
	VulnFeed    string        `json:"vuln_feed,omitempty"` // path to offline JSON feed
	Notify      notify.Config `json:"notify"`
}

// LoadConfig reads and validates the config file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Mode == "" {
		c.Mode = "onprem" // secure default (ТЗ §8.4)
	}
	if len(c.AgentTokens) == 0 {
		return nil, fmt.Errorf("config: at least one agent_token is required")
	}
	if len(c.APITokens) == 0 {
		return nil, fmt.Errorf("config: at least one api_token is required")
	}
	for tok, role := range c.APITokens {
		switch role {
		case "viewer", "analyst", "admin":
		default:
			return nil, fmt.Errorf("config: api token %q has unknown role %q", tok[:min(4, len(tok))]+"…", role)
		}
	}
	return &c, nil
}

// LoadVulnFeed reads the offline vulnerability feed if configured.
func LoadVulnFeed(path string) ([]risk.VulnRule, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []risk.VulnRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("vuln feed %s: %w", path, err)
	}
	return rules, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
