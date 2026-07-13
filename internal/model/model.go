// Package model defines the core data model of the platform (ТЗ §7).
//
// Privacy by design: no entity has a field for secret values or personal
// data content. Only metadata and fingerprints are stored (ТЗ §7, §9).
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Severity is the risk category of a finding (ТЗ §5.4).
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Exposure describes network reachability of an instance.
type Exposure string

const (
	ExposureLocalhost Exposure = "localhost"
	ExposureLAN       Exposure = "lan"
	ExposurePublic    Exposure = "public"
	ExposureUnknown   Exposure = "unknown"
)

// FindingStatus lifecycle (ТЗ §7).
type FindingStatus string

const (
	FindingNew         FindingStatus = "new"
	FindingAcked       FindingStatus = "acked"
	FindingWhitelisted FindingStatus = "whitelisted"
	FindingResolved    FindingStatus = "resolved"
)

// Host is a sensor host (ТЗ §7).
type Host struct {
	ID           string            `json:"id"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Kernel       string            `json:"kernel,omitempty"`
	IPs          []string          `json:"ips,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	AgentID      string            `json:"agent_id,omitempty"`
	AgentVersion string            `json:"agent_version,omitempty"`
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
}

// Instance is a discovered automation engine (ТЗ §7).
type Instance struct {
	ID       string `json:"id"`       // stable: hash(host|engine|identity)
	HostID   string `json:"host_id"`  // may reference a network-only pseudo host
	Engine   string `json:"engine"`   // n8n | node-script | python-runner | cron | systemd-timer | make-agent | unknown
	Identity string `json:"identity"` // container id / port / path / cron line hash

	Version   string   `json:"version,omitempty"`
	RunMode   string   `json:"run_mode,omitempty"` // docker | npm | systemd | process | cron | network
	Status    string   `json:"status,omitempty"`   // running | stopped
	Exposure  Exposure `json:"exposure"`
	DBType    string   `json:"db_type,omitempty"` // sqlite | postgres | unknown
	QueueMode bool     `json:"queue_mode,omitempty"`

	Owner     string `json:"owner,omitempty"` // OS user / container owner if known
	OwnerIsIT bool   `json:"owner_is_it,omitempty"`

	Image         string   `json:"image,omitempty"`
	Ports         []int    `json:"ports,omitempty"`
	PublicPorts   []int    `json:"public_ports,omitempty"`
	SecretEnvKeys []string `json:"secret_env_keys,omitempty"` // names only, never values

	DetectedBy []string  `json:"detected_by"` // corroborating collectors (ТЗ §5.1: multi-signal)
	Confidence float64   `json:"confidence"`  // 0..1
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`

	Whitelisted     bool   `json:"whitelisted,omitempty"`
	WhitelistReason string `json:"whitelist_reason,omitempty"`
}

// Workflow inside an instance (ТЗ §7).
type Workflow struct {
	ID              string    `json:"id"`
	InstanceID      string    `json:"instance_id"`
	Name            string    `json:"name"`
	Active          bool      `json:"active"`
	Nodes           []string  `json:"nodes,omitempty"`
	WebhookTriggers []string  `json:"webhook_triggers,omitempty"`
	Integrations    []string  `json:"integrations,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CredentialRef is metadata about a secret: never the value (ТЗ §2, §7, §9).
type CredentialRef struct {
	ID             string    `json:"id"`
	InstanceID     string    `json:"instance_id"`
	Type           string    `json:"type"` // n8n credential type / env var kind
	Name           string    `json:"name,omitempty"`
	TargetSystem   string    `json:"target_system,omitempty"`
	TargetCategory string    `json:"target_category,omitempty"` // erp_1c|payments|database|crm|cloud|messaging|other
	Fingerprint    string    `json:"fingerprint,omitempty"`     // sha256 prefix of the value, computed on the agent
	LastSeen       time.Time `json:"last_seen"`
}

// Reachability is a graph edge "instance → target system" (ТЗ §5.3, §7).
type Reachability struct {
	ID             string    `json:"id"`
	InstanceID     string    `json:"instance_id"`
	TargetSystem   string    `json:"target_system"`
	TargetCategory string    `json:"target_category"`
	Via            string    `json:"via"` // credential | http-node | env | link
	LastSeen       time.Time `json:"last_seen"`
}

// RiskFactor is one scored contribution with a human-readable detail (ТЗ §5.4).
type RiskFactor struct {
	Key    string  `json:"key"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

// Finding is a risk-scored fact (ТЗ §7).
type Finding struct {
	ID         string       `json:"id"`
	Module     string       `json:"module"` // producing plugin (m1-discovery, m2-honeynodes, ...)
	InstanceID string       `json:"instance_id,omitempty"`
	HostID     string       `json:"host_id,omitempty"`
	Title      string       `json:"title"`
	TitleEN    string       `json:"title_en,omitempty"`
	Score      float64      `json:"score"`
	Severity   Severity     `json:"severity"`
	Factors    []RiskFactor `json:"factors,omitempty"`
	// Explanation is generated locally (templates), never by external LLMs
	// in on-prem mode (ТЗ §5.4).
	Explanation   string        `json:"explanation"`
	ExplanationEN string        `json:"explanation_en,omitempty"`
	Status        FindingStatus `json:"status"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// Event is a raw observation from an agent or a module event on the bus (ТЗ §7).
type Event struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`   // e.g. observation.docker.container, finding.created
	Source  string          `json:"source"` // agent id or module name
	HostID  string          `json:"host_id,omitempty"`
	Time    time.Time       `json:"time"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// WhitelistRule marks legitimate instances (ТЗ §5.6).
type WhitelistRule struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`    // host | image | instance | engine | identity
	Pattern   string    `json:"pattern"` // glob (*, ?)
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry records every control-plane action (ТЗ §9).
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Role   string    `json:"role,omitempty"`
	Action string    `json:"action"`
	Object string    `json:"object,omitempty"`
	Remote string    `json:"remote,omitempty"`
}

// Report metadata (ТЗ §7).
type Report struct {
	ID        string    `json:"id"`
	Format    string    `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	Path      string    `json:"path,omitempty"`
}

// StableID derives a deterministic short id from parts. Used for idempotent
// upserts (ТЗ §8.2): re-ingesting the same observation never duplicates assets.
func StableID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// SeverityFromScore maps a numeric score to a category (ТЗ §5.4).
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 80:
		return SeverityCritical
	case score >= 60:
		return SeverityHigh
	case score >= 35:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
