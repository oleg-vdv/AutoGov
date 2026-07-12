// Package obs defines the wire contract between the agent and the control
// plane: raw observations (ТЗ §4.2 "агенты шлют сырые наблюдения").
//
// The agent never puts secret values into these structures — only names and
// fingerprints (ТЗ §5.1, §9). The sanitizer enforces this invariant.
package obs

import (
	"encoding/json"
	"time"
)

// Observation types (become bus events "observation.<Type>").
const (
	TypeDockerContainer = "docker.container"
	TypeProcess         = "process"
	TypeFSArtifact      = "fs.artifact"
	TypeCronEntry       = "cron.entry"
	TypeNetworkService  = "network.service"
	TypeN8NAPI          = "n8n.api"
)

// Observation is one raw fact collected on a host. ID is generated once at
// collection time, so retries after network failures are deduplicated by the
// control plane (ТЗ §8.2 idempotent ingest).
type Observation struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Identity string          `json:"identity"` // natural key within host: container id, port, path...
	Time     time.Time       `json:"time"`
	Data     json.RawMessage `json:"data"`
}

// Batch is what the agent POSTs to /ingest/v1/events.
type Batch struct {
	AgentID      string        `json:"agent_id"`
	AgentVersion string        `json:"agent_version"`
	Host         HostInfo      `json:"host"`
	Observations []Observation `json:"observations"`
}

// HostInfo describes the sensor host.
type HostInfo struct {
	Hostname string            `json:"hostname"`
	OS       string            `json:"os"`
	Kernel   string            `json:"kernel,omitempty"`
	IPs      []string          `json:"ips,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// PortMap is a container port binding.
type PortMap struct {
	Private int    `json:"private"`
	Public  int    `json:"public,omitempty"`
	IP      string `json:"ip,omitempty"` // bind address of the public side
}

// DockerContainer — collected via read-only Docker API (ТЗ §5.1 п.1).
type DockerContainer struct {
	ContainerID string            `json:"container_id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	State       string            `json:"state"`
	Ports       []PortMap         `json:"ports,omitempty"`
	EnvKeys     []string          `json:"env_keys,omitempty"`    // names of all env vars
	SecretEnvs  map[string]string `json:"secret_envs,omitempty"` // secret env name → sha256 fingerprint (no value)
	PlainEnvs   map[string]string `json:"plain_envs,omitempty"`  // non-secret whitelisted config vars (DB_TYPE, ...)
	Links       []string          `json:"links,omitempty"`       // related containers (postgres/redis)
	Labels      map[string]string `json:"labels,omitempty"`
	Mounts      []string          `json:"mounts,omitempty"`
}

// Process — collected from /proc (ТЗ §5.1 п.2).
type Process struct {
	PID       int    `json:"pid"`
	User      string `json:"user,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Cmdline   string `json:"cmdline"`
	Cwd       string `json:"cwd,omitempty"`
	Signature string `json:"signature"` // n8n | node-automation | python-runner
}

// FSArtifact — filesystem trace (ТЗ §5.1 п.4).
type FSArtifact struct {
	Path   string            `json:"path"`
	Kind   string            `json:"kind"` // n8n_dir | compose_file | env_file
	Owner  string            `json:"owner,omitempty"`
	Detail map[string]string `json:"detail,omitempty"` // e.g. has_encryption_key=true, db=sqlite
}

// CronEntry — scheduler trace (ТЗ §5.1 п.5).
type CronEntry struct {
	Source   string `json:"source"` // file path or "systemd"
	User     string `json:"user,omitempty"`
	Schedule string `json:"schedule,omitempty"`
	Command  string `json:"command"`
}

// NetworkService — network fingerprint (ТЗ §5.1 п.3).
type NetworkService struct {
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	Fingerprints []string `json:"fingerprints,omitempty"` // matched markers: /api/v1, /rest, /api/v1/docs, /healthz
	IsN8N        bool     `json:"is_n8n"`
	Version      string   `json:"version,omitempty"`
	ServerHeader string   `json:"server_header,omitempty"`
}

// N8NWorkflowNode is a node inside an n8n workflow (names/types only).
type N8NWorkflowNode struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Webhook        bool   `json:"webhook,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	CredentialName string `json:"credential_name,omitempty"`
	URL            string `json:"url,omitempty"` // for HTTP Request nodes — target only
}

// N8NWorkflow — inventory via public API with an admin-provided key (ТЗ §5.2).
type N8NWorkflow struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Active bool              `json:"active"`
	Nodes  []N8NWorkflowNode `json:"nodes,omitempty"`
}

// N8NAPI — result of authorized API inventory of one instance.
type N8NAPI struct {
	BaseURL   string        `json:"base_url"`
	Version   string        `json:"version,omitempty"`
	Workflows []N8NWorkflow `json:"workflows,omitempty"`
}
