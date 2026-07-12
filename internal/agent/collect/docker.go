package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/agent/sanitize"
	"github.com/oleg-vdv/autogov/internal/obs"
)

// Docker inspects containers through the Docker Engine API over the unix
// socket (ТЗ §5.1 п.1). Access is strictly read-only: only GET endpoints are
// ever called (ТЗ §9 «read-only режим по умолчанию»). Implemented with
// net/http over a unix dialer — no Docker SDK dependency, keeping the agent
// auditable.
type Docker struct {
	SocketPath string // default /var/run/docker.sock
	client     *http.Client
}

func NewDocker(socketPath string) *Docker {
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	d := &Docker{SocketPath: socketPath}
	d.client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dl net.Dialer
				return dl.DialContext(ctx, "unix", d.SocketPath)
			},
		},
	}
	return d
}

func (d *Docker) Name() string { return "docker" }

type dockerListEntry struct {
	ID    string `json:"Id"`
	Names []string
	Image string
	State string
	Ports []struct {
		IP          string `json:"IP"`
		PrivatePort int
		PublicPort  int
	}
	Labels map[string]string
}

type dockerInspect struct {
	Config struct {
		Env    []string
		Labels map[string]string
	}
	HostConfig struct {
		Links []string
		Binds []string
	}
	NetworkSettings struct {
		Networks map[string]struct {
			Links []string
		}
	}
	Mounts []struct {
		Source      string
		Destination string
	}
}

func (d *Docker) Collect(ctx context.Context) ([]obs.Observation, error) {
	if _, err := os.Stat(d.SocketPath); err != nil {
		return nil, nil // no Docker on this host — graceful degradation (ТЗ §9)
	}
	var list []dockerListEntry
	if err := d.get(ctx, "/containers/json?all=1", &list); err != nil {
		return nil, fmt.Errorf("docker list: %w", err)
	}

	// Names of sibling containers signal queue mode (postgres/redis links).
	var siblingNames []string
	for _, c := range list {
		for _, n := range c.Names {
			siblingNames = append(siblingNames, strings.TrimPrefix(n, "/"))
		}
	}

	var out []obs.Observation
	for _, c := range list {
		var ins dockerInspect
		if err := d.get(ctx, "/containers/"+c.ID+"/json", &ins); err != nil {
			continue // container may have vanished between list and inspect
		}
		names, secrets, plain := sanitize.SplitEnv(ins.Config.Env)

		payload := obs.DockerContainer{
			ContainerID: c.ID,
			Name:        firstName(c.Names),
			Image:       c.Image,
			State:       c.State,
			EnvKeys:     names,
			SecretEnvs:  secrets,
			PlainEnvs:   plain,
			Labels:      c.Labels,
		}
		for _, p := range c.Ports {
			payload.Ports = append(payload.Ports, obs.PortMap{
				Private: p.PrivatePort, Public: p.PublicPort, IP: p.IP,
			})
		}
		for _, m := range ins.Mounts {
			payload.Mounts = append(payload.Mounts, m.Destination)
		}
		payload.Links = relatedContainers(ins, siblingNames, plain)

		o, err := NewObservation(obs.TypeDockerContainer, c.ID, payload)
		if err != nil {
			continue
		}
		out = append(out, o)
	}
	return out, nil
}

func (d *Docker) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker api %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

// relatedContainers derives postgres/redis relations from legacy links and
// env-configured hosts (queue mode signal, ТЗ §5.1 п.1).
func relatedContainers(ins dockerInspect, siblings []string, plain map[string]string) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	for _, l := range ins.HostConfig.Links {
		add(l)
	}
	for _, nw := range ins.NetworkSettings.Networks {
		for _, l := range nw.Links {
			add(l)
		}
	}
	if h := plain["DB_POSTGRESDB_HOST"]; h != "" {
		add("postgres:" + h)
	}
	if h := plain["QUEUE_BULL_REDIS_HOST"]; h != "" {
		add("redis:" + h)
	}
	_ = siblings // sibling correlation lands with compose-project grouping (Э2)
	return out
}
