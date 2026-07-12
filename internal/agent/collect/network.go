package collect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/obs"
)

// Network fingerprints n8n over HTTP (ТЗ §5.1 п.3). The combination of
// /api/v1 (public REST), /rest (editor backend) and /api/v1/docs (Swagger)
// uniquely identifies n8n. Targets default to localhost:5678 plus any
// admin-configured LAN targets — this is the "network sensor" collector.
type Network struct {
	Targets []string // host:port; default localhost:5678
	client  *http.Client
}

func NewNetwork(targets []string) *Network {
	if len(targets) == 0 {
		targets = []string{"127.0.0.1:5678"}
	}
	return &Network{
		Targets: targets,
		client: &http.Client{
			Timeout: 5 * time.Second,
			// Never follow redirects off the target; we only probe paths.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (n *Network) Name() string { return "network" }

// n8n marker paths and the status codes that count as "present". n8n returns
// 401/200 on these even without a key, which still identifies the product.
var n8nMarkers = []struct {
	path string
	name string
}{
	{"/rest/login", "/rest"},
	{"/api/v1/docs", "/api/v1/docs"},
	{"/healthz", "/healthz"},
	{"/rest/settings", "/rest-settings"},
}

func (n *Network) Collect(ctx context.Context) ([]obs.Observation, error) {
	var out []obs.Observation
	for _, target := range n.Targets {
		host, port := splitTarget(target)
		// Cheap TCP pre-check so we don't HTTP-probe dead ports.
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		var fps []string
		serverHdr := ""
		for _, m := range n8nMarkers {
			code, hdr := n.probe(ctx, target, m.path)
			if code > 0 && code != http.StatusNotFound {
				fps = append(fps, m.name)
			}
			if hdr != "" {
				serverHdr = hdr
			}
		}
		payload := obs.NetworkService{
			IP:           host,
			Port:         port,
			Fingerprints: fps,
			// Two or more distinct n8n markers = confident identification.
			IsN8N:        len(fps) >= 2,
			ServerHeader: serverHdr,
		}
		if o, err := NewObservation(obs.TypeNetworkService, target, payload); err == nil {
			out = append(out, o)
		}
	}
	return out, nil
}

func (n *Network) probe(ctx context.Context, target, path string) (int, string) {
	url := fmt.Sprintf("http://%s%s", target, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, ""
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	return resp.StatusCode, resp.Header.Get("Server")
}

func splitTarget(target string) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, 0
	}
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			break
		}
		port = port*10 + int(c-'0')
	}
	_ = strings.TrimSpace
	return host, port
}
