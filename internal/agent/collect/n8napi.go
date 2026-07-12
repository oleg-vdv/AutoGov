package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/oleg-vdv/autogov/internal/obs"
)

// N8NAPI inventories a specific n8n instance through its public REST API
// (ТЗ §5.2). The API key is supplied by the client administrator — the agent
// never brute-forces or extracts keys. Only node/credential TYPES and NAMES
// and HTTP target URLs are collected: never credential values (ТЗ §5.1, §9).
type N8NAPI struct {
	BaseURL string // e.g. http://127.0.0.1:5678
	APIKey  string
	client  *http.Client
}

func NewN8NAPI(baseURL, apiKey string) *N8NAPI {
	return &N8NAPI{
		BaseURL: baseURL,
		APIKey:  apiKey,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *N8NAPI) Name() string { return "n8n-api" }

func (n *N8NAPI) Collect(ctx context.Context) ([]obs.Observation, error) {
	if n.BaseURL == "" || n.APIKey == "" {
		return nil, nil
	}
	workflows, err := n.fetchWorkflows(ctx)
	if err != nil {
		return nil, err
	}
	payload := obs.N8NAPI{BaseURL: n.BaseURL, Workflows: workflows}
	o, err := NewObservation(obs.TypeN8NAPI, n.BaseURL, payload)
	if err != nil {
		return nil, err
	}
	return []obs.Observation{o}, nil
}

type n8nWorkflowList struct {
	Data []struct {
		ID     json.RawMessage `json:"id"`
		Name   string          `json:"name"`
		Active bool            `json:"active"`
		Nodes  []struct {
			Name       string `json:"name"`
			Type       string `json:"type"`
			Parameters struct {
				URL string `json:"url"`
			} `json:"parameters"`
			Credentials map[string]struct {
				Name string `json:"name"`
			} `json:"credentials"`
		} `json:"nodes"`
	} `json:"data"`
}

func (n *N8NAPI) fetchWorkflows(ctx context.Context) ([]obs.N8NWorkflow, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.BaseURL+"/api/v1/workflows?limit=250", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-N8N-API-KEY", n.APIKey)
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("n8n api workflows: status %d", resp.StatusCode)
	}
	var list n8nWorkflowList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	out := make([]obs.N8NWorkflow, 0, len(list.Data))
	for _, w := range list.Data {
		wf := obs.N8NWorkflow{ID: string(w.ID), Name: w.Name, Active: w.Active}
		for _, node := range w.Nodes {
			nn := obs.N8NWorkflowNode{
				Name:    node.Name,
				Type:    node.Type,
				Webhook: isWebhookNode(node.Type),
				URL:     node.Parameters.URL,
			}
			for credType, cred := range node.Credentials {
				nn.CredentialType = credType
				nn.CredentialName = cred.Name
				break // one credential ref per node is enough for the map
			}
			wf.Nodes = append(wf.Nodes, nn)
		}
		out = append(out, wf)
	}
	return out, nil
}

func isWebhookNode(nodeType string) bool {
	switch nodeType {
	case "n8n-nodes-base.webhook", "n8n-nodes-base.formTrigger", "n8n-nodes-base.wait":
		return true
	}
	return false
}
