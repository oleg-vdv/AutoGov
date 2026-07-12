package discovery

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/oleg-vdv/autogov/internal/obs"
)

// Target system classification for the reachability map (ТЗ §5.3): which
// production systems a shadow instance can reach — 1С, CRM, DB, payments,
// clouds. Keyword tables are intentionally simple and extensible.

var categoryKeywords = map[string][]string{
	"erp_1c":    {"1c", "odata/standard", "v8", "onec", "enterprise"},
	"payments":  {"stripe", "paypal", "kaspi", "cloudpayments", "payment", "halyk", "wooppay", "paybox"},
	"database":  {"postgres", "mysql", "mariadb", "mssql", "oracle", "mongodb", "clickhouse", "redis"},
	"crm":       {"bitrix", "amocrm", "salesforce", "hubspot", "pipedrive", "crm"},
	"cloud":     {"amazonaws", "aws", "googleapis", "gcp", "azure", "yandexcloud", "digitalocean", "s3"},
	"messaging": {"telegram", "slack", "whatsapp", "discord", "smtp", "mail"},
}

func classifyKeyword(s string) (category string) {
	ls := strings.ToLower(s)
	for cat, kws := range categoryKeywords {
		for _, kw := range kws {
			if strings.Contains(ls, kw) {
				return cat
			}
		}
	}
	return ""
}

// classifyCredentialType maps n8n credential types to target systems.
func classifyCredentialType(credType, credName string) (system, category string) {
	system = credType
	if cat := classifyKeyword(credType); cat != "" {
		return system, cat
	}
	if cat := classifyKeyword(credName); cat != "" {
		return system, cat
	}
	return system, "other"
}

// classifyURLTarget maps an HTTP node URL to a target system.
func classifyURLTarget(raw string) (system, category string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return truncate(raw, 60), classifyOr(raw, "other")
	}
	return u.Host, classifyOr(raw, "other")
}

// classifyEnvTarget maps a secret env var name to a target system.
func classifyEnvTarget(envKey string) (system, category string) {
	if envKey == "N8N_ENCRYPTION_KEY" {
		// The key protecting all n8n credentials: presence matters, value never read.
		return "n8n credential store", "other"
	}
	if cat := classifyKeyword(envKey); cat != "" {
		return envKey, cat
	}
	return "", ""
}

func classifyOr(s, def string) string {
	if cat := classifyKeyword(s); cat != "" {
		return cat
	}
	return def
}

func looksLikeAutomationImage(img string) bool {
	for _, kw := range []string{"make", "zapier", "airflow", "prefect", "temporal", "node-red", "huginn", "activepieces", "windmill"} {
		if strings.Contains(img, kw) {
			return true
		}
	}
	return false
}

func containerStatus(state string) string {
	if strings.Contains(strings.ToLower(state), "run") || state == "up" {
		return "running"
	}
	return "stopped"
}

func privatePorts(ports []obs.PortMap) []int {
	var out []int
	seen := map[int]bool{}
	for _, p := range ports {
		if p.Private != 0 && !seen[p.Private] {
			seen[p.Private] = true
			out = append(out, p.Private)
		}
	}
	return out
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func isLoopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}

// isPublicIP is a conservative check: RFC1918/link-local/loopback are private.
func isPublicIP(ip string) bool {
	if isLoopback(ip) {
		return false
	}
	for _, p := range []string{"10.", "192.168.", "169.254.", "fe80:", "fd", "fc"} {
		if strings.HasPrefix(ip, p) {
			return false
		}
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.SplitN(ip, ".", 3)
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil && n >= 16 && n <= 31 {
				return false
			}
		}
	}
	return true
}

func splitHostPort(baseURL string) (string, int) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL, 0
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	return u.Hostname(), port
}
