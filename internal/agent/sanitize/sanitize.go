// Package sanitize is the agent's privacy guard (ТЗ §5.1, §9):
// «агент фиксирует факт наличия секрета, но не извлекает и не передаёт
// значение». Every env var and free-form string leaves the host either
// stripped or replaced with a SHA-256 fingerprint prefix.
package sanitize

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// secretKeyRe matches env var names that hold secrets.
var secretKeyRe = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASS(WORD)?|CRED|AUTH|PWD|PRIVATE|CERT|SIGNATURE|APIKEY|ACCESS)`)

// highEntropyValueRe catches values that look like tokens even when the key
// name is innocent (base64/hex runs of 24+ chars).
var highEntropyValueRe = regexp.MustCompile(`[A-Za-z0-9+/_\-]{24,}={0,2}`)

// IsSecretKey reports whether an env/config key holds a secret by name.
func IsSecretKey(key string) bool {
	return secretKeyRe.MatchString(key)
}

// Fingerprint returns a short non-reversible fingerprint of a secret value.
// It lets the control plane correlate "the same credential is reused on two
// hosts" without ever seeing the value (CredentialRef.Fingerprint, ТЗ §7).
func Fingerprint(value string) string {
	h := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(h[:])[:16]
}

// SplitEnv classifies raw "KEY=VALUE" pairs:
//   - names of all vars (metadata),
//   - secret vars → name→fingerprint (value discarded),
//   - a small allowlist of non-secret config vars needed for detection
//     (DB_TYPE, N8N_PORT, ...) passed through as plain values.
func SplitEnv(env []string) (names []string, secrets map[string]string, plain map[string]string) {
	secrets = map[string]string{}
	plain = map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		names = append(names, k)
		switch {
		case IsSecretKey(k):
			secrets[k] = Fingerprint(v)
		case plainAllowlist[k]:
			plain[k] = truncate(v, 120)
		}
		// Everything else: name only, value dropped.
	}
	return names, secrets, plain
}

// plainAllowlist: non-secret configuration values useful for detection
// (ТЗ §5.1 п.1: DB_TYPE, WEBHOOK_URL signal queue/db mode).
var plainAllowlist = map[string]bool{
	"DB_TYPE":               true,
	"N8N_PORT":              true,
	"N8N_PROTOCOL":          true,
	"N8N_HOST":              true,
	"WEBHOOK_URL":           true,
	"EXECUTIONS_MODE":       true,
	"QUEUE_BULL_REDIS_HOST": true,
	"DB_POSTGRESDB_HOST":    true,
	"NODE_ENV":              true,
}

// Scrub removes token-looking substrings from a free-form string (cmdline,
// cron command) before it leaves the host.
func Scrub(s string) string {
	return highEntropyValueRe.ReplaceAllStringFunc(s, func(m string) string {
		// Keep paths and words readable: only redact if it truly looks random.
		if looksRandom(m) {
			return "<redacted:" + Fingerprint(m)[7:15] + ">"
		}
		return m
	})
}

// looksRandom: crude entropy proxy — mixed case + digits, no path separators.
func looksRandom(s string) bool {
	if strings.ContainsAny(s, "/.") {
		return false
	}
	var upper, lower, digit int
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digit++
		}
	}
	classes := 0
	for _, n := range []int{upper, lower, digit} {
		if n > 0 {
			classes++
		}
	}
	return classes >= 2 && digit >= 2
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
