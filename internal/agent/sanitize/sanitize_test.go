package sanitize

import "testing"

// ТЗ §5.1, §9, §12 п.3: the agent must never emit secret values. These tests
// pin the invariant that SplitEnv drops values of secret-named vars.
func TestSplitEnvNeverLeaksSecretValues(t *testing.T) {
	env := []string{
		"N8N_ENCRYPTION_KEY=supersecretvalue123456",
		"DB_TYPE=postgresdb",
		"DB_POSTGRESDB_PASSWORD=hunter2hunter2hunter2",
		"OPENAI_API_KEY=sk-abcdef0123456789abcdef",
		"NODE_ENV=production",
		"WEBHOOK_URL=https://n8n.example.com/webhook",
	}
	names, secrets, plain := SplitEnv(env)

	if len(names) != len(env) {
		t.Fatalf("expected all %d names, got %d", len(env), len(names))
	}

	for name, fp := range secrets {
		for _, kv := range env {
			if len(kv) > len(name) && kv[:len(name)] == name {
				value := kv[len(name)+1:]
				if fp == value {
					t.Fatalf("secret %q value leaked verbatim", name)
				}
			}
		}
		if fp[:7] != "sha256:" {
			t.Errorf("secret %q not fingerprinted: %q", name, fp)
		}
	}

	if _, ok := secrets["N8N_ENCRYPTION_KEY"]; !ok {
		t.Error("N8N_ENCRYPTION_KEY must be detected as secret")
	}
	if _, ok := secrets["DB_POSTGRESDB_PASSWORD"]; !ok {
		t.Error("password var must be detected as secret")
	}
	if _, ok := secrets["OPENAI_API_KEY"]; !ok {
		t.Error("api key var must be detected as secret")
	}

	// Non-secret config passes through for detection.
	if plain["DB_TYPE"] != "postgresdb" {
		t.Errorf("DB_TYPE should pass through, got %q", plain["DB_TYPE"])
	}
	// A secret value must never appear in the plain map.
	for k, v := range plain {
		if v == "supersecretvalue123456" || v == "hunter2hunter2hunter2" {
			t.Fatalf("plain map leaked secret via %q", k)
		}
	}
}

func TestScrubRedactsHighEntropyTokens(t *testing.T) {
	in := "node /app/run.js --token AKIA1234567890ABCDEF5678 --path /etc/config"
	out := Scrub(in)
	if out == in {
		t.Fatal("expected token to be redacted")
	}
	if contains(out, "AKIA1234567890ABCDEF5678") {
		t.Fatal("token leaked through Scrub")
	}
	// Paths stay readable.
	if !contains(out, "/etc/config") {
		t.Errorf("path was redacted unexpectedly: %q", out)
	}
}

func TestFingerprintStableAndNonReversible(t *testing.T) {
	a := Fingerprint("value")
	b := Fingerprint("value")
	if a != b {
		t.Error("fingerprint must be deterministic")
	}
	if a == Fingerprint("value2") {
		t.Error("different values must fingerprint differently")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
