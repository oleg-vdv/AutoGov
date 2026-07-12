// Package signing implements artifact signing and verification (ТЗ §9:
// «Подписанные артефакты. Агент и обновления подписаны; проверка подписи на
// стороне хоста»).
//
// Scheme: ed25519 detached signatures over a release manifest that pins the
// SHA-256 of each shipped binary. At startup the agent verifies (a) the
// manifest signature against a trusted public key and (b) that its own
// running binary's hash is listed in the manifest. Tampering with the agent
// binary or the manifest is therefore detected on the host before any
// privileged collection runs.
//
// Pure standard library (crypto/ed25519) — no external dependencies, works
// air-gapped.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// Manifest pins the expected hash of each release artifact and carries a
// detached signature over its own canonical form.
type Manifest struct {
	Product   string            `json:"product"`
	Version   string            `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	Files     map[string]string `json:"files"`     // basename → sha256 hex
	Signature string            `json:"signature"` // hex ed25519 signature over the unsigned canonical JSON
}

// signingPayload is the canonical byte string that gets signed: the manifest
// with an empty signature field, marshaled deterministically (sorted keys).
func (m *Manifest) signingPayload() ([]byte, error) {
	files := make([]string, 0, len(m.Files))
	for name := range m.Files {
		files = append(files, name)
	}
	sort.Strings(files)
	canon := struct {
		Product   string      `json:"product"`
		Version   string      `json:"version"`
		CreatedAt time.Time   `json:"created_at"`
		Files     [][2]string `json:"files"`
	}{Product: m.Product, Version: m.Version, CreatedAt: m.CreatedAt}
	for _, name := range files {
		canon.Files = append(canon.Files, [2]string{name, m.Files[name]})
	}
	return json.Marshal(canon)
}

// Sign fills m.Signature using the private key.
func (m *Manifest) Sign(priv ed25519.PrivateKey) error {
	m.Signature = ""
	payload, err := m.signingPayload()
	if err != nil {
		return err
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, payload))
	return nil
}

// Verify checks the manifest signature against pub.
func (m *Manifest) Verify(pub ed25519.PublicKey) bool {
	if m.Signature == "" {
		return false
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil {
		return false
	}
	sigCopy := m.Signature
	m.Signature = ""
	payload, err := m.signingPayload()
	m.Signature = sigCopy
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

// GenerateKeypair creates a new ed25519 keypair.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SHA256File returns the lowercase hex SHA-256 of a file's contents.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// --- key encoding (hex text files) ---

// EncodePublicKey renders a public key as hex.
func EncodePublicKey(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }

// EncodePrivateKey renders a private key as hex.
func EncodePrivateKey(priv ed25519.PrivateKey) string { return hex.EncodeToString(priv) }

// DecodePublicKey parses a hex-encoded public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(trim(s))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// DecodePrivateKey parses a hex-encoded private key.
func DecodePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(trim(s))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// LoadManifest reads and parses a manifest file.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	return &m, nil
}

func trim(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
