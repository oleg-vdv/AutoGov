package signing

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManifestSignVerify(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		Product: "AutoGov", Version: "0.1.0", CreatedAt: time.Now().UTC(),
		Files: map[string]string{"agent": "abc123", "controlplane": "def456"},
	}
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if !m.Verify(pub) {
		t.Fatal("valid signature must verify")
	}
}

func TestTamperedManifestFailsVerify(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	m := &Manifest{Product: "AutoGov", Version: "0.1.0", Files: map[string]string{"agent": "abc"}}
	m.Sign(priv)
	// Tamper with a pinned hash after signing.
	m.Files["agent"] = "evil"
	if m.Verify(pub) {
		t.Fatal("tampered manifest must NOT verify (ТЗ §9)")
	}
}

func TestWrongKeyFailsVerify(t *testing.T) {
	_, priv, _ := GenerateKeypair()
	otherPub, _, _ := GenerateKeypair()
	m := &Manifest{Product: "AutoGov", Files: map[string]string{"agent": "abc"}}
	m.Sign(priv)
	if m.Verify(otherPub) {
		t.Fatal("signature from a different key must not verify")
	}
}

func TestKeyEncodingRoundTrip(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	pub2, err := DecodePublicKey(EncodePublicKey(pub))
	if err != nil || string(pub2) != string(pub) {
		t.Fatalf("public key round trip failed: %v", err)
	}
	priv2, err := DecodePrivateKey(EncodePrivateKey(priv))
	if err != nil || string(priv2) != string(priv) {
		t.Fatalf("private key round trip failed: %v", err)
	}
}

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	os.WriteFile(p, []byte("hello"), 0o644)
	sum, err := SHA256File(p)
	if err != nil {
		t.Fatal(err)
	}
	// sha256("hello")
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if sum != want {
		t.Fatalf("sha256 mismatch: got %s", sum)
	}
}
