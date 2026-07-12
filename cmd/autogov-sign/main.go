// autogov-sign — release signing utility (ТЗ §9 «Подписанные артефакты»).
//
//	autogov-sign keygen  -out-dir ./keys
//	autogov-sign sign    -key ./keys/release.key -version 0.1.0 -out manifest.json bin/agent bin/controlplane
//	autogov-sign verify  -pub ./keys/release.pub -manifest manifest.json [-dir bin]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oleg-vdv/autogov/internal/signing"
	"github.com/oleg-vdv/autogov/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "sign":
		sign(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `autogov-sign — release signing utility

  keygen -out-dir DIR              generate an ed25519 release keypair
  sign   -key K -out M FILES...    hash FILES, write signed manifest M
  verify -pub P -manifest M        verify manifest signature and file hashes`)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := fs.String("out-dir", "keys", "directory to write release.pub / release.key")
	fs.Parse(args)

	pub, priv, err := signing.GenerateKeypair()
	must(err)
	must(os.MkdirAll(*outDir, 0o700))
	pubPath := filepath.Join(*outDir, "release.pub")
	keyPath := filepath.Join(*outDir, "release.key")
	must(os.WriteFile(pubPath, []byte(signing.EncodePublicKey(pub)+"\n"), 0o644))
	must(os.WriteFile(keyPath, []byte(signing.EncodePrivateKey(priv)+"\n"), 0o600))
	fmt.Printf("wrote %s (public) and %s (PRIVATE — keep offline)\n", pubPath, keyPath)
	fmt.Printf("distribute the public key to hosts; embed it in agent config as release.public_key\n")
}

func sign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to private key")
	out := fs.String("out", "manifest.json", "output manifest path")
	ver := fs.String("version", version.Version, "release version")
	fs.Parse(args)
	files := fs.Args()
	if *keyPath == "" || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "sign: -key and at least one FILE are required")
		os.Exit(2)
	}
	keyHex, err := os.ReadFile(*keyPath)
	must(err)
	priv, err := signing.DecodePrivateKey(string(keyHex))
	must(err)

	m := &signing.Manifest{
		Product:   version.Product,
		Version:   *ver,
		CreatedAt: time.Now().UTC(),
		Files:     map[string]string{},
	}
	for _, f := range files {
		sum, err := signing.SHA256File(f)
		must(err)
		m.Files[filepath.Base(f)] = sum
		fmt.Printf("  %s  %s\n", sum[:16], filepath.Base(f))
	}
	must(m.Sign(priv))
	raw := mustJSON(m)
	must(os.WriteFile(*out, raw, 0o644))
	fmt.Printf("signed manifest written to %s (%d files)\n", *out, len(m.Files))
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "path to public key")
	manPath := fs.String("manifest", "manifest.json", "manifest path")
	dir := fs.String("dir", "", "directory containing the artifacts to re-hash (optional)")
	fs.Parse(args)
	if *pubPath == "" {
		fmt.Fprintln(os.Stderr, "verify: -pub is required")
		os.Exit(2)
	}
	pubHex, err := os.ReadFile(*pubPath)
	must(err)
	pub, err := signing.DecodePublicKey(string(pubHex))
	must(err)
	m, err := signing.LoadManifest(*manPath)
	must(err)

	if !m.Verify(pub) {
		fmt.Fprintln(os.Stderr, "FAIL: manifest signature is INVALID")
		os.Exit(1)
	}
	fmt.Println("OK: manifest signature valid")
	if *dir != "" {
		bad := 0
		for name, want := range m.Files {
			got, err := signing.SHA256File(filepath.Join(*dir, name))
			if err != nil {
				fmt.Printf("  MISSING %s (%v)\n", name, err)
				bad++
				continue
			}
			if got != want {
				fmt.Printf("  TAMPERED %s\n", name)
				bad++
				continue
			}
			fmt.Printf("  OK %s\n", name)
		}
		if bad > 0 {
			os.Exit(1)
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func mustJSON(m *signing.Manifest) []byte {
	raw, err := json.MarshalIndent(m, "", "  ")
	must(err)
	return raw
}
