package agent

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/oleg-vdv/autogov/internal/signing"
)

// verifyRelease implements the host-side signature check of ТЗ §9. If a
// signed manifest and trusted public key are configured, the agent:
//  1. verifies the manifest's ed25519 signature, and
//  2. confirms its own running binary's SHA-256 is pinned in the manifest.
//
// On failure with Enforce=true the agent refuses to start (fail closed). With
// Enforce=false it only warns, so operators can roll out verification
// gradually. If no manifest is configured, verification is skipped with a
// warning — this keeps dev/demo simple but is visible in logs.
func verifyRelease(cfg Config, logger *slog.Logger) error {
	if cfg.Release.ManifestPath == "" || cfg.Release.PublicKey == "" {
		logger.Warn("release signature verification disabled (no manifest/public_key configured) — enable for production (ТЗ §9)")
		return nil
	}

	pub, err := signing.DecodePublicKey(cfg.Release.PublicKey)
	if err != nil {
		return fmt.Errorf("release public key: %w", err)
	}
	m, err := signing.LoadManifest(cfg.Release.ManifestPath)
	if err != nil {
		return failClosed(cfg, logger, fmt.Errorf("load manifest: %w", err))
	}
	if !m.Verify(pub) {
		return failClosed(cfg, logger, fmt.Errorf("manifest signature is invalid"))
	}

	self, err := os.Executable()
	if err != nil {
		return failClosed(cfg, logger, fmt.Errorf("locate self: %w", err))
	}
	got, err := signing.SHA256File(self)
	if err != nil {
		return failClosed(cfg, logger, fmt.Errorf("hash self: %w", err))
	}
	name := filepath.Base(self)
	want, ok := m.Files[name]
	if !ok {
		// Try common release name if the binary was renamed on install.
		want, ok = m.Files["agent"]
	}
	if !ok {
		return failClosed(cfg, logger, fmt.Errorf("binary %q not present in manifest", name))
	}
	if got != want {
		return failClosed(cfg, logger, fmt.Errorf("binary hash mismatch: possible tampering (%s)", name))
	}

	logger.Info("release signature verified", "manifest", cfg.Release.ManifestPath, "version", m.Version, "binary", name)
	return nil
}

func failClosed(cfg Config, logger *slog.Logger, err error) error {
	if cfg.Release.Enforce {
		return fmt.Errorf("release verification failed (fail-closed): %w", err)
	}
	logger.Warn("release verification failed (continuing: enforce=false)", "err", err)
	return nil
}
