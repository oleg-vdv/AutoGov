// autogov-agent — outbound-only host sensor (ТЗ §4.2, §9).
// Collects Docker/process/filesystem/cron/network signals of shadow
// automations, sanitizes secrets locally, and ships observations to the
// control plane over mTLS. Never opens a listening port.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/oleg-vdv/autogov/internal/agent"
	"github.com/oleg-vdv/autogov/internal/version"
)

func main() {
	cfgPath := flag.String("config", "agent.json", "path to agent config (JSON)")
	once := flag.Bool("once", false, "run a single scan and exit (for testing)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s agent v%s\n", version.Product, version.Version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		logger.Error("config read failed", "err", err)
		os.Exit(1)
	}
	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		logger.Error("config parse failed", "err", err)
		os.Exit(1)
	}
	if cfg.ControlPlaneURL == "" || cfg.Token == "" {
		logger.Error("config: control_plane_url and token are required")
		os.Exit(1)
	}

	a, err := agent.New(cfg, logger)
	if err != nil {
		logger.Error("agent init failed", "err", err)
		os.Exit(1)
	}

	if *once {
		a.RunOnce(context.Background())
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	a.Run(ctx)
}
