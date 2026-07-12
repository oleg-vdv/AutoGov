// autogov-controlplane — центральный сервер платформы (ТЗ §4.1):
// Ingest API → Event Bus → Module Runtime (плагины M1..M4) → Asset Store /
// Risk Engine / Findings + Notifier → Web UI / Public API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oleg-vdv/autogov/internal/bus"
	"github.com/oleg-vdv/autogov/internal/modules"
	"github.com/oleg-vdv/autogov/internal/modules/autodoc"
	"github.com/oleg-vdv/autogov/internal/modules/discovery"
	"github.com/oleg-vdv/autogov/internal/modules/honeynodes"
	"github.com/oleg-vdv/autogov/internal/modules/selfhealing"
	"github.com/oleg-vdv/autogov/internal/notify"
	"github.com/oleg-vdv/autogov/internal/risk"
	"github.com/oleg-vdv/autogov/internal/server"
	"github.com/oleg-vdv/autogov/internal/store"
	"github.com/oleg-vdv/autogov/internal/version"
)

func main() {
	cfgPath := flag.String("config", "controlplane.json", "path to control plane config (JSON)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s control plane v%s\n", version.Product, version.Version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		logger.Error("store open failed", "err", err)
		os.Exit(1)
	}

	b := bus.New(8192, logger)
	rt := modules.NewRuntime(st, b, logger)

	// Risk engine (ТЗ §5.4): configurable weights + offline vuln feed.
	weights := risk.DefaultWeights()
	if cfg.RiskWeights != nil {
		weights = *cfg.RiskWeights
	}
	vulns, err := server.LoadVulnFeed(cfg.VulnFeed)
	if err != nil {
		logger.Error("vuln feed load failed", "err", err)
		os.Exit(1)
	}
	engine := risk.NewEngine(weights, vulns)

	// Register modules. M1 is the MVP; M2–M4 are contract stubs proving the
	// plugin model (ТЗ-0): they plug in with zero core changes.
	for _, m := range []modules.Module{
		discovery.New(engine),
		honeynodes.New(),
		selfhealing.New(),
		autodoc.New(),
	} {
		if err := rt.Register(m); err != nil {
			logger.Error("module registration failed", "module", m.Name(), "err", err)
			os.Exit(1)
		}
	}

	// Notifications with the on-prem egress guard (ТЗ §8.4).
	guard := notify.EgressGuard{OnPrem: cfg.Mode == "onprem", AllowExternal: cfg.AllowExternalEgress}
	nm, err := notify.NewManager(cfg.Notify, guard, logger)
	if err != nil {
		logger.Error("notifier init failed (on-prem egress guard?)", "err", err)
		os.Exit(1)
	}
	nm.Attach(b)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go b.Run(ctx)
	stopFlush := make(chan struct{})
	go st.RunAutoFlush(stopFlush, 5*time.Second)

	srv := server.New(cfg, st, b, rt, logger)
	logger.Info("starting", "product", version.Product, "version", version.Version, "mode", cfg.Mode)
	if err := srv.Run(ctx); err != nil {
		logger.Error("server failed", "err", err)
	}
	close(stopFlush)
	b.Drain()
	if err := st.Flush(); err != nil {
		logger.Error("final flush failed", "err", err)
	}
}
