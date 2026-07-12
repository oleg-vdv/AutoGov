package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/bus"
	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/modules"
	"github.com/oleg-vdv/autogov/internal/store"
)

// Server hosts ingest, the public API and the dashboard.
type Server struct {
	cfg     *Config
	store   *store.Store
	bus     *bus.Bus
	runtime *modules.Runtime
	logger  *slog.Logger
	http    *http.Server
}

func New(cfg *Config, st *store.Store, b *bus.Bus, rt *modules.Runtime, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{cfg: cfg, store: st, bus: b, runtime: rt, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("/ingest/v1/events", s.handleIngest)
	s.registerAPI(mux)
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})

	s.http = &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Run starts the listener (TLS if configured; mTLS for agents when a client
// CA is provided — client certs are requested but only verified for /ingest,
// so browsers can still open the dashboard).
func (s *Server) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.http.Shutdown(shCtx) //nolint:errcheck
	}()

	if s.cfg.TLS.CertFile != "" && s.cfg.TLS.KeyFile != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if s.cfg.TLS.ClientCAFile != "" {
			caPEM, err := os.ReadFile(s.cfg.TLS.ClientCAFile)
			if err != nil {
				return fmt.Errorf("client CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return fmt.Errorf("client CA %s: no certificates found", s.cfg.TLS.ClientCAFile)
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
		s.http.TLSConfig = tlsCfg
		s.logger.Info("control plane listening (TLS)", "addr", s.cfg.Listen, "mode", s.cfg.Mode)
		err := s.http.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}

	s.logger.Warn("control plane listening WITHOUT TLS — use only behind a TLS-terminating proxy", "addr", s.cfg.Listen)
	err := s.http.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// --- auth ---

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return t
	}
	return ""
}

// checkAgentAuth: bearer token from the agent pool; if mTLS client CA is
// configured, a verified client certificate is also required (ТЗ §9).
func (s *Server) checkAgentAuth(r *http.Request) bool {
	tok := bearerToken(r)
	okTok := false
	for _, t := range s.cfg.AgentTokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(tok)) == 1 {
			okTok = true
			break
		}
	}
	if !okTok {
		return false
	}
	if s.cfg.TLS.ClientCAFile != "" {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			return false
		}
	}
	return true
}

// roleOf resolves the API caller's role; "" = unauthenticated.
func (s *Server) roleOf(r *http.Request) (actor, role string) {
	tok := bearerToken(r)
	if tok == "" {
		return "", ""
	}
	for t, ro := range s.cfg.APITokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(tok)) == 1 {
			suffix := t
			if len(suffix) > 4 {
				suffix = suffix[len(suffix)-4:]
			}
			return "token…" + suffix, ro
		}
	}
	return "", ""
}

var roleRank = map[string]int{"viewer": 1, "analyst": 2, "admin": 3}

// requireRole wraps an API handler with RBAC + audit logging (ТЗ §9).
// The reachability map is a sensitive artifact: it is gated at analyst+.
func (s *Server) requireRole(minRole string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, role := s.roleOf(r)
		if role == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if roleRank[role] < roleRank[minRole] {
			s.audit(actor, role, "DENIED "+r.Method+" "+r.URL.Path, r)
			http.Error(w, "forbidden: requires role "+minRole, http.StatusForbidden)
			return
		}
		s.audit(actor, role, r.Method+" "+r.URL.Path, r)
		h(w, r)
	}
}

func (s *Server) audit(actor, role, action string, r *http.Request) {
	s.store.AppendAudit(model.AuditEntry{
		Time:   time.Now().UTC(),
		Actor:  actor,
		Role:   role,
		Action: action,
		Remote: r.RemoteAddr,
	})
}
