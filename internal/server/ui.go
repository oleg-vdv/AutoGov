package server

import (
	_ "embed"
	"net/http"
)

//go:embed ui/index.html
var uiIndex []byte

// handleUI serves the embedded single-page dashboard (ТЗ §5.5).
// Authentication happens client-side: the page asks for an API token and
// sends it as a Bearer header; the server enforces RBAC on every API call.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	w.Write(uiIndex) //nolint:errcheck
}
