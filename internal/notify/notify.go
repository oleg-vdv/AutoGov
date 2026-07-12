// Package notify implements finding notifications (ТЗ §5.5): webhook,
// syslog/CEF for SIEM (Wazuh/Splunk), e-mail, Telegram — plus the on-prem
// egress guard (ТЗ §8.4): in on-prem mode any external destination is
// refused unless the administrator explicitly enabled external egress,
// because that constitutes cross-border transfer (Закон РК № 94-V, ТЗ §3.3).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/oleg-vdv/autogov/internal/bus"
	"github.com/oleg-vdv/autogov/internal/model"
	"github.com/oleg-vdv/autogov/internal/version"
)

// Notifier delivers one finding.
type Notifier interface {
	Name() string
	Send(f *model.Finding) error
}

// Config for the notification manager (JSON, control plane config).
type Config struct {
	// MinSeverity below which findings are not delivered (default: medium).
	MinSeverity string `json:"min_severity"`

	Webhooks []WebhookConfig `json:"webhooks,omitempty"`
	Syslog   []SyslogConfig  `json:"syslog,omitempty"`
	SMTP     *SMTPConfig     `json:"smtp,omitempty"`
	Telegram *TelegramConfig `json:"telegram,omitempty"`
}

type WebhookConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

type SyslogConfig struct {
	Network string `json:"network"` // udp | tcp
	Address string `json:"address"` // host:port (Wazuh, ТЗ §12 п.5)
}

type SMTPConfig struct {
	Address  string   `json:"address"` // host:port
	From     string   `json:"from"`
	To       []string `json:"to"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
}

type TelegramConfig struct {
	// Telegram Bot API is always an external service: blocked in on-prem
	// mode unless allow_external_egress is set (ТЗ §8.4).
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
	APIBase  string `json:"api_base,omitempty"` // override for tests
}

// EgressGuard enforces the on-prem "no external traffic by default" rule.
type EgressGuard struct {
	OnPrem        bool
	AllowExternal bool
}

// Check returns an error if the destination host is external and egress is
// not explicitly allowed.
func (g EgressGuard) Check(hostport string) error {
	if !g.OnPrem || g.AllowExternal {
		return nil
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return nil
		}
		return g.deny(host)
	}
	// Hostname: resolve once; all addresses must be private.
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		// Unresolvable in an air-gapped network: assume internal DNS name.
		return nil
	}
	for _, ip := range addrs {
		if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			return g.deny(host)
		}
	}
	return nil
}

func (g EgressGuard) deny(host string) error {
	return fmt.Errorf("on-prem mode: destination %q is external; enable allow_external_egress explicitly to permit cross-border transfer (ТЗ §8.4)", host)
}

// Manager subscribes to finding events and fans out to notifiers.
type Manager struct {
	notifiers []Notifier
	minSev    model.Severity
	logger    *slog.Logger
}

// NewManager builds notifiers from config, applying the egress guard at
// construction time: external destinations fail fast, not at alert time.
func NewManager(cfg Config, guard EgressGuard, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	m := &Manager{minSev: model.Severity(cfg.MinSeverity), logger: logger}
	if m.minSev == "" {
		m.minSev = model.SeverityMedium
	}
	for _, w := range cfg.Webhooks {
		u, err := url.Parse(w.URL)
		if err != nil {
			return nil, fmt.Errorf("webhook url %q: %w", w.URL, err)
		}
		if err := guard.Check(u.Host); err != nil {
			return nil, fmt.Errorf("webhook %q: %w", w.URL, err)
		}
		m.notifiers = append(m.notifiers, &Webhook{URL: w.URL, Headers: w.Headers})
	}
	for _, s := range cfg.Syslog {
		if err := guard.Check(s.Address); err != nil {
			return nil, fmt.Errorf("syslog %q: %w", s.Address, err)
		}
		m.notifiers = append(m.notifiers, &SyslogCEF{Network: s.Network, Address: s.Address})
	}
	if cfg.SMTP != nil {
		if err := guard.Check(cfg.SMTP.Address); err != nil {
			return nil, fmt.Errorf("smtp: %w", err)
		}
		m.notifiers = append(m.notifiers, &SMTP{Cfg: *cfg.SMTP})
	}
	if cfg.Telegram != nil {
		base := cfg.Telegram.APIBase
		if base == "" {
			base = "https://api.telegram.org"
		}
		u, _ := url.Parse(base)
		if u == nil || u.Host == "" {
			return nil, fmt.Errorf("telegram api_base %q invalid", base)
		}
		if err := guard.Check(u.Host); err != nil {
			return nil, fmt.Errorf("telegram: %w", err)
		}
		m.notifiers = append(m.notifiers, &Telegram{Cfg: *cfg.Telegram, APIBase: base})
	}
	return m, nil
}

// Attach subscribes the manager to finding events on the bus.
func (m *Manager) Attach(b *bus.Bus) {
	b.Subscribe("finding.*", func(_ context.Context, ev model.Event) {
		var f model.Finding
		if err := json.Unmarshal(ev.Payload, &f); err != nil {
			return
		}
		m.Notify(&f)
	})
}

var sevRank = map[model.Severity]int{
	model.SeverityInfo: 0, model.SeverityLow: 1, model.SeverityMedium: 2,
	model.SeverityHigh: 3, model.SeverityCritical: 4,
}

// Notify fans a finding out to all channels above the severity threshold.
func (m *Manager) Notify(f *model.Finding) {
	if sevRank[f.Severity] < sevRank[m.minSev] || f.Status == model.FindingWhitelisted {
		return
	}
	for _, n := range m.notifiers {
		if err := n.Send(f); err != nil {
			m.logger.Warn("notification failed", "notifier", n.Name(), "finding", f.ID, "err", err)
		}
	}
}

// --- Webhook ---

type Webhook struct {
	URL     string
	Headers map[string]string
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(f *model.Finding) error {
	body, err := json.Marshal(f)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.Product+"/"+version.Version)
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// --- Syslog / CEF (ТЗ §5.5, §12 п.5: Wazuh) ---

type SyslogCEF struct {
	Network string
	Address string
}

func (s *SyslogCEF) Name() string { return "syslog-cef" }

func (s *SyslogCEF) Send(f *model.Finding) error {
	msg := FormatCEF(f)
	network := s.Network
	if network == "" {
		network = "udp"
	}
	conn, err := net.DialTimeout(network, s.Address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	// RFC3164-style envelope: <PRI>timestamp host CEF:...
	pri := 13*8 + severityToSyslog(f.Severity) // facility 13 (log audit)
	line := fmt.Sprintf("<%d>%s autogov %s", pri, time.Now().Format(time.Stamp), msg)
	if network == "tcp" {
		line += "\n"
	}
	_, err = conn.Write([]byte(line))
	return err
}

// FormatCEF renders a finding as an ArcSight CEF record understood by
// Wazuh/Splunk (ТЗ §5.5).
func FormatCEF(f *model.Finding) string {
	sevNum := map[model.Severity]int{
		model.SeverityInfo: 1, model.SeverityLow: 3, model.SeverityMedium: 5,
		model.SeverityHigh: 8, model.SeverityCritical: 10,
	}[f.Severity]
	ext := fmt.Sprintf("cs1=%s cs1Label=InstanceID cs2=%s cs2Label=HostID cn1=%.0f cn1Label=RiskScore msg=%s",
		f.InstanceID, f.HostID, f.Score, cefEscapeExt(f.ExplanationEN))
	return fmt.Sprintf("CEF:0|%s|ControlPlane|%s|%s|%s|%d|%s",
		version.Product, version.Version, f.Module, cefEscapeHeader(f.Title), sevNum, ext)
}

func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func cefEscapeExt(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func severityToSyslog(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 2 // crit
	case model.SeverityHigh:
		return 3 // err
	case model.SeverityMedium:
		return 4 // warning
	default:
		return 6 // info
	}
}

// --- SMTP ---

type SMTP struct{ Cfg SMTPConfig }

func (s *SMTP) Name() string { return "smtp" }

func (s *SMTP) Send(f *model.Finding) error {
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: [%s] %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\nScore: %.0f\r\nFinding ID: %s\r\n",
		s.Cfg.From, strings.Join(s.Cfg.To, ", "), strings.ToUpper(string(f.Severity)), f.Title, f.Explanation, f.Score, f.ID)
	var auth smtp.Auth
	if s.Cfg.Username != "" {
		host, _, _ := net.SplitHostPort(s.Cfg.Address)
		auth = smtp.PlainAuth("", s.Cfg.Username, s.Cfg.Password, host)
	}
	return smtp.SendMail(s.Cfg.Address, auth, s.Cfg.From, s.Cfg.To, []byte(body))
}

// --- Telegram (external egress; blocked by guard in on-prem mode) ---

type Telegram struct {
	Cfg     TelegramConfig
	APIBase string
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(f *model.Finding) error {
	text := fmt.Sprintf("🔴 [%s] %s\n\n%s\n\nScore: %.0f", strings.ToUpper(string(f.Severity)), f.Title, f.Explanation, f.Score)
	payload, _ := json.Marshal(map[string]string{"chat_id": t.Cfg.ChatID, "text": text})
	u := fmt.Sprintf("%s/bot%s/sendMessage", t.APIBase, t.Cfg.BotToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(u, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram status %d", resp.StatusCode)
	}
	return nil
}
