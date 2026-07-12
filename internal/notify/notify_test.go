package notify

import (
	"strings"
	"testing"

	"github.com/oleg-vdv/autogov/internal/model"
)

// ТЗ §8.4 / §3.3: in on-prem mode external destinations are refused by
// default; internal ones are allowed. This is the cross-border-transfer guard.
func TestEgressGuardBlocksExternalInOnPrem(t *testing.T) {
	g := EgressGuard{OnPrem: true, AllowExternal: false}

	if err := g.Check("10.0.0.5:514"); err != nil {
		t.Errorf("private address must be allowed: %v", err)
	}
	if err := g.Check("127.0.0.1:8080"); err != nil {
		t.Errorf("loopback must be allowed: %v", err)
	}
	if err := g.Check("8.8.8.8:443"); err == nil {
		t.Error("public IP must be blocked in on-prem mode")
	}
}

func TestEgressGuardAllowsWhenEnabledOrSaaS(t *testing.T) {
	if err := (EgressGuard{OnPrem: true, AllowExternal: true}).Check("8.8.8.8:443"); err != nil {
		t.Errorf("explicit allow must permit external: %v", err)
	}
	if err := (EgressGuard{OnPrem: false}).Check("8.8.8.8:443"); err != nil {
		t.Errorf("saas mode must permit external: %v", err)
	}
}

// ТЗ §5.5, §12 п.5: findings serialize to CEF for Wazuh/Splunk.
func TestFormatCEF(t *testing.T) {
	f := &model.Finding{
		Module: "m1-discovery", InstanceID: "inst1", HostID: "host1",
		Title: "Shadow n8n | prod", Score: 82, Severity: model.SeverityCritical,
		ExplanationEN: "Risk 82/100 with payments access",
	}
	cef := FormatCEF(f)
	if !strings.HasPrefix(cef, "CEF:0|AutoGov|ControlPlane|") {
		t.Errorf("bad CEF prefix: %q", cef)
	}
	if !strings.Contains(cef, "cn1=82") {
		t.Errorf("CEF must carry risk score: %q", cef)
	}
	// The pipe in the title must be escaped so the CEF header is not broken.
	if strings.Contains(cef, "Shadow n8n | prod") {
		t.Errorf("pipe in header must be escaped: %q", cef)
	}
}

// Manager construction must fail fast if a notifier targets an external host
// in on-prem mode (ТЗ §8.4): the error surfaces at startup, not at alert time.
func TestNewManagerRejectsExternalSyslogOnPrem(t *testing.T) {
	_, err := NewManager(
		Config{Syslog: []SyslogConfig{{Network: "udp", Address: "8.8.8.8:514"}}},
		EgressGuard{OnPrem: true},
		nil,
	)
	if err == nil {
		t.Fatal("expected on-prem egress guard to reject external syslog target")
	}
}
