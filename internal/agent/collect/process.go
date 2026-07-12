package collect

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/oleg-vdv/autogov/internal/agent/sanitize"
	"github.com/oleg-vdv/autogov/internal/obs"
)

// Process scans /proc for automation runners (ТЗ §5.1 п.2): Node.js processes
// with n8n signatures, generic node automations and Python runners/schedulers.
type Process struct {
	ProcPath string // default /proc; overridable for tests
}

func NewProcess() *Process { return &Process{ProcPath: "/proc"} }

func (p *Process) Name() string { return "process" }

func (p *Process) Collect(_ context.Context) ([]obs.Observation, error) {
	entries, err := os.ReadDir(p.ProcPath)
	if err != nil {
		return nil, nil // no /proc (non-Linux): degrade gracefully
	}
	var out []obs.Observation
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline := p.readCmdline(pid)
		if cmdline == "" {
			continue
		}
		sig := classifyProcess(cmdline)
		if sig == "" {
			continue
		}
		exe, _ := os.Readlink(filepath.Join(p.ProcPath, e.Name(), "exe"))
		cwd, _ := os.Readlink(filepath.Join(p.ProcPath, e.Name(), "cwd"))
		payload := obs.Process{
			PID:       pid,
			User:      p.ownerOf(pid),
			Exe:       exe,
			Cwd:       cwd,
			Cmdline:   sanitize.Scrub(cmdline),
			Signature: sig,
		}
		o, err := NewObservation(obs.TypeProcess, exe+"|"+cwd, payload)
		if err != nil {
			continue
		}
		out = append(out, o)
	}
	return out, nil
}

func (p *Process) readCmdline(pid int) string {
	raw, err := os.ReadFile(filepath.Join(p.ProcPath, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
}

func (p *Process) ownerOf(pid int) string {
	fi, err := os.Stat(filepath.Join(p.ProcPath, strconv.Itoa(pid)))
	if err != nil {
		return ""
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if u, err := user.LookupId(strconv.Itoa(int(st.Uid))); err == nil {
			return u.Username
		}
		return strconv.Itoa(int(st.Uid))
	}
	return ""
}

// n8nBinaryRe matches n8n as an actual executable/path token (".../n8n",
// "n8n start"), not a mere substring. This avoids flagging shells that merely
// mention an N8N_* env var or a path — a first-release false-positive
// requirement (ТЗ §5.6). Env var names use uppercase "N8N_", so the
// lowercase word-boundary match here does not fire on them.
var n8nBinaryRe = regexp.MustCompile(`(^|/|\s)n8n(\s|$)`)

// classifyProcess maps a command line to an automation signature. It requires
// a real runner invocation, corroborated later by other collectors (ТЗ §5.1
// multi-signal).
func classifyProcess(cmdline string) string {
	lc := strings.ToLower(cmdline)
	switch {
	case n8nBinaryRe.MatchString(lc):
		return "n8n"
	case strings.Contains(lc, "node-red") || strings.Contains(lc, "activepieces") ||
		strings.Contains(lc, "windmill"):
		return "node-automation"
	case (strings.Contains(lc, "python") || strings.Contains(lc, "celery")) &&
		(strings.Contains(lc, "worker") || strings.Contains(lc, "scheduler") ||
			strings.Contains(lc, "beat") || strings.Contains(lc, "airflow") ||
			strings.Contains(lc, "prefect")):
		return "python-runner"
	default:
		return ""
	}
}
