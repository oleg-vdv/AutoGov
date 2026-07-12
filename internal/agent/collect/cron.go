package collect

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/oleg-vdv/autogov/internal/agent/sanitize"
	"github.com/oleg-vdv/autogov/internal/obs"
)

// Cron reads scheduler entries (ТЗ §5.1 п.5): system crontab, /etc/cron.d,
// per-user crontabs and systemd timer unit ExecStart lines. Only entries that
// look like automation runners are reported.
type Cron struct {
	Roots []string // crontab locations; overridable for tests
}

func NewCron() *Cron {
	return &Cron{Roots: []string{
		"/etc/crontab", "/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs",
	}}
}

func (c *Cron) Name() string { return "cron" }

var automationHints = []string{"n8n", "node", "python", "npm", "docker", "make", "curl", "webhook", ".js", ".py"}

func (c *Cron) Collect(_ context.Context) ([]obs.Observation, error) {
	var out []obs.Observation
	for _, root := range c.Roots {
		fi, err := os.Stat(root)
		if err != nil {
			continue
		}
		var files []string
		if fi.IsDir() {
			entries, _ := os.ReadDir(root)
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(root, e.Name()))
				}
			}
		} else {
			files = []string{root}
		}
		for _, fpath := range files {
			out = append(out, c.parseCrontab(fpath)...)
		}
	}
	out = append(out, c.systemdTimers()...)
	return out, nil
}

func (c *Cron) parseCrontab(path string) []obs.Observation {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []obs.Observation
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@reboot #") {
			continue
		}
		if !looksLikeAutomation(line) {
			continue
		}
		schedule, command := splitCron(line)
		payload := obs.CronEntry{
			Source:   path,
			Schedule: schedule,
			Command:  sanitize.Scrub(command),
		}
		if o, err := NewObservation(obs.TypeCronEntry, path+"|"+command, payload); err == nil {
			out = append(out, o)
		}
	}
	return out
}

func (c *Cron) systemdTimers() []obs.Observation {
	var out []obs.Observation
	dirs := []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			// Only report services that have a matching .timer and look like automation.
			timer := strings.TrimSuffix(e.Name(), ".service") + ".timer"
			if _, err := os.Stat(filepath.Join(dir, timer)); err != nil {
				continue
			}
			exec := execStart(filepath.Join(dir, e.Name()))
			if exec == "" || !looksLikeAutomation(exec) {
				continue
			}
			payload := obs.CronEntry{
				Source:   "systemd",
				Schedule: timer,
				Command:  sanitize.Scrub(exec),
			}
			if o, err := NewObservation(obs.TypeCronEntry, "systemd|"+e.Name(), payload); err == nil {
				out = append(out, o)
			}
		}
	}
	return out
}

func execStart(unitPath string) string {
	f, err := os.Open(unitPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "ExecStart="); ok {
			return v
		}
	}
	return ""
}

func looksLikeAutomation(line string) bool {
	lc := strings.ToLower(line)
	for _, h := range automationHints {
		if strings.Contains(lc, h) {
			return true
		}
	}
	return false
}

// splitCron separates the 5-field schedule from the command.
func splitCron(line string) (schedule, command string) {
	fields := strings.Fields(line)
	// /etc/crontab and cron.d have a user field; user crontabs do not. We
	// only need a best-effort split, so take the first 5 as schedule.
	if len(fields) < 6 {
		return "", line
	}
	if strings.HasPrefix(fields[0], "@") {
		return fields[0], strings.Join(fields[1:], " ")
	}
	return strings.Join(fields[:5], " "), strings.Join(fields[5:], " ")
}
