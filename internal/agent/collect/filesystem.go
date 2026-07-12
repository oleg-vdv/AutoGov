package collect

import (
	"bufio"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/oleg-vdv/autogov/internal/obs"
)

// Filesystem finds n8n traces on disk (ТЗ §5.1 п.4): ~/.n8n directories,
// docker-compose files with an n8n service, .env files that carry
// N8N_ENCRYPTION_KEY. Only the FACT of the key is recorded — the value is
// never read past the key name (ТЗ §5.1: «не извлекает и не передаёт значение»).
type Filesystem struct {
	// Roots to scan for home dirs and compose projects.
	HomeRoots  []string // default: /home, /root
	ExtraRoots []string // e.g. /opt, /srv from agent config
	MaxDepth   int      // compose/.env search depth below each root
}

func NewFilesystem(extraRoots []string) *Filesystem {
	return &Filesystem{
		HomeRoots:  []string{"/home", "/root"},
		ExtraRoots: extraRoots,
		MaxDepth:   3,
	}
}

func (f *Filesystem) Name() string { return "filesystem" }

func (f *Filesystem) Collect(_ context.Context) ([]obs.Observation, error) {
	var out []obs.Observation

	// 1) ~/.n8n directories — the default install location.
	for _, root := range f.HomeRoots {
		homes := []string{root}
		if root != "/root" {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			homes = homes[:0]
			for _, e := range entries {
				if e.IsDir() {
					homes = append(homes, filepath.Join(root, e.Name()))
				}
			}
		}
		for _, home := range homes {
			n8nDir := filepath.Join(home, ".n8n")
			fi, err := os.Stat(n8nDir)
			if err != nil || !fi.IsDir() {
				continue
			}
			detail := map[string]string{}
			if _, err := os.Stat(filepath.Join(n8nDir, "database.sqlite")); err == nil {
				detail["db"] = "sqlite"
			}
			if _, err := os.Stat(filepath.Join(n8nDir, "config")); err == nil {
				detail["has_config"] = "true"
			}
			payload := obs.FSArtifact{
				Path:   n8nDir,
				Kind:   "n8n_dir",
				Owner:  fileOwner(fi),
				Detail: detail,
			}
			if o, err := NewObservation(obs.TypeFSArtifact, n8nDir, payload); err == nil {
				out = append(out, o)
			}
		}
	}

	// 2) docker-compose / .env traces under configured roots.
	for _, root := range append([]string{"/home", "/root", "/opt", "/srv"}, f.ExtraRoots...) {
		out = append(out, f.scanRoot(root)...)
	}
	return out, nil
}

func (f *Filesystem) scanRoot(root string) []obs.Observation {
	var out []obs.Observation
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error { //nolint:errcheck
		if err != nil {
			return filepath.SkipDir
		}
		depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
		if d.IsDir() {
			if depth > f.MaxDepth || skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasPrefix(name, "docker-compose") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")),
			name == "compose.yml", name == "compose.yaml":
			if grepFile(path, "n8n") {
				fi, _ := d.Info()
				payload := obs.FSArtifact{Path: path, Kind: "compose_file", Owner: fileOwner(fi),
					Detail: map[string]string{"references": "n8n"}}
				if o, err := NewObservation(obs.TypeFSArtifact, path, payload); err == nil {
					out = append(out, o)
				}
			}
		case name == ".env":
			// Look for the KEY NAME only; the value is never captured.
			if grepFile(path, "N8N_ENCRYPTION_KEY") {
				fi, _ := d.Info()
				payload := obs.FSArtifact{Path: path, Kind: "env_file", Owner: fileOwner(fi),
					Detail: map[string]string{"has_encryption_key": "true"}}
				if o, err := NewObservation(obs.TypeFSArtifact, path, payload); err == nil {
					out = append(out, o)
				}
			}
		}
		return nil
	})
	return out
}

// grepFile reports whether needle occurs in the first 256KB of a file.
func grepFile(path, needle string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	read := 0
	for sc.Scan() && read < 256*1024 {
		line := sc.Text()
		read += len(line)
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func skipDir(name string) bool {
	switch name {
	case "node_modules", ".git", ".cache", "vendor", "__pycache__", ".venv", "venv", "proc", "sys", "dev":
		return true
	}
	return false
}

func fileOwner(fi os.FileInfo) string {
	if fi == nil {
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
