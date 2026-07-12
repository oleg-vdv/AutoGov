// Package spool buffers observation batches on disk so the agent survives
// control-plane downtime (ТЗ §8.2: «буферизация наблюдений, дозапись при
// восстановлении связи»). Batches are written as JSON files and replayed in
// order once connectivity returns.
package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/oleg-vdv/autogov/internal/obs"
)

// Spool is an on-disk FIFO of pending batches.
type Spool struct {
	dir  string
	maxN int // cap on retained batches (drop oldest beyond this)
}

// New creates a spool rooted at dir. maxN<=0 defaults to 1000.
func New(dir string, maxN int) (*Spool, error) {
	if maxN <= 0 {
		maxN = 1000
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Spool{dir: dir, maxN: maxN}, nil
}

// Enqueue persists a batch, dropping the oldest if over capacity.
func (s *Spool) Enqueue(b obs.Batch) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%d-%09d.json", time.Now().UnixNano(), len(b.Observations))
	tmp := filepath.Join(s.dir, "."+name)
	final := filepath.Join(s.dir, name)
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	s.trim()
	return nil
}

// Pending returns queued batch file names in FIFO order.
func (s *Spool) Pending() []string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" && e.Name()[0] != '.' {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // timestamp-prefixed → chronological
	return names
}

// Load reads a queued batch by file name.
func (s *Spool) Load(name string) (obs.Batch, error) {
	var b obs.Batch
	raw, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(raw, &b)
	return b, err
}

// Remove deletes a batch once acknowledged by the control plane.
func (s *Spool) Remove(name string) error {
	return os.Remove(filepath.Join(s.dir, name))
}

func (s *Spool) trim() {
	names := s.Pending()
	for len(names) > s.maxN {
		s.Remove(names[0]) //nolint:errcheck // best effort
		names = names[1:]
	}
}
