// Package collect implements the agent's collectors (ТЗ §4.1, §5.1).
// Collectors only gather and normalize locally; all analysis lives in the
// control plane (ТЗ §4.2). Every collector degrades gracefully: missing
// permissions or absent subsystems produce fewer observations, not errors
// (ТЗ §9: работа без Docker-сокета = деградация функций, а не требование root).
package collect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/oleg-vdv/autogov/internal/obs"
)

// Collector produces raw observations for one detection method.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]obs.Observation, error)
}

// NewObservation wraps a payload into an observation with a unique id
// (generated once → idempotent retries, ТЗ §8.2).
func NewObservation(obsType, identity string, payload any) (obs.Observation, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return obs.Observation{}, err
	}
	return obs.Observation{
		ID:       randomID(),
		Type:     obsType,
		Identity: identity,
		Time:     time.Now().UTC(),
		Data:     raw,
	}, nil
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck // crypto/rand never fails on Linux
	return hex.EncodeToString(b)
}
